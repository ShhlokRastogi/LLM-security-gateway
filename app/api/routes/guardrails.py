from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
import httpx

from app.api.dependencies import pipeline
from app.models.requests import (
    ChatCompletionProxyRequest,
    CheckInputRequest,
    CheckOutputRequest,
)
from app.models.responses import SecurityAction, SecurityDecision

router = APIRouter(tags=["Input & Output Guardrails"])


@router.post("/check/input", response_model=SecurityDecision)
def check_input_endpoint(req: CheckInputRequest):
    """Inspect user or client inputs for PII, prompt injections, jailbreaks, and policy violations."""
    return pipeline.inspect_input(req)


@router.post("/check/output", response_model=SecurityDecision)
def check_output_endpoint(req: CheckOutputRequest):
    """Inspect LLM output for PII leakage, hallucinations, and safety violations."""
    return pipeline.inspect_output(req)


@router.post("/chat/completions")
async def guarded_chat_completion(req: ChatCompletionProxyRequest):
    """Transparent reverse proxy protecting any upstream LLM (Groq / OpenAI compatible)."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="Messages cannot be empty.")

    latest_user_msg = next((m.content for m in reversed(req.messages) if m.role == "user"), "")

    # 1. Input check
    in_decision = pipeline.inspect_input(CheckInputRequest(text=latest_user_msg, metadata=req.metadata))
    if in_decision.decision == SecurityAction.BLOCK:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by LLM Security Gateway",
                "risk_score": in_decision.risk_score,
                "reasons": [d.details for d in in_decision.detections],
            },
        )

    # 2. Forward to Upstream
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raw_completion = f"Mock completion for safe input: {in_decision.text}"
    else:
        sanitized_messages = []
        for m in req.messages:
            if m.role == "user" and m.content == latest_user_msg:
                sanitized_messages.append({"role": m.role, "content": in_decision.text})
            else:
                sanitized_messages.append({"role": m.role, "content": m.content})

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
                json={
                    "model": req.model,
                    "messages": sanitized_messages,
                    "temperature": req.temperature,
                },
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"Upstream provider error: {resp.text}")
            raw_completion = resp.json()["choices"][0]["message"]["content"]

    # 3. Output check
    out_decision = pipeline.inspect_output(CheckOutputRequest(text=raw_completion, evidence_context=req.evidence_context))
    if out_decision.decision == SecurityAction.BLOCK:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "LLM response blocked by Security Gateway",
                "reasons": [d.details for d in out_decision.detections],
            },
        )

    return {
        "choices": [{"message": {"role": "assistant", "content": out_decision.text}}],
        "security": {
            "input_risk": in_decision.risk_score,
            "output_risk": out_decision.risk_score,
            "input_decision": in_decision.decision.value,
            "output_decision": out_decision.decision.value,
        },
    }
