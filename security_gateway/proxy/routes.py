from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
import httpx
from pydantic import BaseModel, Field

from security_gateway.gateway import SecurityGateway
from security_gateway.models import InspectInputRequest, InspectOutputRequest, SecurityAction

app = FastAPI(
    title="LLM Security Gateway API",
    description="Application-Agnostic LLM Security Gateway, Policy Engine & Reverse Proxy",
    version="0.1.0",
)

gateway = SecurityGateway()


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "llm-security-gateway",
        "policy_mode": gateway.config.policy_mode,
    }


@app.post("/v1/inspect/input")
def inspect_input_endpoint(req: InspectInputRequest):
    decision = gateway.inspect_input(req.text, context=req.context)
    return decision.model_dump()


@app.post("/v1/inspect/output")
def inspect_output_endpoint(req: InspectOutputRequest):
    decision = gateway.inspect_output(req.text, evidence_context=req.evidence_context)
    return decision.model_dump()


class ChatMessagePayload(BaseModel):
    role: str
    content: str


class ChatCompletionProxyRequest(BaseModel):
    messages: List[ChatMessagePayload]
    model: Optional[str] = "llama-3.3-70b-versatile"
    temperature: Optional[float] = 0.0
    evidence_context: Optional[List[str]] = None


@app.post("/v1/chat/completions")
async def guarded_chat_completion(req: ChatCompletionProxyRequest):
    """Transparent proxy that checks input, forwards to upstream LLM, and guards output."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="Messages cannot be empty.")

    latest_user_msg = next((m.content for m in reversed(req.messages) if m.role == "user"), "")

    # 1. Input Guardrail
    input_decision = gateway.inspect_input(latest_user_msg)
    if input_decision.action == SecurityAction.BLOCK:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by Security Gateway",
                "reasons": [t.description for t in input_decision.threats],
            },
        )

    # 2. Forward to Upstream LLM (Groq / OpenAI compatible)
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        # Mock mode if no upstream key configured
        raw_completion = f"Mock completion for: {input_decision.sanitized_text}"
    else:
        # Forward sanitized messages
        sanitized_messages = []
        for m in req.messages:
            if m.role == "user" and m.content == latest_user_msg:
                sanitized_messages.append({"role": m.role, "content": input_decision.sanitized_text})
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
            data = resp.json()
            raw_completion = data["choices"][0]["message"]["content"]

    # 3. Output Guardrail
    output_decision = gateway.inspect_output(raw_completion, evidence_context=req.evidence_context)
    if output_decision.action == SecurityAction.BLOCK:
        return {
            "id": "sec-blocked",
            "choices": [{"message": {"role": "assistant", "content": output_decision.sanitized_text}}],
            "security": output_decision.model_dump(),
        }

    return {
        "id": "sec-ok",
        "choices": [{"message": {"role": "assistant", "content": output_decision.sanitized_text}}],
        "security": {
            "input": input_decision.model_dump(),
            "output": output_decision.model_dump(),
        },
    }
