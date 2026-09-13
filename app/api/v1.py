from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException
import httpx
from app.models.requests import (
    ChatCompletionProxyRequest,
    CheckActionRequest,
    CheckBatchActionsRequest,
    CheckInputRequest,
    CheckOutputRequest,
)
from app.models.responses import (
    ActionSecurityDecision,
    BatchActionsSecurityDecision,
    PolicyTemplateInfo,
    PolicyTemplatesResponse,
    SecurityAction,
    SecurityDecision,
)
from app.policy.action_permissions import default_action_layer
from app.policy.templates import default_template_registry
from app.services.logging import get_security_logger
from app.services.pipeline import SecurityPipeline

router = APIRouter(prefix="/v1", tags=["Security Gateway V1"])
pipeline = SecurityPipeline()
action_layer = default_action_layer
template_registry = default_template_registry
logger = get_security_logger("security.api")


# --- Input & Output Inspection ---

@router.post("/check/input", response_model=SecurityDecision)
def check_input_endpoint(req: CheckInputRequest):
    """Inspect user or client inputs for PII, prompt injections, jailbreaks, and policy violations."""
    return pipeline.inspect_input(req)


@router.post("/check/output", response_model=SecurityDecision)
def check_output_endpoint(req: CheckOutputRequest):
    """Inspect LLM output for PII leakage, hallucinations, and safety violations."""
    return pipeline.inspect_output(req)


# --- Action Permissions Layer ---

@router.post("/check/action", response_model=ActionSecurityDecision)
def check_action_endpoint(req: CheckActionRequest):
    """Inspect an agent's proposed tool action against pre-existing templates or custom policies."""
    decision = action_layer.evaluate_action(req)
    logger.info(
        f"Action inspected: tool='{decision.tool_name}' decision='{decision.decision.value}' risk={decision.risk_score}",
        extra={
            "request_id": decision.request_id,
            "event_type": "action_inspection",
            "tool_name": decision.tool_name,
            "decision": decision.decision.value,
            "latency_ms": decision.latency_ms,
        },
    )
    return decision


@router.post("/check/actions", response_model=BatchActionsSecurityDecision)
def check_batch_actions_endpoint(req: CheckBatchActionsRequest):
    """Inspect multiple proposed parallel tool actions."""
    batch_decision = action_layer.evaluate_batch(req)
    logger.info(
        f"Batch actions inspected: count={len(batch_decision.decisions)} overall='{batch_decision.overall_decision.value}'",
        extra={
            "request_id": batch_decision.request_id,
            "event_type": "batch_action_inspection",
            "decision": batch_decision.overall_decision.value,
            "latency_ms": batch_decision.latency_ms,
        },
    )
    return batch_decision


# --- Policy Templates Discovery ---

@router.get("/policies/templates", response_model=PolicyTemplatesResponse)
def list_policy_templates():
    """List all available pre-existing policy templates."""
    templates = template_registry.get_template_info_list()
    return PolicyTemplatesResponse(templates=templates, count=len(templates))


@router.get("/policies/templates/{template_name}", response_model=PolicyTemplateInfo)
def get_policy_template(template_name: str):
    """Get full details of a specific policy template."""
    cfg = template_registry.get(template_name)
    if not cfg:
        raise HTTPException(
            status_code=404,
            detail=f"Policy template '{template_name}' not found. Use GET /v1/policies/templates to view available templates.",
        )
    return PolicyTemplateInfo(
        name=template_name,
        description=cfg.description or "",
        allowed_tools=cfg.allowed_tools,
        denied_tools=cfg.denied_tools or [],
        approval_required_tools=cfg.approval_required_tools or [],
        has_argument_constraints=bool(cfg.argument_constraints),
    )


# --- Transparent Proxy ---

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
