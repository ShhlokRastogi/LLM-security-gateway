from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Header

from app.api.dependencies import (
    action_layer,
    audit_logger,
    decision_engine,
    get_client_id,
    logger,
)
from app.audit.models import AuditEvent
from app.decision.models import (
    ComprehensiveActionCheckRequest,
    ComprehensiveActionCheckResponse,
)
from app.models.requests import CheckActionRequest, CheckBatchActionsRequest
from app.models.responses import (
    ActionSecurityDecision,
    BatchActionsSecurityDecision,
)

router = APIRouter(tags=["Action Security"])


@router.post("/actions/check", response_model=ComprehensiveActionCheckResponse)
def check_comprehensive_action_endpoint(
    req: ComprehensiveActionCheckRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Comprehensive Action Security Guard: validates permissions, schemas, multi-factor risk,
    declarative policies, and human approval before any tool can execute."""
    if not req.client_id:
        req.client_id = get_client_id(x_client_id)

    decision = decision_engine.evaluate_action(req)

    # Record structured audit event
    audit_logger.record(
        AuditEvent(
            event_id="",
            event_type="action_security",
            client_id=req.client_id,
            agent_id=req.agent_id,
            user_id=(req.user or {}).get("id"),
            request_id=decision.request_id,
            tool_name=decision.tool_name,
            arguments=decision.arguments,
            risk_level=decision.risk.risk_level.value,
            risk_score=decision.risk.risk_score,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            decision=decision.decision.value,
            reasons="; ".join(decision.reasons),
            approval_id=decision.approval_id,
            latency_ms=decision.latency_ms,
        )
    )

    return decision


@router.post("/check/action", response_model=ActionSecurityDecision)
def check_action_endpoint(req: CheckActionRequest):
    """Backward-compatible action inspection endpoint."""
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
    return action_layer.evaluate_batch(req)
