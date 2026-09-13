from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query
import httpx
from pydantic import BaseModel

# Models
from app.approvals.manager import default_approval_manager
from app.approvals.models import ApprovalRequest, HumanApprovalActionRequest
from app.audit.logger import default_audit_logger
from app.audit.models import AuditEvent, AuditEventsQueryResponse
from app.decision.engine import default_decision_engine
from app.decision.models import (
    CentralDecision,
    ComprehensiveActionCheckRequest,
    ComprehensiveActionCheckResponse,
)
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
from app.permissions.manager import default_permission_manager
from app.permissions.models import AgentPermissions, SetPermissionsRequest
from app.policy.action_permissions import default_action_layer
from app.policy.declarative_engine import default_declarative_engine
from app.policy.models import PolicyDocument, PolicyOrigin, PolicyRule, PolicyScope
from app.policy.templates import default_template_registry
from app.services.logging import get_security_logger
from app.services.pipeline import SecurityPipeline
from app.tools.models import (
    ToolDefinition,
    ToolRegistrationRequest,
    ToolUpdateRequest,
)
from app.tools.registry import default_tool_registry

router = APIRouter(prefix="/v1", tags=["Security Gateway V1"])
pipeline = SecurityPipeline()
logger = get_security_logger("security.api")

# Singletons
tool_registry = default_tool_registry
permission_manager = default_permission_manager
policy_engine = default_declarative_engine
template_registry = default_template_registry
approval_manager = default_approval_manager
decision_engine = default_decision_engine
audit_logger = default_audit_logger
action_layer = default_action_layer


def get_client_id(x_client_id: Optional[str] = Header(None)) -> str:
    return x_client_id or "default"


# ==============================================================================
# 1. TOOL REGISTRY ENDPOINTS (/v1/tools)
# ==============================================================================

@router.post("/tools", response_model=ToolDefinition)
def register_tool_endpoint(
    req: ToolRegistrationRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Register a client/tenant tool with parameter schemas and risk category."""
    cid = req.client_id or x_client_id or "default"
    return tool_registry.register_tool(cid, req)


@router.get("/tools", response_model=List[ToolDefinition])
def list_tools_endpoint(
    include_defaults: bool = Query(True),
    x_client_id: Optional[str] = Header(None),
):
    """List all registered tools available to the client."""
    cid = get_client_id(x_client_id)
    return tool_registry.list_tools(cid, include_defaults=include_defaults)


@router.get("/tools/{tool_id_or_name}", response_model=ToolDefinition)
def get_tool_endpoint(
    tool_id_or_name: str,
    x_client_id: Optional[str] = Header(None),
):
    """Retrieve details of a specific tool by ID or name."""
    cid = get_client_id(x_client_id)
    tool = tool_registry.get_tool(cid, tool_id_or_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id_or_name}' not found.")
    return tool


@router.patch("/tools/{tool_id}", response_model=ToolDefinition)
def update_tool_endpoint(
    tool_id: str,
    req: ToolUpdateRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Update description, parameters, or risk configuration for a registered tool."""
    cid = get_client_id(x_client_id)
    updated = tool_registry.update_tool(cid, tool_id, req)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found for update.")
    return updated


@router.delete("/tools/{tool_id}")
def delete_tool_endpoint(
    tool_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Delete a registered tool from the tenant's registry."""
    cid = get_client_id(x_client_id)
    deleted = tool_registry.delete_tool(cid, tool_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found for deletion.")
    return {"deleted": True, "tool_id": tool_id}


# ==============================================================================
# 2. AGENT PERMISSIONS ENDPOINTS (/v1/agents/{agent_id}/permissions)
# ==============================================================================

@router.post("/agents/{agent_id}/permissions", response_model=AgentPermissions)
def set_agent_permissions_endpoint(
    agent_id: str,
    req: SetPermissionsRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Configure allowed and denied tools for a specific agent under the tenant."""
    cid = get_client_id(x_client_id)
    return permission_manager.set_permissions(cid, agent_id, req)


@router.get("/agents/{agent_id}/permissions", response_model=AgentPermissions)
def get_agent_permissions_endpoint(
    agent_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Fetch tool authorization permissions for an agent."""
    cid = get_client_id(x_client_id)
    perms = permission_manager.get_permissions(cid, agent_id)
    if not perms:
        raise HTTPException(status_code=404, detail=f"Permissions not configured for agent '{agent_id}'.")
    return perms


@router.delete("/agents/{agent_id}/permissions")
def delete_agent_permissions_endpoint(
    agent_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Remove explicit permissions for an agent."""
    cid = get_client_id(x_client_id)
    deleted = permission_manager.delete_permissions(cid, agent_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Permissions not found for agent '{agent_id}'.")
    return {"deleted": True, "agent_id": agent_id}


# ==============================================================================
# 3. DECLARATIVE POLICIES ENDPOINTS (/v1/policies)
# ==============================================================================

@router.post("/policies", response_model=PolicyDocument)
def create_policy_endpoint(
    policy: PolicyDocument,
    x_client_id: Optional[str] = Header(None),
):
    """Create or register a custom declarative security policy document."""
    cid = policy.client_id or get_client_id(x_client_id)
    return policy_engine.create_policy(cid, policy)


# ==============================================================================
# 3. DECLARATIVE POLICIES & TEMPLATES ENDPOINTS (/v1/policies & /v1/policy-templates)
# ==============================================================================

class ApplyTemplateRequest(BaseModel):
    agent_id: str
    customizations: Optional[Dict[str, Any]] = None


@router.get("/policy-templates", response_model=PolicyTemplatesResponse)
@router.get("/policies/templates", response_model=PolicyTemplatesResponse)
def list_policy_templates_endpoint():
    """List all available pre-existing policy templates."""
    templates = template_registry.get_template_info_list()
    return PolicyTemplatesResponse(templates=templates, count=len(templates))


@router.get("/policy-templates/{template_name}", response_model=PolicyTemplateInfo)
@router.get("/policies/templates/{template_name}", response_model=PolicyTemplateInfo)
def get_policy_template_endpoint(template_name: str):
    """Get full details of a specific policy template."""
    cfg = template_registry.get(template_name)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Policy template '{template_name}' not found.")
    version = template_registry.get_version(template_name)
    clean_name = template_name.split("@")[0]
    return PolicyTemplateInfo(
        name=clean_name,
        version=version,
        description=cfg.description or "",
        allowed_tools=cfg.allowed_tools,
        denied_tools=cfg.denied_tools or [],
        approval_required_tools=cfg.approval_required_tools or [],
        has_argument_constraints=bool(cfg.argument_constraints),
    )


@router.post("/policies", response_model=PolicyDocument)
def create_policy_endpoint(
    policy: PolicyDocument,
    x_client_id: Optional[str] = Header(None),
):
    """Create or register a custom declarative security policy document."""
    cid = policy.client_id or get_client_id(x_client_id)
    return policy_engine.create_policy(cid, policy)


@router.get("/policies", response_model=List[PolicyDocument])
def list_policies_endpoint(
    x_client_id: Optional[str] = Header(None),
):
    """List all active policies for the tenant."""
    cid = get_client_id(x_client_id)
    return policy_engine.list_policies(cid)


@router.get("/policies/{policy_id}", response_model=PolicyDocument)
def get_policy_endpoint(
    policy_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Get policy details by ID."""
    cid = get_client_id(x_client_id)
    pol = policy_engine.get_policy(cid, policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    return pol


@router.delete("/policies/{policy_id}")
def delete_policy_endpoint(
    policy_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Delete a custom security policy."""
    cid = get_client_id(x_client_id)
    deleted = policy_engine.delete_policy(cid, policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found for deletion.")
    return {"deleted": True, "policy_id": policy_id}


@router.post("/policy-templates/{template_name}/apply")
def apply_policy_template_endpoint(
    template_name: str,
    req: ApplyTemplateRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Apply a pre-existing policy template to an agent, establishing its permissions and rules."""
    cid = get_client_id(x_client_id)
    cfg = template_registry.get(template_name)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Template '{template_name}' not found.")
    version = template_registry.get_version(template_name)

    # 1. Update Agent Permissions
    perms = permission_manager.set_permissions(
        client_id=cid,
        agent_id=req.agent_id,
        request=SetPermissionsRequest(
            allowed_tools=cfg.allowed_tools or ["*"],
            denied_tools=cfg.denied_tools or [],
            description=f"Applied from template {template_name}@{version}",
        ),
    )

    # 2. Register Applied Policy Document
    rules = []
    for at in (cfg.approval_required_tools or []):
        rules.append(
            PolicyRule(
                rule_id=f"rule-appr-{at}",
                description=f"Mandatory approval for {at}",
                match={"tool": at, "agent": req.agent_id},
                decision=PolicyAction.REQUIRE_APPROVAL,
                reason=f"Action '{at}' requires supervisor approval under {template_name}@{version}",
            )
        )

    pol = policy_engine.create_policy(
        client_id=cid,
        policy=PolicyDocument(
            policy_id=f"pol-applied-{template_name.split('@')[0]}-{req.agent_id}",
            name=f"Policy from {template_name}@{version}",
            version=version,
            client_id=cid,
            scope=PolicyScope.AGENT,
            origin=PolicyOrigin.TEMPLATE if not req.customizations else PolicyOrigin.CUSTOMIZED_TEMPLATE,
            rules=rules,
        ),
    )

    return {
        "status": "applied",
        "agent_id": req.agent_id,
        "template": f"{template_name}@{version}",
        "policy_id": pol.policy_id,
        "permissions": perms,
    }


# ==============================================================================
# 5. ACTION SECURITY GATING ENDPOINTS (/v1/actions/check & /v1/check/action)
# ==============================================================================

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


# ==============================================================================
# 6. HUMAN APPROVAL ENDPOINTS (/v1/approvals)
# ==============================================================================

@router.get("/approvals", response_model=List[ApprovalRequest])
def list_approvals_endpoint(
    status: Optional[str] = Query(None, description="pending | approved | denied | expired"),
    x_client_id: Optional[str] = Header(None),
):
    """List pending or historic human approval requests for the tenant."""
    cid = get_client_id(x_client_id)
    return approval_manager.list_approvals(cid, status=status)


@router.get("/approvals/{approval_id}", response_model=ApprovalRequest)
def get_approval_endpoint(
    approval_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Retrieve details of a specific approval request."""
    cid = get_client_id(x_client_id)
    req = approval_manager.get_approval(cid, approval_id)
    if not req:
        raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")
    return req


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalRequest)
def approve_action_endpoint(
    approval_id: str,
    req: HumanApprovalActionRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Authorize an action execution by a verified human supervisor."""
    cid = get_client_id(x_client_id)
    success, msg, approval = approval_manager.approve(
        client_id=cid,
        approval_id=approval_id,
        approver_id=req.approver_id,
        approver_role=req.approver_role or "supervisor",
        reason=req.reason or "",
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    # Record audit event
    audit_logger.record(
        AuditEvent(
            event_id="",
            event_type="approval_event",
            client_id=cid,
            agent_id=approval.agent_id if approval else None,
            user_id=req.approver_id,
            request_id=approval.request_id if approval else "",
            tool_name=approval.tool_name if approval else None,
            decision="APPROVED",
            reasons=req.reason or msg,
            approval_id=approval_id,
        )
    )

    return approval


@router.post("/approvals/{approval_id}/deny", response_model=ApprovalRequest)
def deny_action_endpoint(
    approval_id: str,
    req: HumanApprovalActionRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Reject and cancel a pending action authorization request."""
    cid = get_client_id(x_client_id)
    success, msg, approval = approval_manager.deny(
        client_id=cid,
        approval_id=approval_id,
        approver_id=req.approver_id,
        reason=req.reason or "",
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    # Record audit event
    audit_logger.record(
        AuditEvent(
            event_id="",
            event_type="approval_event",
            client_id=cid,
            agent_id=approval.agent_id if approval else None,
            user_id=req.approver_id,
            request_id=approval.request_id if approval else "",
            tool_name=approval.tool_name if approval else None,
            decision="DENIED",
            reasons=req.reason or msg,
            approval_id=approval_id,
        )
    )

    return approval


# ==============================================================================
# 7. AUDIT LOGGING ENDPOINTS (/v1/audit/events)
# ==============================================================================

@router.get("/audit/events", response_model=AuditEventsQueryResponse)
def query_audit_events_endpoint(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    x_client_id: Optional[str] = Header(None),
):
    """Query tenant-isolated, PII-scrubbed security audit records."""
    cid = get_client_id(x_client_id)
    events = audit_logger.query(cid, limit=limit, event_type=event_type)
    return AuditEventsQueryResponse(events=events, count=len(events), client_id=cid)


# ==============================================================================
# 8. INPUT, OUTPUT & TRANSPARENT REVERSE PROXY
# ==============================================================================

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
