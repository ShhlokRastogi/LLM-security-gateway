from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.api.dependencies import approval_manager, audit_logger, get_client_id
from app.approvals.models import ApprovalRequest, HumanApprovalActionRequest
from app.audit.models import AuditEvent

router = APIRouter(tags=["Human Approvals"])


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
