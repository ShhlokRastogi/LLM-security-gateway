from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    approval_id: str = Field(..., description="Unique approval identifier")
    request_id: str = Field(..., description="Original action inspection request ID")
    client_id: str = Field(default="default", description="Tenant / client ID")
    agent_id: str = Field(..., description="Agent that requested the action")
    tool_name: str = Field(..., description="Tool name requiring authorization")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Exact parameters requested")
    action_hash: str = Field(..., description="Cryptographic SHA256 binding of the action and arguments")
    risk_score: float = Field(default=0.5, description="Evaluated risk score")
    risk_level: str = Field(default="HIGH", description="Risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = Field(..., description="Expiration timestamp (TTL)")
    decided_at: Optional[str] = None
    approver_id: Optional[str] = None
    approver_role: Optional[str] = None
    decision_reason: Optional[str] = None
    is_used: bool = Field(default=False, description="Whether this approval has already been consumed (replay prevention)")


class HumanApprovalActionRequest(BaseModel):
    approver_id: str = Field(..., description="Human supervisor or admin user ID (cannot be the agent)")
    approver_role: Optional[str] = Field(default="supervisor", description="Role of the human approver")
    reason: Optional[str] = Field(default="", description="Reason for the decision")
