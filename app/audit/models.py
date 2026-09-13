from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    event_id: str = Field(..., description="Unique audit event ID")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = Field(default="action_security", description="Category: action_security, input_security, output_security, approval")
    client_id: str = Field(default="default", description="Tenant / client ID")
    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: str = Field(..., description="Correlated request ID")
    tool_name: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    decision: str = Field(..., description="ALLOW, REQUIRE_APPROVAL, DENY, BLOCK, REDACT")
    reasons: Optional[str] = None
    approval_id: Optional[str] = None
    latency_ms: float = Field(default=0.0)


class AuditEventsQueryResponse(BaseModel):
    events: list[AuditEvent]
    count: int
    client_id: str
