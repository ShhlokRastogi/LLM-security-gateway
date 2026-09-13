from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.risk.models import RiskAssessment, RiskLevel


class CentralDecision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ComprehensiveActionCheckRequest(BaseModel):
    client_id: Optional[str] = "default"
    agent_id: str = Field(..., description="Calling agent ID")
    tool_name: str = Field(..., description="Action/tool name to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Action arguments")
    user: Optional[Dict[str, Any]] = Field(default_factory=lambda: {"role": "user"}, description="User identity and role context")
    context: Optional[Dict[str, Any]] = Field(default_factory=lambda: {"environment": "development"}, description="Execution environment context")
    approval_id: Optional[str] = Field(default=None, description="Optional previously approved human authorization token")
    policy_template: Optional[str] = Field(default=None, description="Optional policy template to apply")
    custom_policies: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional inline custom policy rules")


class ComprehensiveActionCheckResponse(BaseModel):
    decision: CentralDecision = Field(..., description="Final authorization outcome: ALLOW, REQUIRE_APPROVAL, or DENY")
    allowed_to_execute: bool = Field(..., description="True only if action can be directly executed now")
    tool_name: str
    arguments: Dict[str, Any]
    risk: RiskAssessment
    reasons: List[str] = Field(default_factory=list)
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    approval_id: Optional[str] = None
    approval_required: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    request_id: str
    latency_ms: float
