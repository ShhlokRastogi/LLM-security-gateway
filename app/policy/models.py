from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyOrigin(str, Enum):
    CUSTOM = "CUSTOM"
    TEMPLATE = "TEMPLATE"
    CUSTOMIZED_TEMPLATE = "CUSTOMIZED_TEMPLATE"


class PolicyScope(str, Enum):
    ORGANIZATION = "organization"
    AGENT = "agent"
    ROLE = "role"
    TOOL = "tool"


class PolicyRule(BaseModel):
    rule_id: str = Field(..., description="Unique identifier for the rule")
    description: Optional[str] = Field(default="", description="Rule summary")
    match: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Target selectors: e.g. {'tool': 'refund_payment', 'agent': 'support_bot', 'role': 'user'}",
    )
    conditions: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Declarative condition tree (all, any, not, field comparisons)",
    )
    decision: PolicyAction = Field(..., description="Action to take when conditions match: allow, deny, require_approval")
    reason: Optional[str] = Field(default="", description="Human-readable justification for this decision")


class PolicyDocument(BaseModel):
    policy_id: str = Field(..., description="Unique policy document identifier")
    name: str = Field(..., description="Human-readable policy name")
    version: str = Field(default="1.0", description="Semver string (e.g. 1.0, 1.1, 2.0)")
    client_id: str = Field(default="default", description="Tenant / client ID")
    scope: PolicyScope = Field(default=PolicyScope.AGENT, description="Precedence scope: organization, agent, role, tool")
    rules: List[PolicyRule] = Field(default_factory=list, description="Ordered policy rules")
    origin: PolicyOrigin = Field(default=PolicyOrigin.CUSTOM, description="Origin tracking: CUSTOM, TEMPLATE, CUSTOMIZED_TEMPLATE")
    description: Optional[str] = Field(default="", description="Policy description")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PolicyEvaluationResult(BaseModel):
    action: PolicyAction
    matched: bool
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    policy_version: Optional[str] = None
    rule_id: Optional[str] = None
    reason: Optional[str] = None
