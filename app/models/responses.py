from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"


class ActionDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    FLAG = "flag"


class DetectionItem(BaseModel):
    type: str = Field(..., description="Type of detector that triggered (e.g. prompt_injection, pii, grounding)")
    category: str = Field(..., description="Sub-category (e.g. instruction_override, credit_card, hallucination)")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0")
    details: Optional[str] = Field(default=None, description="Human-readable description or pattern snippet")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SecurityDecision(BaseModel):
    decision: SecurityAction = Field(..., description="Enforced policy decision: allow, block, redact, or flag")
    risk_score: float = Field(default=0.0, description="Overall evaluated risk score between 0.0 and 1.0")
    text: str = Field(..., description="Sanitized/redacted text or original input")
    detections: List[DetectionItem] = Field(default_factory=list, description="List of detected threats or policy findings")
    request_id: str = Field(..., description="Unique request tracing ID")
    latency_ms: float = Field(default=0.0, description="Total inspection latency in milliseconds")


# --- Action Permissions Response Models ---

class ActionViolationItem(BaseModel):
    """Details of an action permission or parameter constraint violation."""
    tool_name: str
    parameter: Optional[str] = None
    rule: str = Field(..., description="Violated rule type (e.g. 'forbidden_tool', 'path_traversal', 'destructive_sql', 'keyword_prohibited')")
    message: str = Field(..., description="Human-readable reason for the violation")
    severity: str = Field(default="high", description="high | medium | low")


class ActionSecurityDecision(BaseModel):
    """Evaluation result for an agent's proposed action."""
    decision: ActionDecision = Field(..., description="Final authorization decision: allow, block, require_approval, flag")
    tool_name: str = Field(..., description="Evaluated tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool arguments (sanitized or original)")
    risk_score: float = Field(default=0.0, description="Risk score from 0.0 (safe) to 1.0 (dangerous)")
    reasons: List[str] = Field(default_factory=list, description="Summary explanation of the decision")
    violations: List[ActionViolationItem] = Field(default_factory=list, description="List of specific rule violations if any")
    policy_source: str = Field(default="default", description="Source of policy evaluated ('template:<name>', 'custom', 'default')")
    requires_approval: bool = Field(default=False, description="Quick boolean indicating if human approval is required")
    request_id: str = Field(..., description="Unique request tracing ID")
    latency_ms: float = Field(default=0.0, description="Evaluation latency in ms")


class BatchActionsSecurityDecision(BaseModel):
    """Evaluation result for multiple proposed actions."""
    overall_decision: ActionDecision
    decisions: List[ActionSecurityDecision]
    all_allowed: bool
    requires_approval_count: int = 0
    blocked_count: int = 0
    request_id: str
    latency_ms: float


class PolicyTemplateInfo(BaseModel):
    """Summary of a pre-existing policy template."""
    name: str
    version: Optional[str] = "1.0"
    description: str
    allowed_tools: Optional[List[str]] = None
    denied_tools: List[str] = Field(default_factory=list)
    approval_required_tools: List[str] = Field(default_factory=list)
    has_argument_constraints: bool = False


class PolicyTemplatesResponse(BaseModel):
    """List of available pre-existing policy templates."""
    templates: List[PolicyTemplateInfo]
    count: int


class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str = "llm-security-gateway"
    version: str = "1.0.0"
    policy_mode: str = "balanced"


class ReadyResponse(BaseModel):
    ready: bool = True
    detectors_initialized: List[str] = Field(default_factory=list)
