from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from app.models.requests import CheckInputRequest as InspectInputRequest, CheckOutputRequest as InspectOutputRequest
from app.models.responses import DetectionItem, SecurityAction, SecurityDecision


class ThreatType(str, Enum):
    PII_INPUT = "pii_input"
    PII_LEAKAGE = "pii_leakage"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOXICITY = "toxicity"
    GROUNDING_VIOLATION = "grounding_violation"
    LENGTH_VIOLATION = "length_violation"


class ThreatFinding(BaseModel):
    threat_type: ThreatType | str = Field(..., description="Categorical classification of the detected threat")
    severity: str = Field(default="medium", description="critical | high | medium | low")
    confidence: float = Field(default=1.0, description="Confidence score between 0.0 and 1.0")
    description: str = Field(default="", description="Human-readable description of the threat finding")
    matched_pattern: Optional[str] = Field(default=None, description="Triggering pattern or snippet")
    span: Optional[Tuple[int, int]] = Field(default=None, description="Start and end indices within original string")


class RedactionRecord(BaseModel):
    entity_type: str = Field(..., description="Redacted entity category (e.g. CREDIT_CARD, EMAIL, SSN)")
    masked_value: str = Field(..., description="Replacement placeholder (e.g. [REDACTED_CARD])")
    original_snippet: Optional[str] = Field(default=None, description="Original unmasked snippet for audit tracking")
    start: Optional[int] = Field(default=None, description="Start index in original string")
    end: Optional[int] = Field(default=None, description="End index in original string")


__all__ = [
    "SecurityAction",
    "SecurityDecision",
    "DetectionItem",
    "InspectInputRequest",
    "InspectOutputRequest",
    "ThreatType",
    "ThreatFinding",
    "RedactionRecord",
]
