from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskAssessment(BaseModel):
    risk_level: RiskLevel = Field(..., description="Categorical risk tier (LOW, MEDIUM, HIGH, CRITICAL)")
    risk_score: float = Field(..., description="Normalized quantitative risk score between 0.0 and 1.0")
    factors: List[str] = Field(default_factory=list, description="Specific risk drivers identified during evaluation")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic breakdown of risk calculation")
