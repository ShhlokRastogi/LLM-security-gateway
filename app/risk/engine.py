from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from app.risk.models import RiskAssessment, RiskLevel
from app.tools.models import ToolDefinition, ToolRiskCategory


class RiskEngine:
    """Modular, multi-factor risk assessment engine for agent tool-call execution."""

    DESTRUCTIVE_KEYWORDS = [
        "DROP", "TRUNCATE", "DELETE", "PURGE", "DESTROY", "FORMAT", "RM -RF", "SHUTDOWN", "KILL", "DROP_DATABASE"
    ]

    CATEGORY_BASELINES = {
        ToolRiskCategory.READ_ONLY: 0.05,
        ToolRiskCategory.GENERAL: 0.20,
        ToolRiskCategory.EXTERNAL_COMMUNICATION: 0.35,
        ToolRiskCategory.DATA_MUTATION: 0.45,
        ToolRiskCategory.FINANCIAL: 0.50,
        ToolRiskCategory.SYSTEM_COMMAND: 0.70,
        ToolRiskCategory.PRIVILEGED: 0.80,
    }

    def assess_risk(
        self,
        tool: Optional[ToolDefinition],
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        user: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        factors: List[str] = []
        score = 0.0
        details: Dict[str, Any] = {}
        ctx = context or {}
        usr = user or {}
        args = arguments or {}

        # 1. Base category risk
        if tool:
            cat_risk = self.CATEGORY_BASELINES.get(tool.risk_category, 0.25)
            score += cat_risk
            factors.append(f"category_{tool.risk_category.value}")
            details["category_baseline"] = cat_risk
        else:
            # Unknown tool baseline penalty
            score += 0.50
            factors.append("unknown_tool_penalty")
            details["category_baseline"] = 0.50

        # 2. Environment factor
        env = str(ctx.get("environment", "development")).lower()
        if env == "production":
            score += 0.20
            factors.append("production_environment")
            details["environment_modifier"] = 0.20
        elif env == "staging":
            score += 0.05
            factors.append("staging_environment")
            details["environment_modifier"] = 0.05

        # 3. Financial magnitude factor
        amount = None
        for key in ["amount", "value", "price", "cost"]:
            if key in args and isinstance(args[key], (int, float)):
                amount = float(args[key])
                break

        if amount is not None:
            if amount > 5000:
                score += 0.35
                factors.append("high_financial_impact")
                details["financial_modifier"] = 0.35
            elif amount > 500:
                score += 0.15
                factors.append("moderate_financial_impact")
                details["financial_modifier"] = 0.15

        # 4. Destructive operation heuristic
        str_repr = str(args).upper()
        if any(re.search(rf"\b{re.escape(kw)}\b", str_repr) for kw in self.DESTRUCTIVE_KEYWORDS):
            score += 0.35
            factors.append("destructive_operation")
            details["destructive_modifier"] = 0.35

        # 5. User privilege factor
        role = str(usr.get("role", "user")).lower()
        if role in ["admin", "superuser", "root"]:
            details["user_role"] = "privileged"
        elif role in ["anonymous", "guest"]:
            score += 0.15
            factors.append("unauthenticated_or_guest_user")
            details["guest_penalty"] = 0.15

        # Clamp normalized score to [0.0, 1.0]
        final_score = round(min(max(score, 0.0), 1.0), 2)

        # Map to Risk Level
        if final_score >= 0.85:
            level = RiskLevel.CRITICAL
        elif final_score >= 0.60:
            level = RiskLevel.HIGH
        elif final_score >= 0.25:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return RiskAssessment(
            risk_level=level,
            risk_score=final_score,
            factors=factors,
            details=details,
        )


default_risk_engine = RiskEngine()

__all__ = ["RiskEngine", "default_risk_engine"]
