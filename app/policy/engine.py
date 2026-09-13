from __future__ import annotations

from typing import List, Tuple
from app.models.responses import DetectionItem, SecurityAction
from app.policy.config import PolicyConfig


class PolicyEngine:
    """Evaluates detector threats against configurable policy rules and determines actions."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate(
        self,
        detections: List[DetectionItem],
        pipeline_type: str = "input",
    ) -> Tuple[SecurityAction, float]:
        if not detections:
            return SecurityAction.ALLOW, 0.0

        max_risk = max(d.confidence for d in detections)
        guards = self.config.input_guards if pipeline_type == "input" else self.config.output_guards

        actions_triggered = []
        for d in detections:
            guard_cfg = guards.get(d.type, {})
            # If enabled is False, ignore
            if guard_cfg and not guard_cfg.get("enabled", True):
                continue

            action = guard_cfg.get("action", "block" if d.type != "pii" else "redact")
            threshold = guard_cfg.get("threshold", 0.50)

            if d.confidence >= threshold or d.type == "pii":
                actions_triggered.append(action.lower())

        if "block" in actions_triggered:
            return SecurityAction.BLOCK, max_risk
        if "redact" in actions_triggered:
            return SecurityAction.REDACT, max_risk
        if "flag" in actions_triggered:
            return SecurityAction.FLAG, max_risk

        return SecurityAction.ALLOW, max_risk
