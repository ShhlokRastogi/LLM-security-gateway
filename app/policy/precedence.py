from __future__ import annotations

from typing import List, Optional
from app.policy.models import PolicyAction, PolicyEvaluationResult


class PolicyPrecedenceResolver:
    """Deterministic conflict resolution following the security hierarchy:
    DENY > REQUIRE_APPROVAL > ALLOW
    Fail-closed stance on ambiguity or error."""

    PRECEDENCE_ORDER = {
        PolicyAction.DENY: 3,
        PolicyAction.REQUIRE_APPROVAL: 2,
        PolicyAction.ALLOW: 1,
    }

    @classmethod
    def resolve(
        cls,
        results: List[PolicyEvaluationResult],
        fail_closed: bool = True,
    ) -> PolicyEvaluationResult:
        if not results:
            # Default fallback
            if fail_closed:
                return PolicyEvaluationResult(
                    action=PolicyAction.DENY,
                    matched=False,
                    reason="No matching policy found; failing closed.",
                )
            return PolicyEvaluationResult(
                action=PolicyAction.ALLOW,
                matched=False,
                reason="No matching policy found; failing open.",
            )

        # Sort results by precedence descending (DENY first, then REQUIRE_APPROVAL, then ALLOW)
        sorted_results = sorted(
            results,
            key=lambda r: cls.PRECEDENCE_ORDER.get(r.action, 0),
            reverse=True,
        )
        return sorted_results[0]


__all__ = ["PolicyPrecedenceResolver"]
