from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List, Optional
from app.policy.ast import ConditionEvaluator
from app.policy.models import PolicyAction, PolicyDocument, PolicyEvaluationResult, PolicyOrigin, PolicyRule, PolicyScope
from app.policy.precedence import PolicyPrecedenceResolver


class DeclarativePolicyEngine:
    """Declarative, multi-tenant policy evaluation engine with deterministic precedence."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Storage: client_id -> policy_id -> PolicyDocument
        self._policies: Dict[str, Dict[str, PolicyDocument]] = {}
        self._seed_default_policies()

    def _seed_default_policies(self) -> None:
        """Seed baseline enterprise safety policies under default tenant."""
        default_pols = [
            PolicyDocument(
                policy_id="pol-refund-safety",
                name="Financial Refund Governance Policy",
                version="1.0",
                client_id="default",
                scope=PolicyScope.TOOL,
                origin=PolicyOrigin.TEMPLATE,
                description="Governs automated vs human-approved refunds based on amount and user role.",
                rules=[
                    # Rule 1: High value refunds (> $500) require human approval
                    PolicyRule(
                        rule_id="rule-high-refund-approval",
                        description="Refunds exceeding $500 require human authorization",
                        match={"tool": "refund_payment"},
                        conditions={
                            "all": [
                                {"field": "arguments.amount", "operator": "greater_than", "value": 500}
                            ]
                        },
                        decision=PolicyAction.REQUIRE_APPROVAL,
                        reason="Financial refund exceeds automatic threshold ($500); human approval required.",
                    ),
                    # Rule 2: Low value refunds (<= $500) permitted automatically
                    PolicyRule(
                        rule_id="rule-low-refund-allow",
                        description="Low value refunds up to $500 are authorized",
                        match={"tool": "refund_payment"},
                        conditions={
                            "all": [
                                {"field": "arguments.amount", "operator": "less_than_or_equal", "value": 500}
                            ]
                        },
                        decision=PolicyAction.ALLOW,
                        reason="Refund amount is within automatic approval limits.",
                    ),
                ],
            ),
            PolicyDocument(
                policy_id="pol-production-destructive-guard",
                name="Production Destructive Action Defense",
                version="1.0",
                client_id="default",
                scope=PolicyScope.ORGANIZATION,
                origin=PolicyOrigin.TEMPLATE,
                description="Strictly blocks destructive SQL or filesystem deletions in production.",
                rules=[
                    PolicyRule(
                        rule_id="rule-block-prod-destructive-sql",
                        description="Block destructive SQL statements in production",
                        match={"tool": "query_database"},
                        conditions={
                            "all": [
                                {"field": "context.environment", "operator": "equals", "value": "production"},
                                {"field": "risk.factors", "operator": "contains", "value": "destructive_operation"},
                            ]
                        },
                        decision=PolicyAction.DENY,
                        reason="Destructive database mutations are strictly prohibited in production.",
                    ),
                    PolicyRule(
                        rule_id="rule-block-delete-file",
                        description="File deletion in production requires approval",
                        match={"tool": "delete_file"},
                        conditions={
                            "all": [
                                {"field": "context.environment", "operator": "equals", "value": "production"}
                            ]
                        },
                        decision=PolicyAction.REQUIRE_APPROVAL,
                        reason="Production file deletion requires supervisor approval.",
                    ),
                ],
            ),
        ]
        for p in default_pols:
            self._insert_policy(p)

    def _insert_policy(self, policy: PolicyDocument) -> None:
        cid = policy.client_id
        if cid not in self._policies:
            self._policies[cid] = {}
        self._policies[cid][policy.policy_id] = policy

    def create_policy(self, client_id: str, policy: PolicyDocument) -> PolicyDocument:
        with self._lock:
            cid = client_id or policy.client_id or "default"
            policy.client_id = cid
            if not policy.policy_id:
                policy.policy_id = f"pol-{uuid.uuid4().hex[:8]}"
            self._insert_policy(policy)
            return policy

    def get_policy(self, client_id: str, policy_id: str) -> Optional[PolicyDocument]:
        with self._lock:
            cid = client_id or "default"
            if cid in self._policies and policy_id in self._policies[cid]:
                return self._policies[cid][policy_id]
            if cid != "default" and "default" in self._policies and policy_id in self._policies["default"]:
                return self._policies["default"][policy_id]
            return None

    def list_policies(self, client_id: str) -> List[PolicyDocument]:
        with self._lock:
            cid = client_id or "default"
            pols = []
            if cid in self._policies:
                pols.extend(self._policies[cid].values())
            if cid != "default" and "default" in self._policies:
                tenant_pids = {p.policy_id for p in pols}
                for dp in self._policies["default"].values():
                    if dp.policy_id not in tenant_pids:
                        pols.append(dp)
            return pols

    def delete_policy(self, client_id: str, policy_id: str) -> bool:
        with self._lock:
            cid = client_id or "default"
            if cid in self._policies and policy_id in self._policies[cid]:
                del self._policies[cid][policy_id]
                return True
            return False

    def evaluate(
        self,
        client_id: str,
        evaluation_context: Dict[str, Any],
        custom_policies: Optional[List[PolicyDocument]] = None,
    ) -> PolicyEvaluationResult:
        """Evaluates all matching policies for the client and returns the resolved decision."""
        with self._lock:
            try:
                candidate_policies = self.list_policies(client_id)
                if custom_policies:
                    candidate_policies = list(custom_policies) + candidate_policies

                matching_results: List[PolicyEvaluationResult] = []

                for pol in candidate_policies:
                    for rule in pol.rules:
                        if self._match_selector(rule.match, evaluation_context):
                            if ConditionEvaluator.evaluate(rule.conditions, evaluation_context):
                                matching_results.append(
                                    PolicyEvaluationResult(
                                        action=rule.decision,
                                        matched=True,
                                        policy_id=pol.policy_id,
                                        policy_name=pol.name,
                                        policy_version=pol.version,
                                        rule_id=rule.rule_id,
                                        reason=rule.reason or f"Matched rule '{rule.rule_id}' in policy '{pol.name}'",
                                    )
                                )

                # If no specific rule matched:
                if not matching_results:
                    return PolicyEvaluationResult(
                        action=PolicyAction.ALLOW,
                        matched=False,
                        reason="No prohibitive policy matched; standard operation allowed.",
                    )

                # Precedence resolution (DENY > REQUIRE_APPROVAL > ALLOW)
                return PolicyPrecedenceResolver.resolve(matching_results, fail_closed=True)

            except Exception as ex:
                # Security critical: fail closed on any internal evaluation error
                return PolicyEvaluationResult(
                    action=PolicyAction.DENY,
                    matched=False,
                    reason=f"Policy evaluation failure: {str(ex)}; failing closed for security.",
                )

    def _match_selector(self, match_spec: Optional[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        if not match_spec:
            return True
        for k, expected in match_spec.items():
            if k == "tool":
                actual = ConditionEvaluator.extract_field(context, "tool.name")
            elif k == "agent":
                actual = ConditionEvaluator.extract_field(context, "agent.id")
            elif k == "role":
                actual = ConditionEvaluator.extract_field(context, "user.role")
            else:
                actual = ConditionEvaluator.extract_field(context, k)

            if actual != expected and expected != "*":
                return False
        return True


default_declarative_engine = DeclarativePolicyEngine()

__all__ = ["DeclarativePolicyEngine", "default_declarative_engine"]
