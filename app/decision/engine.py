from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from app.approvals.manager import ApprovalManager, default_approval_manager
from app.decision.models import CentralDecision, ComprehensiveActionCheckRequest, ComprehensiveActionCheckResponse
from app.permissions.manager import PermissionManager, default_permission_manager
from app.policy.declarative_engine import DeclarativePolicyEngine, default_declarative_engine
from app.policy.models import PolicyAction, PolicyDocument, PolicyOrigin, PolicyRule, PolicyScope
from app.policy.templates import PolicyTemplateRegistry, default_template_registry
from app.risk.engine import RiskEngine, default_risk_engine
from app.risk.models import RiskAssessment, RiskLevel
from app.tools.models import ToolDefinition, ToolRiskCategory
from app.tools.registry import ToolRegistry, default_tool_registry
from app.tools.validator import ArgumentValidator, default_argument_validator


class CentralDecisionEngine:
    """Central Decision Engine synthesizing Permissions, Schema Validation, Multi-factor Risk,
    Declarative Policies, and Human Approvals into explainable authorization decisions."""

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        permission_manager: Optional[PermissionManager] = None,
        argument_validator: Optional[ArgumentValidator] = None,
        risk_engine: Optional[RiskEngine] = None,
        policy_engine: Optional[DeclarativePolicyEngine] = None,
        approval_manager: Optional[ApprovalManager] = None,
        template_registry: Optional[PolicyTemplateRegistry] = None,
    ) -> None:
        self.tools = tool_registry or default_tool_registry
        self.permissions = permission_manager or default_permission_manager
        self.validator = argument_validator or default_argument_validator
        self.risk = risk_engine or default_risk_engine
        self.policy = policy_engine or default_declarative_engine
        self.approvals = approval_manager or default_approval_manager
        self.templates = template_registry or default_template_registry

    def evaluate_action(self, req: ComprehensiveActionCheckRequest) -> ComprehensiveActionCheckResponse:
        t0 = time.perf_counter()
        req_id = f"act-{uuid.uuid4().hex[:8]}"
        cid = req.client_id or "default"
        aid = req.agent_id
        tool_name = req.tool_name.strip()
        args = req.arguments or {}
        reasons: List[str] = []

        # 1. Resolve Tool Definition
        tool_def = self.tools.get_tool(cid, tool_name)
        if not tool_def:
            # Check if dynamically allowed or known; create lightweight fallback representation
            tool_def = ToolDefinition(
                tool_id=f"dynamic-{tool_name}",
                tool_name=tool_name,
                description="Client proposed tool",
                client_id=cid,
                risk_category=ToolRiskCategory.GENERAL,
                parameters={},
            )

        # 2. Layer 1: Action Permissions Check (Agent -> Tool)
        perm_res = self.permissions.check_permission(cid, aid, tool_name)
        if not perm_res.is_permitted:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            risk_res = self.risk.assess_risk(tool_def, tool_name, args, req.context, req.user)
            return ComprehensiveActionCheckResponse(
                decision=CentralDecision.DENY,
                allowed_to_execute=False,
                tool_name=tool_name,
                arguments=args,
                risk=risk_res,
                reasons=[perm_res.reason],
                request_id=req_id,
                latency_ms=latency,
            )

        # 3. Layer 2: Schema & Argument Validation
        val_errors = self.validator.validate(tool_def, args)
        if val_errors:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            risk_res = self.risk.assess_risk(tool_def, tool_name, args, req.context, req.user)
            err_msgs = [f"[{e.rule}] {e.message}" for e in val_errors]
            return ComprehensiveActionCheckResponse(
                decision=CentralDecision.DENY,
                allowed_to_execute=False,
                tool_name=tool_name,
                arguments=args,
                risk=risk_res,
                reasons=[f"Argument validation failed: {err_msgs[0]}"],
                validation_errors=err_msgs,
                request_id=req_id,
                latency_ms=latency,
            )

        # 4. Layer 3: Risk Assessment
        risk_res = self.risk.assess_risk(tool_def, tool_name, args, req.context, req.user)

        # 5. Layer 4: Check if client presented a valid pre-approved human token
        if req.approval_id:
            consumed, msg = self.approvals.consume_approval(
                client_id=cid,
                approval_id=req.approval_id,
                agent_id=aid,
                tool_name=tool_name,
                arguments=args,
            )
            latency = round((time.perf_counter() - t0) * 1000, 2)
            if consumed:
                return ComprehensiveActionCheckResponse(
                    decision=CentralDecision.ALLOW,
                    allowed_to_execute=True,
                    tool_name=tool_name,
                    arguments=args,
                    risk=risk_res,
                    reasons=[f"Action approved and verified by human supervisor ({req.approval_id})"],
                    approval_id=req.approval_id,
                    request_id=req_id,
                    latency_ms=latency,
                )
            else:
                # Invalid or replayed approval token -> Strict DENY
                return ComprehensiveActionCheckResponse(
                    decision=CentralDecision.DENY,
                    allowed_to_execute=False,
                    tool_name=tool_name,
                    arguments=args,
                    risk=risk_res,
                    reasons=[f"Approval authorization failed: {msg}"],
                    approval_id=req.approval_id,
                    request_id=req_id,
                    latency_ms=latency,
                )

        # 6. Layer 5: Declarative Policy Evaluation
        eval_context: Dict[str, Any] = {
            "tool": {"name": tool_name, "risk_category": tool_def.risk_category.value},
            "arguments": args,
            "agent": {"id": aid},
            "user": req.user or {"role": "user"},
            "context": req.context or {"environment": "development"},
            "risk": {"level": risk_res.risk_level.value, "score": risk_res.risk_score, "factors": risk_res.factors},
        }

        # Check template-applied or custom policies
        custom_pols = self._build_custom_policies(cid, req.policy_template, req.custom_policies)
        policy_res = self.policy.evaluate(cid, eval_context, custom_policies=custom_pols)

        latency = round((time.perf_counter() - t0) * 1000, 2)

        # 7. Synthesize Final Decision
        if policy_res.action == PolicyAction.DENY:
            return ComprehensiveActionCheckResponse(
                decision=CentralDecision.DENY,
                allowed_to_execute=False,
                tool_name=tool_name,
                arguments=args,
                risk=risk_res,
                reasons=[policy_res.reason or "Denied by policy rule."],
                policy_id=policy_res.policy_id,
                policy_version=policy_res.policy_version,
                request_id=req_id,
                latency_ms=latency,
            )

        if policy_res.action == PolicyAction.REQUIRE_APPROVAL:
            # Create a tracked approval request
            app_req = self.approvals.create_approval_request(
                request_id=req_id,
                client_id=cid,
                agent_id=aid,
                tool_name=tool_name,
                arguments=args,
                risk_score=risk_res.risk_score,
                risk_level=risk_res.risk_level.value,
            )
            return ComprehensiveActionCheckResponse(
                decision=CentralDecision.REQUIRE_APPROVAL,
                allowed_to_execute=False,
                tool_name=tool_name,
                arguments=args,
                risk=risk_res,
                reasons=[policy_res.reason or "Action requires human approval."],
                policy_id=policy_res.policy_id,
                policy_version=policy_res.policy_version,
                approval_id=app_req.approval_id,
                approval_required=True,
                request_id=req_id,
                latency_ms=latency,
            )

        # ALLOW
        return ComprehensiveActionCheckResponse(
            decision=CentralDecision.ALLOW,
            allowed_to_execute=True,
            tool_name=tool_name,
            arguments=args,
            risk=risk_res,
            reasons=[policy_res.reason or "Action permitted."],
            policy_id=policy_res.policy_id,
            policy_version=policy_res.policy_version,
            request_id=req_id,
            latency_ms=latency,
        )

    def _build_custom_policies(
        self,
        client_id: str,
        template_name: Optional[str],
        custom_specs: Optional[List[Dict[str, Any]]],
    ) -> List[PolicyDocument]:
        docs: List[PolicyDocument] = []

        # If template is selected
        if template_name:
            cfg = self.templates.get(template_name)
            ver = self.templates.get_version(template_name)
            if cfg:
                rules = []
                # Block denied tools
                for dt in (cfg.denied_tools or []):
                    rules.append(
                        PolicyRule(
                            rule_id=f"rule-deny-{dt}",
                            description=f"Template {template_name} denies tool {dt}",
                            match={"tool": dt},
                            decision=PolicyAction.DENY,
                            reason=f"Tool '{dt}' is prohibited under template {template_name}@{ver}.",
                        )
                    )
                # Approval required tools
                for at in (cfg.approval_required_tools or []):
                    rules.append(
                        PolicyRule(
                            rule_id=f"rule-approval-{at}",
                            description=f"Template {template_name} requires approval for {at}",
                            match={"tool": at},
                            decision=PolicyAction.REQUIRE_APPROVAL,
                            reason=f"Action '{at}' is sensitive under template {template_name}@{ver}; human approval required.",
                        )
                    )

                docs.append(
                    PolicyDocument(
                        policy_id=f"pol-template-{template_name}",
                        name=f"Template: {template_name}",
                        version=ver,
                        client_id=client_id,
                        scope=PolicyScope.AGENT,
                        origin=PolicyOrigin.TEMPLATE,
                        rules=rules,
                    )
                )

        if custom_specs:
            for i, spec in enumerate(custom_specs):
                rules = []
                for j, r in enumerate(spec.get("rules", [])):
                    rules.append(
                        PolicyRule(
                            rule_id=r.get("rule_id", f"custom-rule-{i}-{j}"),
                            description=r.get("description", ""),
                            match=r.get("match", {}),
                            conditions=r.get("conditions"),
                            decision=PolicyAction(r.get("decision", "deny").lower()),
                            reason=r.get("reason", ""),
                        )
                    )
                docs.append(
                    PolicyDocument(
                        policy_id=spec.get("policy_id", f"pol-custom-{i}"),
                        name=spec.get("name", f"Custom Policy {i+1}"),
                        version=spec.get("version", "1.0"),
                        client_id=client_id,
                        scope=PolicyScope(spec.get("scope", "agent")),
                        origin=PolicyOrigin.CUSTOM,
                        rules=rules,
                    )
                )

        return docs


default_decision_engine = CentralDecisionEngine()

__all__ = ["CentralDecisionEngine", "default_decision_engine"]
