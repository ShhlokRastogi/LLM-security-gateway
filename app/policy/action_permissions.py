from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from app.models.requests import (
    ActionArgumentConstraint,
    ActionPolicyConfig,
    CheckActionRequest,
    CheckBatchActionsRequest,
)
from app.models.responses import (
    ActionDecision,
    ActionSecurityDecision,
    ActionViolationItem,
    BatchActionsSecurityDecision,
)
from app.policy.templates import PolicyTemplateRegistry, default_template_registry


class ActionPermissionsLayer:
    """Action Permissions and Tool Execution Guardrail Engine."""

    # Universal security heuristics for argument inspection
    PATH_TRAVERSAL_REGEX = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)", re.IGNORECASE)
    DANGEROUS_COMMANDS = [
        re.compile(r"\brm\s+-(?:r[fF]|f[rR])\b", re.IGNORECASE),
        re.compile(r"\b(?:sudo|mkfs|format|fdisk|dd\s+if=)\b", re.IGNORECASE),
        re.compile(r"\bcurl\s+[^|]+\|\s*(?:ba|z)?sh\b", re.IGNORECASE),
        re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    ]

    def __init__(self, registry: Optional[PolicyTemplateRegistry] = None) -> None:
        self.registry = registry or default_template_registry

    def resolve_policy(
        self,
        template_name: Optional[str],
        custom_policy: Optional[ActionPolicyConfig],
    ) -> Tuple[ActionPolicyConfig, str]:
        """Resolves the active policy configuration by merging template and custom rules."""
        base_policy: Optional[ActionPolicyConfig] = None
        source = "default"

        if template_name:
            base_policy = self.registry.get(template_name)
            if base_policy:
                source = f"template:{template_name}"

        if base_policy is None:
            base_policy = ActionPolicyConfig(
                description="Default balanced action policy",
                allowed_tools=["*"],
                denied_tools=["execute_command", "bash", "powershell", "sudo", "format_disk"],
                approval_required_tools=["issue_refund", "send_email", "delete_database"],
                allow_unknown_tools=True,
            )

        if custom_policy is None:
            return base_policy, source

        # Merge custom policy over base policy
        source = f"{source}+custom" if template_name else "custom"
        
        merged_allowed = custom_policy.allowed_tools if custom_policy.allowed_tools is not None else base_policy.allowed_tools
        merged_denied = list(set((base_policy.denied_tools or []) + (custom_policy.denied_tools or [])))
        merged_approval = list(set((base_policy.approval_required_tools or []) + (custom_policy.approval_required_tools or [])))
        
        merged_constraints = dict(base_policy.argument_constraints or {})
        if custom_policy.argument_constraints:
            for tool, c_map in custom_policy.argument_constraints.items():
                if tool not in merged_constraints:
                    merged_constraints[tool] = {}
                merged_constraints[tool].update(c_map)

        merged = ActionPolicyConfig(
            description=custom_policy.description or base_policy.description,
            allowed_tools=merged_allowed,
            denied_tools=merged_denied,
            approval_required_tools=merged_approval,
            argument_constraints=merged_constraints,
            allow_unknown_tools=custom_policy.allow_unknown_tools,
        )
        return merged, source

    def evaluate_action(self, request: CheckActionRequest) -> ActionSecurityDecision:
        t0 = time.perf_counter()
        req_id = f"act-{uuid.uuid4().hex[:8]}"

        policy, policy_source = self.resolve_policy(
            template_name=request.policy_template,
            custom_policy=request.custom_policy,
        )

        tool = request.tool_name.strip()
        args = request.arguments or {}
        violations: List[ActionViolationItem] = []
        reasons: List[str] = []

        # 1. Check Explicitly Denied Tools
        if policy.denied_tools and tool in policy.denied_tools:
            violations.append(
                ActionViolationItem(
                    tool_name=tool,
                    rule="denied_tool",
                    message=f"Tool '{tool}' is explicitly prohibited by security policy.",
                    severity="high",
                )
            )
            reasons.append(f"Tool '{tool}' is in the prohibited tools list.")

        # 2. Check Tool Whitelist (if allowed_tools is configured without wildcard)
        if policy.allowed_tools and "*" not in policy.allowed_tools:
            if tool not in policy.allowed_tools and not policy.allow_unknown_tools:
                violations.append(
                    ActionViolationItem(
                        tool_name=tool,
                        rule="unauthorized_tool",
                        message=f"Tool '{tool}' is not in the allowed tools whitelist for this agent role.",
                        severity="high",
                    )
                )
                reasons.append(f"Tool '{tool}' is not authorized for this agent role.")

        # 3. Parameter and Argument Guardrails
        arg_violations = self._inspect_arguments(tool, args, policy)
        violations.extend(arg_violations)
        for v in arg_violations:
            reasons.append(v.message)

        # 4. Determine Decision
        latency = round((time.perf_counter() - t0) * 1000, 2)

        if violations:
            return ActionSecurityDecision(
                decision=ActionDecision.BLOCK,
                tool_name=tool,
                arguments=args,
                risk_score=1.0,
                reasons=reasons,
                violations=violations,
                policy_source=policy_source,
                requires_approval=False,
                request_id=req_id,
                latency_ms=latency,
            )

        # 5. Check Approval-Required Tools (Human-in-the-loop)
        if policy.approval_required_tools and tool in policy.approval_required_tools:
            return ActionSecurityDecision(
                decision=ActionDecision.REQUIRE_APPROVAL,
                tool_name=tool,
                arguments=args,
                risk_score=0.50,
                reasons=[f"Action '{tool}' is sensitive and requires human-in-the-loop authorization."],
                violations=[],
                policy_source=policy_source,
                requires_approval=True,
                request_id=req_id,
                latency_ms=latency,
            )

        # 6. Allow Safe Action
        return ActionSecurityDecision(
            decision=ActionDecision.ALLOW,
            tool_name=tool,
            arguments=args,
            risk_score=0.0,
            reasons=[f"Tool '{tool}' and arguments satisfy all policy constraints."],
            violations=[],
            policy_source=policy_source,
            requires_approval=False,
            request_id=req_id,
            latency_ms=latency,
        )

    def evaluate_batch(self, batch_request: CheckBatchActionsRequest) -> BatchActionsSecurityDecision:
        t0 = time.perf_counter()
        req_id = f"batch-{uuid.uuid4().hex[:8]}"

        decisions: List[ActionSecurityDecision] = []
        blocked_count = 0
        approval_count = 0

        for single_action in batch_request.actions:
            # Fallback to batch-level policy if action didn't define its own
            if single_action.policy_template is None:
                single_action.policy_template = batch_request.policy_template
            if single_action.custom_policy is None:
                single_action.custom_policy = batch_request.custom_policy

            dec = self.evaluate_action(single_action)
            decisions.append(dec)

            if dec.decision == ActionDecision.BLOCK:
                blocked_count += 1
            elif dec.decision == ActionDecision.REQUIRE_APPROVAL:
                approval_count += 1

        if blocked_count > 0:
            overall = ActionDecision.BLOCK
        elif approval_count > 0:
            overall = ActionDecision.REQUIRE_APPROVAL
        else:
            overall = ActionDecision.ALLOW

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return BatchActionsSecurityDecision(
            overall_decision=overall,
            decisions=decisions,
            all_allowed=(overall == ActionDecision.ALLOW),
            requires_approval_count=approval_count,
            blocked_count=blocked_count,
            request_id=req_id,
            latency_ms=latency,
        )

    def _inspect_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        policy: ActionPolicyConfig,
    ) -> List[ActionViolationItem]:
        violations: List[ActionViolationItem] = []

        # Built-in generic heuristics across all tools
        for param_name, val in arguments.items():
            if not isinstance(val, str):
                continue

            # Path Traversal Check on path/file/dir parameters
            if any(k in param_name.lower() for k in ["path", "file", "dir", "dest", "target"]):
                if self.PATH_TRAVERSAL_REGEX.search(val):
                    violations.append(
                        ActionViolationItem(
                            tool_name=tool_name,
                            parameter=param_name,
                            rule="path_traversal",
                            message=f"Path traversal sequence ('..') detected in parameter '{param_name}'.",
                            severity="high",
                        )
                    )

            # Shell Command Check on command/cmd/exec/script parameters
            if any(k in param_name.lower() for k in ["command", "cmd", "exec", "script", "code"]):
                for d_regex in self.DANGEROUS_COMMANDS:
                    if d_regex.search(val):
                        violations.append(
                            ActionViolationItem(
                                tool_name=tool_name,
                                parameter=param_name,
                                rule="dangerous_command",
                                message=f"Dangerous shell command signature detected in parameter '{param_name}'.",
                                severity="high",
                            )
                        )
                        break

        # Policy-defined Argument Constraints
        tool_constraints = (policy.argument_constraints or {}).get(tool_name, {})
        for param_name, constraint in tool_constraints.items():
            if param_name not in arguments:
                continue

            val = arguments[param_name]

            # 1. Allowed Values
            if constraint.allowed_values is not None and val not in constraint.allowed_values:
                violations.append(
                    ActionViolationItem(
                        tool_name=tool_name,
                        parameter=param_name,
                        rule="value_not_allowed",
                        message=f"Value '{val}' for parameter '{param_name}' is not in permitted values {constraint.allowed_values}.",
                        severity="medium",
                    )
                )

            if isinstance(val, str):
                # 2. Max length
                if constraint.max_length and len(val) > constraint.max_length:
                    violations.append(
                        ActionViolationItem(
                            tool_name=tool_name,
                            parameter=param_name,
                            rule="max_length_exceeded",
                            message=f"Parameter '{param_name}' length ({len(val)}) exceeds maximum permitted length ({constraint.max_length}).",
                            severity="medium",
                        )
                    )

                # 3. Allowed Prefixes
                if constraint.allowed_prefixes:
                    if not any(val.startswith(pfx) for pfx in constraint.allowed_prefixes):
                        violations.append(
                            ActionViolationItem(
                                tool_name=tool_name,
                                parameter=param_name,
                                rule="prefix_disallowed",
                                message=f"Parameter '{param_name}' does not start with an authorized prefix {constraint.allowed_prefixes}.",
                                severity="high",
                            )
                        )

                # 4. Forbidden Keywords (case-insensitive)
                if constraint.forbidden_keywords:
                    val_upper = val.upper()
                    for kw in constraint.forbidden_keywords:
                        # Match word boundaries for SQL keywords like DROP, DELETE, etc.
                        if re.search(rf"\b{re.escape(kw.upper())}\b", val_upper):
                            violations.append(
                                ActionViolationItem(
                                    tool_name=tool_name,
                                    parameter=param_name,
                                    rule="forbidden_keyword",
                                    message=f"Prohibited keyword '{kw}' detected in parameter '{param_name}'.",
                                    severity="high",
                                )
                            )
                            break

                # 5. Forbidden Patterns (regex)
                if constraint.forbidden_patterns:
                    for pat in constraint.forbidden_patterns:
                        if re.search(pat, val):
                            violations.append(
                                ActionViolationItem(
                                    tool_name=tool_name,
                                    parameter=param_name,
                                    rule="pattern_violation",
                                    message=f"Parameter '{param_name}' matched forbidden pattern '{pat}'.",
                                    severity="high",
                                )
                            )
                            break

        return violations


default_action_layer = ActionPermissionsLayer()

__all__ = ["ActionPermissionsLayer", "default_action_layer"]
