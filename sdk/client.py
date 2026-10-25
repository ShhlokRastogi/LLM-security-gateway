from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union
import httpx
from sdk.exceptions import ApprovalRequiredError, SecurityDenialError, SecurityGatewayError


class ActionDecisionResult:
    """Encapsulates the gateway's pre-execution evaluation for an action."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.action = raw.get("decision", "DENY")
        self.decision = self.action
        self.allowed_to_execute = bool(raw.get("allowed_to_execute", False))
        self.tool_name = raw.get("tool_name", "")
        self.arguments = raw.get("arguments", {})
        self.risk = raw.get("risk", {})
        self.risk_level = self.risk.get("risk_level", "LOW")
        self.risk_score = self.risk.get("risk_score", 0.0)
        self.reasons = raw.get("reasons", [])
        self.policy_id = raw.get("policy_id")
        self.policy_version = raw.get("policy_version")
        self.approval_id = raw.get("approval_id")
        self.approval_required = bool(raw.get("approval_required", False))
        self.validation_errors = raw.get("validation_errors", [])
        self.request_id = raw.get("request_id", "")
        self.latency_ms = raw.get("latency_ms", 0.0)

    def is_allowed(self) -> bool:
        return self.action == "ALLOW" and self.allowed_to_execute

    def is_denied(self) -> bool:
        return self.action == "DENY"

    def requires_approval(self) -> bool:
        return self.action == "REQUIRE_APPROVAL"

    def __getitem__(self, item: str) -> Any:
        return self.raw[item]

    def get(self, item: str, default: Any = None) -> Any:
        return self.raw.get(item, default)

    def __contains__(self, item: str) -> bool:
        return item in self.raw

    def __repr__(self) -> str:
        return f"<ActionDecisionResult decision={self.action} tool={self.tool_name} risk={self.risk_level}>"


class InspectionDecisionResult:
    """Encapsulates input prompt or output completion inspection results."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.decision = raw.get("decision", "allow")
        self.action = self.decision
        self.risk_score = raw.get("risk_score", 0.0)
        self.text = raw.get("text", "")
        self.detections = raw.get("detections", [])
        self.request_id = raw.get("request_id", "")
        self.latency_ms = raw.get("latency_ms", 0.0)

    @property
    def is_allowed(self) -> bool:
        return self.decision in ("allow", "redact")

    @property
    def is_blocked(self) -> bool:
        return self.decision == "block"

    def __getitem__(self, item: str) -> Any:
        return self.raw[item]

    def get(self, item: str, default: Any = None) -> Any:
        return self.raw.get(item, default)

    def __contains__(self, item: str) -> bool:
        return item in self.raw

    def __repr__(self) -> str:
        return f"<InspectionDecisionResult decision={self.decision} risk={self.risk_score:.2f}>"


class SecurityGateway:
    """Production-grade Python SDK for securing Agentic AI systems across Input, Output, and Action boundaries."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        client_id: str = "default",
        api_key: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Client-ID": self.client_id,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # --- 1. Action Security Guard ---

    def check_action(
        self,
        agent_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        user: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        approval_id: Optional[str] = None,
        policy_template: Optional[str] = None,
        custom_policies: Optional[List[Dict[str, Any]]] = None,
    ) -> ActionDecisionResult:
        """Evaluates permissions, schemas, risk, and policy rules before a tool call executes."""
        payload = {
            "client_id": self.client_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "user": user or {"role": "user"},
            "context": context or {"environment": "development"},
            "approval_id": approval_id,
            "policy_template": policy_template,
            "custom_policies": custom_policies,
        }

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/actions/check",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return ActionDecisionResult(resp.json())

    def secure_execute(
        self,
        agent_id: str,
        tool_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        tool_callable: Optional[Callable[..., Any]] = None,
        user: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        approval_id: Optional[str] = None,
        policy_template: Optional[str] = None,
    ) -> Any:
        """Secure execution helper: authorizes tool call before invocation.
        Can be invoked directly or used as a function decorator:
            @gateway.secure_execute(agent_id="support_bot")
            def my_tool(...): ...
        """
        # Decorator mode: @gateway.secure_execute(agent_id="...", ...)
        if tool_callable is None and arguments is None:
            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                target_tool_name = tool_name or fn.__name__

                @functools.wraps(fn)
                def wrapper(*args: Any, **kwargs: Any) -> Any:
                    sig = inspect.signature(fn)
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    call_args = bound.arguments
                    appr_id = kwargs.pop("__approval_id", approval_id)
                    return self.secure_execute(
                        agent_id=agent_id,
                        tool_name=target_tool_name,
                        arguments=call_args,
                        tool_callable=fn,
                        user=user,
                        context=context,
                        approval_id=appr_id,
                        policy_template=policy_template,
                    )

                return wrapper

            return decorator

        # Direct execution mode
        if tool_callable is None:
            raise ValueError("tool_callable must be provided when not used as a decorator.")

        actual_tool_name = tool_name or getattr(tool_callable, "__name__", "tool")
        decision = self.check_action(
            agent_id=agent_id,
            tool_name=actual_tool_name,
            arguments=arguments or {},
            user=user,
            context=context,
            approval_id=approval_id,
            policy_template=policy_template,
        )

        if decision.is_allowed():
            return tool_callable(**(arguments or {}))
        elif decision.requires_approval():
            raise ApprovalRequiredError(
                tool_name=actual_tool_name,
                approval_id=decision.approval_id or "",
                reasons=decision.reasons,
            )
        else:
            raise SecurityDenialError(
                tool_name=actual_tool_name,
                reasons=decision.reasons,
            )

    # --- 2. Human Approvals ---

    def list_approvals(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"status": status} if status else {}
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/v1/approvals", params=params, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/v1/approvals/{approval_id}", headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def approve_action(
        self,
        approval_id: str,
        approver_id: str,
        approver_role: str = "supervisor",
        reason: str = "",
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/approvals/{approval_id}/approve",
                json={"approver_id": approver_id, "approver_role": approver_role, "reason": reason},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def deny_action(self, approval_id: str, approver_id: str, reason: str = "") -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/approvals/{approval_id}/deny",
                json={"approver_id": approver_id, "reason": reason},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # --- 3. Tool & Policy Management ---

    def register_tool(
        self,
        tool_name: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None,
        risk_category: str = "general",
    ) -> Dict[str, Any]:
        payload = {
            "tool_name": tool_name,
            "description": description,
            "client_id": self.client_id,
            "parameters": parameters or {},
            "risk_category": risk_category,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/v1/tools", json=payload, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def set_agent_permissions(
        self,
        agent_id: str,
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "allowed_tools": allowed_tools or [],
            "denied_tools": denied_tools or [],
            "description": description,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/agents/{agent_id}/permissions",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def apply_policy_template(self, template_name: str, agent_id: str) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/policy-templates/{template_name}/apply",
                json={"agent_id": agent_id},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # --- 4. Input & Output Guards ---

    def check_input(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> InspectionDecisionResult:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/input",
                json={"text": text, "metadata": metadata or {}},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return InspectionDecisionResult(resp.json())

    def check_output(
        self,
        text: str,
        evidence_context: Optional[List[str]] = None,
        evidence_sources: Optional[List[str]] = None,
        context: Optional[Union[str, List[str]]] = None,
    ) -> InspectionDecisionResult:
        ctx = evidence_context
        if ctx is None and context is not None:
            ctx = [context] if isinstance(context, str) else list(context)

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/output",
                json={
                    "text": text,
                    "evidence_context": ctx,
                    "evidence_sources": evidence_sources,
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return InspectionDecisionResult(resp.json())

    # Documentation and quickstart aliases
    inspect_input = check_input
    inspect_output = check_output


__all__ = [
    "SecurityGateway",
    "ActionDecisionResult",
    "InspectionDecisionResult",
    "SecurityGatewayError",
    "SecurityDenialError",
    "ApprovalRequiredError",
]
