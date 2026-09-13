from __future__ import annotations

from typing import Any, Dict, List, Optional
import httpx


class SecurityGatewayClient:
    """Python client for communicating with the LLM Security Gateway over HTTP."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_input(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/input",
                json={"text": text, "metadata": metadata or {}},
            )
            resp.raise_for_status()
            return resp.json()

    def check_output(
        self,
        text: str,
        evidence_context: Optional[List[str]] = None,
        evidence_sources: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/output",
                json={
                    "text": text,
                    "evidence_context": evidence_context,
                    "evidence_sources": evidence_sources,
                    "metadata": metadata or {},
                },
            )
            resp.raise_for_status()
            return resp.json()

    def check_action(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        client_id: Optional[str] = None,
        policy_template: Optional[str] = None,
        custom_policy: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Inspect and authorize an agent tool action before execution."""
        payload = {
            "tool_name": tool_name,
            "arguments": arguments or {},
            "agent_id": agent_id,
            "client_id": client_id,
            "policy_template": policy_template,
            "custom_policy": custom_policy,
            "metadata": metadata or {},
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/action",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    def check_batch_actions(
        self,
        actions: List[Dict[str, Any]],
        policy_template: Optional[str] = None,
        custom_policy: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Inspect multiple parallel tool actions."""
        payload = {
            "actions": actions,
            "policy_template": policy_template,
            "custom_policy": custom_policy,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/v1/check/actions",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    def get_policy_templates(self) -> List[Dict[str, Any]]:
        """List all pre-existing policy templates available on the gateway."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}/v1/policies/templates")
            resp.raise_for_status()
            return resp.json().get("templates", [])

    def health(self) -> Dict[str, Any]:
        with httpx.Client(timeout=self.timeout) as client:
            return client.get(f"{self.base_url}/health").json()
