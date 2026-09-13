from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.permissions.models import AgentPermissions, PermissionCheckResult, SetPermissionsRequest


class PermissionManager:
    """Thread-safe, multi-tenant manager for Agent -> Tool permissions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Storage: client_id -> agent_id -> AgentPermissions
        self._permissions: Dict[str, Dict[str, AgentPermissions]] = {}
        self._seed_default_permissions()

    def _seed_default_permissions(self) -> None:
        """Seed baseline permissions for standard agent roles."""
        defaults = [
            AgentPermissions(
                client_id="default",
                agent_id="customer_support_agent",
                description="Customer support representative agent",
                allowed_tools=["search_orders", "get_customer", "send_email", "refund_payment"],
                denied_tools=["execute_code", "query_database", "delete_file"],
            ),
            AgentPermissions(
                client_id="default",
                agent_id="research_agent",
                description="Read-only research assistant",
                allowed_tools=["search_orders", "get_customer", "read_file", "search_documentation"],
                denied_tools=["refund_payment", "execute_code", "query_database", "delete_file", "send_email"],
            ),
            AgentPermissions(
                client_id="default",
                agent_id="data_analyst",
                description="SQL database query agent",
                allowed_tools=["query_database", "search_orders", "get_customer"],
                denied_tools=["delete_file", "execute_code", "send_email"],
            ),
        ]
        for p in defaults:
            self._insert_permissions(p)

    def _insert_permissions(self, perm: AgentPermissions) -> None:
        cid = perm.client_id
        if cid not in self._permissions:
            self._permissions[cid] = {}
        self._permissions[cid][perm.agent_id] = perm

    def set_permissions(
        self,
        client_id: str,
        agent_id: str,
        request: SetPermissionsRequest,
    ) -> AgentPermissions:
        with self._lock:
            cid = client_id or "default"
            aid = agent_id.strip()
            perm = AgentPermissions(
                client_id=cid,
                agent_id=aid,
                allowed_tools=request.allowed_tools or [],
                denied_tools=request.denied_tools or [],
                description=request.description or "",
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            self._insert_permissions(perm)
            return perm

    def get_permissions(self, client_id: str, agent_id: str) -> Optional[AgentPermissions]:
        with self._lock:
            cid = client_id or "default"
            aid = agent_id.strip()
            # Check tenant-specific first, then fallback to default
            if cid in self._permissions and aid in self._permissions[cid]:
                return self._permissions[cid][aid]
            if cid != "default" and "default" in self._permissions and aid in self._permissions["default"]:
                return self._permissions["default"][aid]
            return None

    def list_permissions(self, client_id: str) -> List[AgentPermissions]:
        with self._lock:
            cid = client_id or "default"
            perms = []
            if cid in self._permissions:
                perms.extend(self._permissions[cid].values())
            if cid != "default" and "default" in self._permissions:
                tenant_agent_ids = {p.agent_id for p in perms}
                for dp in self._permissions["default"].values():
                    if dp.agent_id not in tenant_agent_ids:
                        perms.append(dp)
            return perms

    def delete_permissions(self, client_id: str, agent_id: str) -> bool:
        with self._lock:
            cid = client_id or "default"
            aid = agent_id.strip()
            if cid in self._permissions and aid in self._permissions[cid]:
                del self._permissions[cid][aid]
                return True
            return False

    def check_permission(
        self,
        client_id: str,
        agent_id: str,
        tool_name: str,
    ) -> PermissionCheckResult:
        """Evaluates whether agent_id is authorized to call tool_name at all."""
        with self._lock:
            cid = client_id or "default"
            aid = agent_id.strip() if agent_id else "anonymous"
            tool = tool_name.strip()

            perm = self.get_permissions(cid, aid)

            # If no explicit permissions exist for agent:
            if not perm:
                # Default security stance: allow general tools, but flag unconfigured agent
                return PermissionCheckResult(
                    is_permitted=True,
                    agent_id=aid,
                    tool_name=tool,
                    client_id=cid,
                    reason=f"No explicit permission profile configured for agent '{aid}'; proceeding with policy evaluation.",
                )

            # 1. Check Denied Tools
            if perm.denied_tools and (tool in perm.denied_tools or "*" in perm.denied_tools):
                return PermissionCheckResult(
                    is_permitted=False,
                    agent_id=aid,
                    tool_name=tool,
                    client_id=cid,
                    reason=f"Tool '{tool}' is explicitly prohibited for agent '{aid}'.",
                )

            # 2. Check Allowed Tools
            if perm.allowed_tools:
                if "*" in perm.allowed_tools or tool in perm.allowed_tools:
                    return PermissionCheckResult(
                        is_permitted=True,
                        agent_id=aid,
                        tool_name=tool,
                        client_id=cid,
                        reason=f"Tool '{tool}' is explicitly permitted for agent '{aid}'.",
                    )
                else:
                    return PermissionCheckResult(
                        is_permitted=False,
                        agent_id=aid,
                        tool_name=tool,
                        client_id=cid,
                        reason=f"Tool '{tool}' is not in the allowed tools whitelist for agent '{aid}'.",
                    )

            return PermissionCheckResult(
                is_permitted=True,
                agent_id=aid,
                tool_name=tool,
                client_id=cid,
                reason=f"Agent '{aid}' has unrestricted allowed_tools.",
            )


default_permission_manager = PermissionManager()

__all__ = ["PermissionManager", "default_permission_manager"]
