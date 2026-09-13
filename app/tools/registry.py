from __future__ import annotations

import threading
import uuid
from typing import Dict, List, Optional
from app.tools.models import (
    ArgumentType,
    ToolDefinition,
    ToolParameterSchema,
    ToolRegistrationRequest,
    ToolRiskCategory,
    ToolUpdateRequest,
)


class ToolRegistry:
    """Thread-safe, multi-tenant registry for client-defined and built-in tools."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Storage structure: client_id -> tool_id -> ToolDefinition
        self._tools_by_id: Dict[str, Dict[str, ToolDefinition]] = {}
        # Secondary index: client_id -> tool_name -> tool_id
        self._name_index: Dict[str, Dict[str, str]] = {}
        self._seed_default_tools()

    def _seed_default_tools(self) -> None:
        defaults = [
            ToolDefinition(
                tool_id="builtin-search-orders",
                tool_name="search_orders",
                description="Search customer orders by customer_id or query",
                client_id="default",
                risk_category=ToolRiskCategory.READ_ONLY,
                parameters={
                    "query": ToolParameterSchema(name="query", type=ArgumentType.STRING, required=False),
                    "customer_id": ToolParameterSchema(name="customer_id", type=ArgumentType.STRING, required=False),
                    "limit": ToolParameterSchema(name="limit", type=ArgumentType.INTEGER, required=False, min_value=1, max_value=100),
                },
            ),
            ToolDefinition(
                tool_id="builtin-get-customer",
                tool_name="get_customer",
                description="Retrieve customer profile by ID or email",
                client_id="default",
                risk_category=ToolRiskCategory.READ_ONLY,
                parameters={
                    "customer_id": ToolParameterSchema(name="customer_id", type=ArgumentType.STRING, required=False),
                    "email": ToolParameterSchema(name="email", type=ArgumentType.STRING, required=False),
                },
            ),
            ToolDefinition(
                tool_id="builtin-refund-payment",
                tool_name="refund_payment",
                description="Issue financial refund for an existing order",
                client_id="default",
                risk_category=ToolRiskCategory.FINANCIAL,
                parameters={
                    "order_id": ToolParameterSchema(name="order_id", type=ArgumentType.STRING, required=True),
                    "amount": ToolParameterSchema(name="amount", type=ArgumentType.FLOAT, required=True, min_value=0.01),
                    "currency": ToolParameterSchema(name="currency", type=ArgumentType.STRING, required=False, allowed_values=["USD", "EUR", "GBP", "CAD"]),
                    "reason": ToolParameterSchema(name="reason", type=ArgumentType.STRING, required=False, max_length=500),
                },
            ),
            ToolDefinition(
                tool_id="builtin-query-database",
                tool_name="query_database",
                description="Execute database query",
                client_id="default",
                risk_category=ToolRiskCategory.DATA_MUTATION,
                parameters={
                    "query": ToolParameterSchema(
                        name="query",
                        type=ArgumentType.STRING,
                        required=True,
                        forbidden_keywords=["DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"],
                    ),
                },
            ),
            ToolDefinition(
                tool_id="builtin-delete-file",
                tool_name="delete_file",
                description="Delete a file on the host filesystem",
                client_id="default",
                risk_category=ToolRiskCategory.PRIVILEGED,
                parameters={
                    "path": ToolParameterSchema(
                        name="path",
                        type=ArgumentType.STRING,
                        required=True,
                        forbidden_patterns=[r"(?:^|[\\/])\.\.(?:[\\/]|$)", r"^/(?:etc|root|var|boot|sys)"],
                    ),
                },
            ),
            ToolDefinition(
                tool_id="builtin-send-email",
                tool_name="send_email",
                description="Send email to recipient",
                client_id="default",
                risk_category=ToolRiskCategory.EXTERNAL_COMMUNICATION,
                parameters={
                    "recipient": ToolParameterSchema(name="recipient", type=ArgumentType.STRING, required=True),
                    "subject": ToolParameterSchema(name="subject", type=ArgumentType.STRING, required=True),
                    "body": ToolParameterSchema(name="body", type=ArgumentType.STRING, required=True),
                },
            ),
            ToolDefinition(
                tool_id="builtin-execute-code",
                tool_name="execute_code",
                description="Execute arbitrary script or shell code",
                client_id="default",
                risk_category=ToolRiskCategory.SYSTEM_COMMAND,
                parameters={
                    "command": ToolParameterSchema(
                        name="command",
                        type=ArgumentType.STRING,
                        required=True,
                        forbidden_keywords=["sudo", "rm -rf", "mkfs", "format", "dd if="],
                    ),
                },
            ),
        ]
        for t in defaults:
            self._insert_tool(t)

    def _insert_tool(self, tool: ToolDefinition) -> None:
        cid = tool.client_id
        if cid not in self._tools_by_id:
            self._tools_by_id[cid] = {}
            self._name_index[cid] = {}
        self._tools_by_id[cid][tool.tool_id] = tool
        self._name_index[cid][tool.tool_name] = tool.tool_id

    def register_tool(self, client_id: str, request: ToolRegistrationRequest) -> ToolDefinition:
        with self._lock:
            cid = client_id or request.client_id or "default"
            tid = f"tool-{uuid.uuid4().hex[:8]}"
            tool = ToolDefinition(
                tool_id=tid,
                tool_name=request.tool_name.strip(),
                description=request.description or "",
                client_id=cid,
                parameters=request.parameters or {},
                risk_category=request.risk_category or ToolRiskCategory.GENERAL,
                is_enabled=request.is_enabled if request.is_enabled is not None else True,
                metadata=request.metadata or {},
            )
            self._insert_tool(tool)
            return tool

    def get_tool(self, client_id: str, name_or_id: str) -> Optional[ToolDefinition]:
        with self._lock:
            # Check tenant specific first
            cids_to_check = [client_id] if client_id != "default" else []
            cids_to_check.append("default")

            for cid in cids_to_check:
                if cid in self._tools_by_id:
                    # By ID
                    if name_or_id in self._tools_by_id[cid]:
                        return self._tools_by_id[cid][name_or_id]
                    # By Name
                    if name_or_id in self._name_index.get(cid, {}):
                        tid = self._name_index[cid][name_or_id]
                        return self._tools_by_id[cid].get(tid)
            return None

    def list_tools(self, client_id: str, include_defaults: bool = True) -> List[ToolDefinition]:
        with self._lock:
            tools = []
            if client_id in self._tools_by_id:
                tools.extend(self._tools_by_id[client_id].values())
            if include_defaults and client_id != "default" and "default" in self._tools_by_id:
                # Add default tools that are not shadowed by tenant
                tenant_names = {t.tool_name for t in tools}
                for dt in self._tools_by_id["default"].values():
                    if dt.tool_name not in tenant_names:
                        tools.append(dt)
            return list(tools)

    def update_tool(self, client_id: str, tool_id: str, update: ToolUpdateRequest) -> Optional[ToolDefinition]:
        with self._lock:
            cid = client_id or "default"
            if cid in self._tools_by_id and tool_id in self._tools_by_id[cid]:
                current = self._tools_by_id[cid][tool_id]
                updated = ToolDefinition(
                    tool_id=current.tool_id,
                    tool_name=current.tool_name,
                    description=update.description if update.description is not None else current.description,
                    client_id=current.client_id,
                    parameters=update.parameters if update.parameters is not None else current.parameters,
                    risk_category=update.risk_category if update.risk_category is not None else current.risk_category,
                    is_enabled=update.is_enabled if update.is_enabled is not None else current.is_enabled,
                    metadata=update.metadata if update.metadata is not None else current.metadata,
                )
                self._tools_by_id[cid][tool_id] = updated
                return updated
            return None

    def delete_tool(self, client_id: str, tool_id: str) -> bool:
        with self._lock:
            cid = client_id or "default"
            if cid in self._tools_by_id and tool_id in self._tools_by_id[cid]:
                tool = self._tools_by_id[cid].pop(tool_id)
                self._name_index[cid].pop(tool.tool_name, None)
                return True
            return False


default_tool_registry = ToolRegistry()

__all__ = ["ToolRegistry", "default_tool_registry"]
