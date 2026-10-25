from __future__ import annotations

from typing import Optional
from fastapi import Header

from app.approvals.manager import default_approval_manager
from app.audit.logger import default_audit_logger
from app.decision.engine import default_decision_engine
from app.permissions.manager import default_permission_manager
from app.policy.action_permissions import default_action_layer
from app.policy.declarative_engine import default_declarative_engine
from app.policy.templates import default_template_registry
from app.services.logging import get_security_logger
from app.services.pipeline import SecurityPipeline
from app.tools.registry import default_tool_registry

logger = get_security_logger("security.api")

# Shared Singletons
pipeline = SecurityPipeline()
tool_registry = default_tool_registry
permission_manager = default_permission_manager
policy_engine = default_declarative_engine
template_registry = default_template_registry
approval_manager = default_approval_manager
decision_engine = default_decision_engine
audit_logger = default_audit_logger
action_layer = default_action_layer


def get_client_id(x_client_id: Optional[str] = Header(None)) -> str:
    """Resolve tenant/client ID from request header, falling back to 'default'."""
    return x_client_id or "default"
