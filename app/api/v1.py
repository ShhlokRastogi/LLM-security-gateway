from __future__ import annotations

from fastapi import APIRouter

# Re-export shared singletons and dependencies for backward compatibility
from app.api.dependencies import (
    action_layer,
    approval_manager,
    audit_logger,
    decision_engine,
    get_client_id,
    logger,
    permission_manager,
    pipeline,
    policy_engine,
    template_registry,
    tool_registry,
)
from app.api.routes.actions import router as actions_router
from app.api.routes.approvals import router as approvals_router
from app.api.routes.audit import router as audit_router
from app.api.routes.guardrails import router as guardrails_router
from app.api.routes.permissions import router as permissions_router
from app.api.routes.policies import ApplyTemplateRequest, router as policies_router
from app.api.routes.tools import router as tools_router

router = APIRouter(prefix="/v1", tags=["Security Gateway V1"])

# Mount modular domain sub-routers
router.include_router(tools_router)
router.include_router(permissions_router)
router.include_router(policies_router)
router.include_router(actions_router)
router.include_router(approvals_router)
router.include_router(audit_router)
router.include_router(guardrails_router)

__all__ = [
    "router",
    "pipeline",
    "logger",
    "tool_registry",
    "permission_manager",
    "policy_engine",
    "template_registry",
    "approval_manager",
    "decision_engine",
    "audit_logger",
    "action_layer",
    "get_client_id",
    "ApplyTemplateRequest",
]
