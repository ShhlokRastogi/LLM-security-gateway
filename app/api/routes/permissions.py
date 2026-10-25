from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Header, HTTPException

from app.api.dependencies import get_client_id, permission_manager
from app.permissions.models import AgentPermissions, SetPermissionsRequest

router = APIRouter(tags=["Agent Permissions"])


@router.post("/agents/{agent_id}/permissions", response_model=AgentPermissions)
def set_agent_permissions_endpoint(
    agent_id: str,
    req: SetPermissionsRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Configure allowed and denied tools for a specific agent under the tenant."""
    cid = get_client_id(x_client_id)
    return permission_manager.set_permissions(cid, agent_id, req)


@router.get("/agents/{agent_id}/permissions", response_model=AgentPermissions)
def get_agent_permissions_endpoint(
    agent_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Fetch tool authorization permissions for an agent."""
    cid = get_client_id(x_client_id)
    perms = permission_manager.get_permissions(cid, agent_id)
    if not perms:
        raise HTTPException(status_code=404, detail=f"Permissions not configured for agent '{agent_id}'.")
    return perms


@router.delete("/agents/{agent_id}/permissions")
def delete_agent_permissions_endpoint(
    agent_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Remove explicit permissions for an agent."""
    cid = get_client_id(x_client_id)
    deleted = permission_manager.delete_permissions(cid, agent_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Permissions not found for agent '{agent_id}'.")
    return {"deleted": True, "agent_id": agent_id}
