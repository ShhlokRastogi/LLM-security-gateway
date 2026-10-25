from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Header, HTTPException, Query

from app.api.dependencies import get_client_id, tool_registry
from app.tools.models import (
    ToolDefinition,
    ToolRegistrationRequest,
    ToolUpdateRequest,
)

router = APIRouter(tags=["Tools"])


@router.post("/tools", response_model=ToolDefinition)
def register_tool_endpoint(
    req: ToolRegistrationRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Register a client/tenant tool with parameter schemas and risk category."""
    cid = req.client_id or x_client_id or "default"
    return tool_registry.register_tool(cid, req)


@router.get("/tools", response_model=List[ToolDefinition])
def list_tools_endpoint(
    include_defaults: bool = Query(True),
    x_client_id: Optional[str] = Header(None),
):
    """List all registered tools available to the client."""
    cid = get_client_id(x_client_id)
    return tool_registry.list_tools(cid, include_defaults=include_defaults)


@router.get("/tools/{tool_id_or_name}", response_model=ToolDefinition)
def get_tool_endpoint(
    tool_id_or_name: str,
    x_client_id: Optional[str] = Header(None),
):
    """Retrieve details of a specific tool by ID or name."""
    cid = get_client_id(x_client_id)
    tool = tool_registry.get_tool(cid, tool_id_or_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id_or_name}' not found.")
    return tool


@router.patch("/tools/{tool_id}", response_model=ToolDefinition)
def update_tool_endpoint(
    tool_id: str,
    req: ToolUpdateRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Update description, parameters, or risk configuration for a registered tool."""
    cid = get_client_id(x_client_id)
    updated = tool_registry.update_tool(cid, tool_id, req)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found for update.")
    return updated


@router.delete("/tools/{tool_id}")
def delete_tool_endpoint(
    tool_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Delete a registered tool from the tenant's registry."""
    cid = get_client_id(x_client_id)
    deleted = tool_registry.delete_tool(cid, tool_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found for deletion.")
    return {"deleted": True, "tool_id": tool_id}
