from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class AgentPermissions(BaseModel):
    """Explicit tool authorization permissions for a specific agent under a tenant."""
    client_id: str = Field(default="default", description="Tenant / client ID")
    agent_id: str = Field(..., description="Unique agent identifier (e.g. 'customer-support-v1')")
    allowed_tools: List[str] = Field(
        default_factory=list,
        description="Explicitly permitted tools or actions. Use '*' to permit all non-denied tools.",
    )
    denied_tools: List[str] = Field(
        default_factory=list,
        description="Explicitly prohibited tools that this agent can never invoke.",
    )
    description: Optional[str] = Field(default="", description="Description of the agent's role and scope")
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO timestamp of last update",
    )


class SetPermissionsRequest(BaseModel):
    allowed_tools: Optional[List[str]] = Field(default_factory=list)
    denied_tools: Optional[List[str]] = Field(default_factory=list)
    description: Optional[str] = ""


class PermissionCheckResult(BaseModel):
    is_permitted: bool
    agent_id: str
    tool_name: str
    reason: str
    client_id: str = "default"
