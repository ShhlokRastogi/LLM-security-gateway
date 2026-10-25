from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.api.dependencies import get_client_id, permission_manager, policy_engine, template_registry
from app.models.responses import PolicyTemplateInfo, PolicyTemplatesResponse
from app.permissions.models import SetPermissionsRequest
from app.policy.models import PolicyAction, PolicyDocument, PolicyOrigin, PolicyRule, PolicyScope

router = APIRouter(tags=["Declarative Policies & Templates"])


class ApplyTemplateRequest(BaseModel):
    agent_id: str
    customizations: Optional[Dict[str, Any]] = None


@router.get("/policy-templates", response_model=PolicyTemplatesResponse)
@router.get("/policies/templates", response_model=PolicyTemplatesResponse)
def list_policy_templates_endpoint():
    """List all available pre-existing policy templates."""
    templates = template_registry.get_template_info_list()
    return PolicyTemplatesResponse(templates=templates, count=len(templates))


@router.get("/policy-templates/{template_name}", response_model=PolicyTemplateInfo)
@router.get("/policies/templates/{template_name}", response_model=PolicyTemplateInfo)
def get_policy_template_endpoint(template_name: str):
    """Get full details of a specific policy template."""
    cfg = template_registry.get(template_name)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Policy template '{template_name}' not found.")
    version = template_registry.get_version(template_name)
    clean_name = template_name.split("@")[0]
    return PolicyTemplateInfo(
        name=clean_name,
        version=version,
        description=cfg.description or "",
        allowed_tools=cfg.allowed_tools,
        denied_tools=cfg.denied_tools or [],
        approval_required_tools=cfg.approval_required_tools or [],
        has_argument_constraints=bool(cfg.argument_constraints),
    )


@router.post("/policies", response_model=PolicyDocument)
def create_policy_endpoint(
    policy: PolicyDocument,
    x_client_id: Optional[str] = Header(None),
):
    """Create or register a custom declarative security policy document."""
    cid = policy.client_id or get_client_id(x_client_id)
    return policy_engine.create_policy(cid, policy)


@router.get("/policies", response_model=List[PolicyDocument])
def list_policies_endpoint(
    x_client_id: Optional[str] = Header(None),
):
    """List all active policies for the tenant."""
    cid = get_client_id(x_client_id)
    return policy_engine.list_policies(cid)


@router.get("/policies/{policy_id}", response_model=PolicyDocument)
def get_policy_endpoint(
    policy_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Get policy details by ID."""
    cid = get_client_id(x_client_id)
    pol = policy_engine.get_policy(cid, policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    return pol


@router.delete("/policies/{policy_id}")
def delete_policy_endpoint(
    policy_id: str,
    x_client_id: Optional[str] = Header(None),
):
    """Delete a custom security policy."""
    cid = get_client_id(x_client_id)
    deleted = policy_engine.delete_policy(cid, policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found for deletion.")
    return {"deleted": True, "policy_id": policy_id}


@router.post("/policy-templates/{template_name}/apply")
def apply_policy_template_endpoint(
    template_name: str,
    req: ApplyTemplateRequest,
    x_client_id: Optional[str] = Header(None),
):
    """Apply a pre-existing policy template to an agent, establishing its permissions and rules."""
    cid = get_client_id(x_client_id)
    cfg = template_registry.get(template_name)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Template '{template_name}' not found.")
    version = template_registry.get_version(template_name)

    # 1. Update Agent Permissions
    perms = permission_manager.set_permissions(
        client_id=cid,
        agent_id=req.agent_id,
        request=SetPermissionsRequest(
            allowed_tools=cfg.allowed_tools or ["*"],
            denied_tools=cfg.denied_tools or [],
            description=f"Applied from template {template_name}@{version}",
        ),
    )

    # 2. Register Applied Policy Document
    rules = []
    for at in (cfg.approval_required_tools or []):
        rules.append(
            PolicyRule(
                rule_id=f"rule-appr-{at}",
                description=f"Mandatory approval for {at}",
                match={"tool": at, "agent": req.agent_id},
                decision=PolicyAction.REQUIRE_APPROVAL,
                reason=f"Action '{at}' requires supervisor approval under {template_name}@{version}",
            )
        )

    pol = policy_engine.create_policy(
        client_id=cid,
        policy=PolicyDocument(
            policy_id=f"pol-applied-{template_name.split('@')[0]}-{req.agent_id}",
            name=f"Policy from {template_name}@{version}",
            version=version,
            client_id=cid,
            scope=PolicyScope.AGENT,
            origin=PolicyOrigin.TEMPLATE if not req.customizations else PolicyOrigin.CUSTOMIZED_TEMPLATE,
            rules=rules,
        ),
    )

    return {
        "status": "applied",
        "agent_id": req.agent_id,
        "template": f"{template_name}@{version}",
        "policy_id": pol.policy_id,
        "permissions": perms,
    }
