from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_tool_registry_crud_lifecycle():
    """Test full registration, retrieval, update, listing, and deletion of a custom tool."""
    tool_payload = {
        "tool_name": "process_wire_transfer",
        "description": "Initiate interbank wire transfer",
        "client_id": "test_corp",
        "risk_category": "financial",
        "parameters": {
            "amount": {
                "name": "amount",
                "type": "float",
                "required": True,
                "min_value": 1.0,
                "max_value": 100000.0,
            },
            "recipient_iban": {
                "name": "recipient_iban",
                "type": "string",
                "required": True,
            },
        },
    }

    # 1. Register Tool
    resp = client.post("/v1/tools", json=tool_payload, headers={"X-Client-ID": "test_corp"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["tool_name"] == "process_wire_transfer"
    assert data["risk_category"] == "financial"
    tool_id = data["tool_id"]

    # 2. Get Tool by Name
    get_resp = client.get("/v1/tools/process_wire_transfer", headers={"X-Client-ID": "test_corp"})
    assert get_resp.status_code == 200
    assert get_resp.json()["tool_id"] == tool_id

    # 3. Update Tool
    patch_resp = client.patch(
        f"/v1/tools/{tool_id}",
        json={"description": "Updated wire transfer tool description"},
        headers={"X-Client-ID": "test_corp"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["description"] == "Updated wire transfer tool description"

    # 4. List Tools
    list_resp = client.get("/v1/tools", headers={"X-Client-ID": "test_corp"})
    assert list_resp.status_code == 200
    tool_names = [t["tool_name"] for t in list_resp.json()]
    assert "process_wire_transfer" in tool_names

    # 5. Delete Tool
    del_resp = client.delete(f"/v1/tools/{tool_id}", headers={"X-Client-ID": "test_corp"})
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


def test_agent_permissions_crud_lifecycle():
    """Test setting, reading, and deleting agent tool permissions."""
    agent_id = "test_ops_agent"
    perm_payload = {
        "allowed_tools": ["search_orders", "read_file", "ping_service"],
        "denied_tools": ["delete_file", "drop_db"],
        "description": "Test operations agent role",
    }

    # 1. Set Permissions
    resp = client.post(f"/v1/agents/{agent_id}/permissions", json=perm_payload, headers={"X-Client-ID": "test_corp"})
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == agent_id
    assert "ping_service" in resp.json()["allowed_tools"]

    # 2. Get Permissions
    get_resp = client.get(f"/v1/agents/{agent_id}/permissions", headers={"X-Client-ID": "test_corp"})
    assert get_resp.status_code == 200
    assert get_resp.json()["allowed_tools"] == ["search_orders", "read_file", "ping_service"]

    # 3. Delete Permissions
    del_resp = client.delete(f"/v1/agents/{agent_id}/permissions", headers={"X-Client-ID": "test_corp"})
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


def test_policy_template_application():
    """Verify applying a built-in policy template to an agent (ensuring PolicyAction import works)."""
    apply_payload = {
        "agent_id": "test_analyst_agent",
    }
    resp = client.post(
        "/v1/policy-templates/sql_analyst/apply",
        json=apply_payload,
        headers={"X-Client-ID": "test_corp"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "applied"
    assert data["agent_id"] == "test_analyst_agent"
    assert "sql_analyst" in data["template"]
    assert "permissions" in data


def test_declarative_policy_crud():
    """Test creating, fetching, and deleting a declarative AST policy document."""
    policy_payload = {
        "policy_id": "pol-test-geo-fence",
        "name": "Geographic Fencing Policy",
        "version": "1.0",
        "client_id": "test_corp",
        "scope": "organization",
        "origin": "CUSTOM",
        "description": "Restrict actions outside approved region",
        "rules": [
            {
                "rule_id": "rule-block-non-us",
                "description": "Block actions outside US",
                "match": {"tool": "transfer_funds"},
                "conditions": {
                    "all": [
                        {"field": "context.region", "operator": "not_equals", "value": "US"}
                    ]
                },
                "decision": "deny",
                "reason": "Fund transfers must originate from US region.",
            }
        ],
    }

    # 1. Create Policy
    create_resp = client.post("/v1/policies", json=policy_payload, headers={"X-Client-ID": "test_corp"})
    assert create_resp.status_code == 200, create_resp.text
    assert create_resp.json()["policy_id"] == "pol-test-geo-fence"

    # 2. Get Policy
    get_resp = client.get("/v1/policies/pol-test-geo-fence", headers={"X-Client-ID": "test_corp"})
    assert get_resp.status_code == 200
    assert len(get_resp.json()["rules"]) == 1

    # 3. List Policies
    list_resp = client.get("/v1/policies", headers={"X-Client-ID": "test_corp"})
    assert list_resp.status_code == 200
    p_ids = [p["policy_id"] for p in list_resp.json()]
    assert "pol-test-geo-fence" in p_ids

    # 4. Delete Policy
    del_resp = client.delete("/v1/policies/pol-test-geo-fence", headers={"X-Client-ID": "test_corp"})
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


def test_comprehensive_action_check_and_human_approval_lifecycle():
    """Test the complete 5-layer action check:
    1. High-value refund requires approval and generates approval token.
    2. Human supervisor approves the ticket.
    3. Resubmitting with the approval token results in ALLOW.
    4. Replaying the same approval token results in strict DENY (anti-replay).
    """
    client_id = "acme_fintech"
    agent_id = "support_agent_007"

    # Configure agent permissions first
    client.post(
        f"/v1/agents/{agent_id}/permissions",
        json={"allowed_tools": ["refund_payment", "search_orders"], "denied_tools": []},
        headers={"X-Client-ID": client_id},
    )

    action_payload = {
        "client_id": client_id,
        "agent_id": agent_id,
        "tool_name": "refund_payment",
        "arguments": {"order_id": "ORD-999", "amount": 1500.0, "currency": "USD"},
        "user": {"role": "customer"},
        "context": {"environment": "production"},
    }

    # Step 1: Check action -> must require approval (refund > $500 threshold)
    resp = client.post("/v1/actions/check", json=action_payload, headers={"X-Client-ID": client_id})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["decision"] == "REQUIRE_APPROVAL"
    assert data["allowed_to_execute"] is False
    assert data["approval_id"] is not None
    approval_id = data["approval_id"]

    # Step 2: Query pending approval
    appr_resp = client.get(f"/v1/approvals/{approval_id}", headers={"X-Client-ID": client_id})
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "pending"

    # Step 3: Human supervisor authorizes the ticket
    approve_resp = client.post(
        f"/v1/approvals/{approval_id}/approve",
        json={"approver_id": "supervisor_alice", "approver_role": "compliance_officer", "reason": "VIP verified"},
        headers={"X-Client-ID": client_id},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # Step 4: Re-evaluate action presenting the valid approval_id -> ALLOW
    action_with_approval = dict(action_payload)
    action_with_approval["approval_id"] = approval_id

    exec_resp = client.post("/v1/actions/check", json=action_with_approval, headers={"X-Client-ID": client_id})
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["decision"] == "ALLOW"
    assert exec_data["allowed_to_execute"] is True

    # Step 5: Anti-replay test: using the same approval token a second time must DENY
    replay_resp = client.post("/v1/actions/check", json=action_with_approval, headers={"X-Client-ID": client_id})
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["decision"] == "DENY"
    assert replay_data["allowed_to_execute"] is False
    assert any("replay" in r.lower() for r in replay_data["reasons"])


def test_audit_events_endpoint():
    """Verify querying structured audit events."""
    resp = client.get("/v1/audit/events?limit=10", headers={"X-Client-ID": "acme_fintech"})
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "count" in data
    assert isinstance(data["events"], list)
