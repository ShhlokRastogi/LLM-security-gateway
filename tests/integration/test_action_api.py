import pytest
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_check_action_allowed(client):
    resp = client.post(
        "/v1/check/action",
        json={
            "tool_name": "web_search",
            "arguments": {"query": "PostgreSQL MVCC documentation"},
            "policy_template": "read_only_agent",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["risk_score"] == 0.0
    assert data["requires_approval"] is False


def test_api_check_action_blocked(client):
    resp = client.post(
        "/v1/check/action",
        json={
            "tool_name": "sql_query",
            "arguments": {"query": "DROP TABLE accounts;"},
            "policy_template": "sql_analyst",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "block"
    assert data["risk_score"] == 1.0
    assert len(data["violations"]) >= 1


def test_api_check_action_require_approval(client):
    resp = client.post(
        "/v1/check/action",
        json={
            "tool_name": "issue_refund",
            "arguments": {"order_id": "ORD-1234", "amount": 75.00},
            "policy_template": "customer_support_agent",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "require_approval"
    assert data["requires_approval"] is True


def test_api_check_batch_actions(client):
    resp = client.post(
        "/v1/check/actions",
        json={
            "actions": [
                {"tool_name": "lookup_customer", "arguments": {"id": "100"}},
                {"tool_name": "issue_refund", "arguments": {"order_id": "100"}},
            ],
            "policy_template": "customer_support_agent",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_decision"] == "require_approval"
    assert len(data["decisions"]) == 2


def test_api_list_policy_templates(client):
    resp = client.get("/v1/policies/templates")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 5
    template_names = [t["name"] for t in data["templates"]]
    assert "read_only_agent" in template_names
    assert "sql_analyst" in template_names
    assert "coding_agent_sandboxed" in template_names
    assert "customer_support_agent" in template_names
    assert "full_access_supervised" in template_names


def test_api_get_specific_template(client):
    # Valid template
    resp = client.get("/v1/policies/templates/sql_analyst")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "sql_analyst"
    assert "sql_query" in data["allowed_tools"]
    assert "execute_command" in data["denied_tools"]

    # Invalid template
    resp_404 = client.get("/v1/policies/templates/non_existent_role")
    assert resp_404.status_code == 404
