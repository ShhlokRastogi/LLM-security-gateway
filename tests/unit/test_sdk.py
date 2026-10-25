from __future__ import annotations

import pytest
from sdk.client import (
    ActionDecisionResult,
    InspectionDecisionResult,
    SecurityGateway,
)
from sdk.exceptions import ApprovalRequiredError, SecurityDenialError


def test_action_decision_result_helpers():
    allowed_raw = {
        "decision": "ALLOW",
        "allowed_to_execute": True,
        "tool_name": "read_file",
        "arguments": {"path": "safe.txt"},
        "risk": {"risk_level": "LOW", "risk_score": 0.05},
        "reasons": ["Action permitted"],
    }
    res = ActionDecisionResult(allowed_raw)
    assert res.is_allowed() is True
    assert res.is_denied() is False
    assert res.requires_approval() is False
    assert res.decision == "ALLOW"
    assert res["tool_name"] == "read_file"
    assert "risk" in res

    deny_raw = {
        "decision": "DENY",
        "allowed_to_execute": False,
        "tool_name": "format_disk",
        "reasons": ["Forbidden tool"],
    }
    deny_res = ActionDecisionResult(deny_raw)
    assert deny_res.is_denied() is True
    assert deny_res.is_allowed() is False

    appr_raw = {
        "decision": "REQUIRE_APPROVAL",
        "allowed_to_execute": False,
        "tool_name": "refund_payment",
        "approval_id": "appr-12345",
    }
    appr_res = ActionDecisionResult(appr_raw)
    assert appr_res.requires_approval() is True
    assert appr_res.approval_id == "appr-12345"


def test_inspection_decision_result_helpers():
    allow_raw = {
        "decision": "allow",
        "risk_score": 0.0,
        "text": "Hello world",
        "detections": [],
    }
    res = InspectionDecisionResult(allow_raw)
    assert res.is_allowed is True
    assert res.is_blocked is False
    assert res.text == "Hello world"
    assert res["decision"] == "allow"

    block_raw = {
        "decision": "block",
        "risk_score": 0.95,
        "text": "[BLOCKED BY SECURITY POLICY]",
    }
    block_res = InspectionDecisionResult(block_raw)
    assert block_res.is_blocked is True
    assert block_res.is_allowed is False


def test_sdk_secure_execute_direct_invocation(monkeypatch):
    """Test direct secure_execute calling pattern."""
    gateway = SecurityGateway(base_url="http://mock-gateway", client_id="test_client")

    # Mock check_action to return ALLOW
    def mock_check_action_allow(*args, **kwargs):
        return ActionDecisionResult({
            "decision": "ALLOW",
            "allowed_to_execute": True,
            "tool_name": "multiply",
            "arguments": {"x": 3, "y": 4},
        })

    monkeypatch.setattr(gateway, "check_action", mock_check_action_allow)

    def multiply(x: int, y: int) -> int:
        return x * y

    result = gateway.secure_execute(
        agent_id="test_bot",
        tool_name="multiply",
        arguments={"x": 3, "y": 4},
        tool_callable=multiply,
    )
    assert result == 12


def test_sdk_secure_execute_decorator(monkeypatch):
    """Test decorator usage @gateway.secure_execute(agent_id=...)."""
    gateway = SecurityGateway(base_url="http://mock-gateway", client_id="test_client")

    def mock_check_action_allow(*args, **kwargs):
        return ActionDecisionResult({
            "decision": "ALLOW",
            "allowed_to_execute": True,
            "tool_name": "add_numbers",
            "arguments": {"a": 10, "b": 20},
        })

    monkeypatch.setattr(gateway, "check_action", mock_check_action_allow)

    @gateway.secure_execute(agent_id="calculator_bot")
    def add_numbers(a: int, b: int) -> int:
        return a + b

    assert add_numbers(10, 20) == 30


def test_sdk_secure_execute_raises_security_denial(monkeypatch):
    """Test SecurityDenialError raised when action is blocked."""
    gateway = SecurityGateway(base_url="http://mock-gateway", client_id="test_client")

    def mock_check_action_deny(*args, **kwargs):
        return ActionDecisionResult({
            "decision": "DENY",
            "allowed_to_execute": False,
            "tool_name": "delete_all",
            "reasons": ["Destructive action prohibited"],
        })

    monkeypatch.setattr(gateway, "check_action", mock_check_action_deny)

    def delete_all():
        return "deleted"

    with pytest.raises(SecurityDenialError) as exc_info:
        gateway.secure_execute(
            agent_id="rogue_bot",
            tool_name="delete_all",
            arguments={},
            tool_callable=delete_all,
        )
    assert exc_info.value.tool_name == "delete_all"


def test_sdk_secure_execute_raises_approval_required(monkeypatch):
    """Test ApprovalRequiredError raised when human approval is required."""
    gateway = SecurityGateway(base_url="http://mock-gateway", client_id="test_client")

    def mock_check_action_appr(*args, **kwargs):
        return ActionDecisionResult({
            "decision": "REQUIRE_APPROVAL",
            "allowed_to_execute": False,
            "tool_name": "large_refund",
            "approval_id": "appr-9999",
            "reasons": ["Amount exceeds $500 limit"],
        })

    monkeypatch.setattr(gateway, "check_action", mock_check_action_appr)

    def large_refund(amount: float):
        return f"refunded {amount}"

    with pytest.raises(ApprovalRequiredError) as exc_info:
        gateway.secure_execute(
            agent_id="support_bot",
            tool_name="large_refund",
            arguments={"amount": 2000.0},
            tool_callable=large_refund,
        )
    assert exc_info.value.approval_id == "appr-9999"
