import pytest
from app.models.requests import (
    ActionArgumentConstraint,
    ActionPolicyConfig,
    CheckActionRequest,
    CheckBatchActionsRequest,
)
from app.models.responses import ActionDecision
from app.policy.action_permissions import ActionPermissionsLayer


@pytest.fixture
def action_layer():
    return ActionPermissionsLayer()


def test_read_only_agent_allows_reading(action_layer):
    req = CheckActionRequest(
        tool_name="read_file",
        arguments={"path": "docs/architecture.md"},
        policy_template="read_only_agent",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.ALLOW
    assert decision.risk_score == 0.0
    assert len(decision.violations) == 0


def test_read_only_agent_blocks_mutating_and_command_tools(action_layer):
    # Prohibited write tool
    req1 = CheckActionRequest(
        tool_name="write_file",
        arguments={"path": "data.txt", "content": "malicious"},
        policy_template="read_only_agent",
    )
    dec1 = action_layer.evaluate_action(req1)
    assert dec1.decision == ActionDecision.BLOCK
    assert any("denied_tool" in v.rule for v in dec1.violations)

    # Prohibited shell command
    req2 = CheckActionRequest(
        tool_name="execute_command",
        arguments={"command": "ls -la"},
        policy_template="read_only_agent",
    )
    dec2 = action_layer.evaluate_action(req2)
    assert dec2.decision == ActionDecision.BLOCK


def test_sql_analyst_allows_read_only_select(action_layer):
    req = CheckActionRequest(
        tool_name="sql_query",
        arguments={"query": "SELECT user_id, email FROM users WHERE status = 'active' LIMIT 10;"},
        policy_template="sql_analyst",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.ALLOW
    assert decision.risk_score == 0.0


def test_sql_analyst_blocks_destructive_queries(action_layer):
    destructive_queries = [
        "DROP TABLE users;",
        "TRUNCATE accounts;",
        "DELETE FROM orders WHERE amount > 0;",
        "UPDATE settings SET debug = 1;",
        "ALTER TABLE users ADD COLUMN password_hash text;",
    ]
    for q in destructive_queries:
        req = CheckActionRequest(
            tool_name="sql_query",
            arguments={"query": q},
            policy_template="sql_analyst",
        )
        decision = action_layer.evaluate_action(req)
        assert decision.decision == ActionDecision.BLOCK
        assert any(v.rule == "forbidden_keyword" for v in decision.violations)


def test_coding_agent_blocks_path_traversal(action_layer):
    req = CheckActionRequest(
        tool_name="read_file",
        arguments={"path": "../../../etc/passwd"},
        policy_template="coding_agent_sandboxed",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.BLOCK
    assert any("path_traversal" in v.rule or "pattern_violation" in v.rule for v in decision.violations)


def test_coding_agent_blocks_dangerous_shell_commands(action_layer):
    req = CheckActionRequest(
        tool_name="run_tests",
        arguments={"command": "rm -rf /var/log"},
        policy_template="coding_agent_sandboxed",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.BLOCK
    assert any("dangerous_command" in v.rule for v in decision.violations)


def test_customer_support_requires_approval_for_refund(action_layer):
    req = CheckActionRequest(
        tool_name="issue_refund",
        arguments={"order_id": "ORD-9988", "amount": 150.00},
        policy_template="customer_support_agent",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.REQUIRE_APPROVAL
    assert decision.requires_approval is True
    assert decision.risk_score == 0.50


def test_customer_support_allows_benign_lookups(action_layer):
    req = CheckActionRequest(
        tool_name="lookup_customer",
        arguments={"email": "client@example.com"},
        policy_template="customer_support_agent",
    )
    decision = action_layer.evaluate_action(req)
    assert decision.decision == ActionDecision.ALLOW
    assert decision.requires_approval is False


def test_custom_inline_policy_overrides(action_layer):
    custom_policy = ActionPolicyConfig(
        description="Custom financial policy",
        allowed_tools=["transfer_funds", "view_balance"],
        denied_tools=["crypto_buy"],
        approval_required_tools=["transfer_funds"],
        argument_constraints={
            "transfer_funds": {
                "currency": ActionArgumentConstraint(allowed_values=["USD", "EUR"]),
            }
        },
    )

    # 1. Transfer funds in USD -> requires approval
    req1 = CheckActionRequest(
        tool_name="transfer_funds",
        arguments={"amount": 500, "currency": "USD"},
        custom_policy=custom_policy,
    )
    dec1 = action_layer.evaluate_action(req1)
    assert dec1.decision == ActionDecision.REQUIRE_APPROVAL

    # 2. Transfer funds with unapproved currency -> blocked
    req2 = CheckActionRequest(
        tool_name="transfer_funds",
        arguments={"amount": 500, "currency": "BTC"},
        custom_policy=custom_policy,
    )
    dec2 = action_layer.evaluate_action(req2)
    assert dec2.decision == ActionDecision.BLOCK
    assert any(v.rule == "value_not_allowed" for v in dec2.violations)


def test_batch_actions_evaluation(action_layer):
    req = CheckBatchActionsRequest(
        actions=[
            CheckActionRequest(tool_name="lookup_customer", arguments={"id": "123"}),
            CheckActionRequest(tool_name="issue_refund", arguments={"order_id": "123"}),
        ],
        policy_template="customer_support_agent",
    )
    batch_res = action_layer.evaluate_batch(req)
    assert len(batch_res.decisions) == 2
    assert batch_res.overall_decision == ActionDecision.REQUIRE_APPROVAL
    assert batch_res.requires_approval_count == 1
    assert batch_res.blocked_count == 0
