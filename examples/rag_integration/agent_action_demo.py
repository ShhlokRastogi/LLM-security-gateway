from __future__ import annotations

import sys
from pathlib import Path

# Add current dir to sys.path for local imports
sys.path.insert(0, str(Path(__file__).parent))
from client import SecurityGatewayClient


def run_agent_action_demo():
    client = SecurityGatewayClient(base_url="http://localhost:8000")

    print("=" * 80)
    print("ACTION PERMISSIONS & POLICY TEMPLATES DEMONSTRATION")
    print("=" * 80)

    # 0. Discovery: List available templates
    print("\n[Step 0] Querying Policy Templates Discovery API...")
    templates = client.get_policy_templates()
    print(f" -> Found {len(templates)} pre-existing policy templates:")
    for t in templates:
        print(f"    * {t['name']:<25} : {t['description'][:65]}...")

    # 1. Flow 1: Read-Only Research Agent
    print("\n" + "-" * 80)
    print("[Flow 1] Research Agent (Role Template: 'read_only_agent')")
    
    # Allowed read
    res1 = client.check_action(
        tool_name="read_file",
        arguments={"path": "docs/architecture.md"},
        policy_template="read_only_agent",
    )
    print(f" 1.1 Action: read_file('docs/architecture.md') -> Decision: {res1['decision'].upper()}")

    # Blocked write
    res2 = client.check_action(
        tool_name="delete_file",
        arguments={"path": "docs/architecture.md"},
        policy_template="read_only_agent",
    )
    print(f" 1.2 Action: delete_file('docs/architecture.md') -> Decision: {res2['decision'].upper()}")
    print(f"     Reason: {res2['reasons']}")

    # 2. Flow 2: SQL Analyst with DDL Guard
    print("\n" + "-" * 80)
    print("[Flow 2] SQL Data Analyst (Role Template: 'sql_analyst')")

    # Safe SELECT
    res3 = client.check_action(
        tool_name="sql_query",
        arguments={"query": "SELECT customer_id, balance FROM accounts WHERE balance > 1000;"},
        policy_template="sql_analyst",
    )
    print(f" 2.1 Action: sql_query(SELECT ...) -> Decision: {res3['decision'].upper()}")

    # Malicious DROP TABLE
    res4 = client.check_action(
        tool_name="sql_query",
        arguments={"query": "DROP TABLE accounts;"},
        policy_template="sql_analyst",
    )
    print(f" 2.2 Action: sql_query('DROP TABLE accounts;') -> Decision: {res4['decision'].upper()}")
    print(f"     Reason: {res4['reasons']}")

    # 3. Flow 3: Customer Support Agent with Human-In-The-Loop Approval
    print("\n" + "-" * 80)
    print("[Flow 3] Customer Support Agent (Role Template: 'customer_support_agent')")

    # Safe lookup
    res5 = client.check_action(
        tool_name="lookup_customer",
        arguments={"email": "sarah.connor@sky.net"},
        policy_template="customer_support_agent",
    )
    print(f" 3.1 Action: lookup_customer(...) -> Decision: {res5['decision'].upper()}")

    # Sensitive Refund Action
    res6 = client.check_action(
        tool_name="issue_refund",
        arguments={"order_id": "ORD-5542", "amount": 299.00},
        policy_template="customer_support_agent",
    )
    print(f" 3.2 Action: issue_refund($299.00) -> Decision: {res6['decision'].upper()}")
    print(f"     Requires Human Approval: {res6['requires_approval']} ({res6['reasons'][0]})")

    # 4. Flow 4: Custom Client Policy (Custom Allowed Currencies & Scopes)
    print("\n" + "-" * 80)
    print("[Flow 4] Fintech Client with Custom Inline Policy")

    custom_policy = {
        "description": "Strict compliance wire transfer policy",
        "allowed_tools": ["initiate_wire", "check_balance"],
        "denied_tools": ["crypto_swap"],
        "approval_required_tools": ["initiate_wire"],
        "argument_constraints": {
            "initiate_wire": {
                "currency": {"allowed_values": ["USD", "EUR", "GBP"]},
            }
        },
    }

    # Allowed but requires approval
    res7 = client.check_action(
        tool_name="initiate_wire",
        arguments={"recipient": "Vendor Corp", "amount": 10000, "currency": "USD"},
        custom_policy=custom_policy,
    )
    print(f" 4.1 Action: initiate_wire(currency='USD') -> Decision: {res7['decision'].upper()}")

    # Disallowed currency
    res8 = client.check_action(
        tool_name="initiate_wire",
        arguments={"recipient": "Crypto Casino", "amount": 10000, "currency": "DOGE"},
        custom_policy=custom_policy,
    )
    print(f" 4.2 Action: initiate_wire(currency='DOGE') -> Decision: {res8['decision'].upper()}")
    print(f"     Reason: {res8['reasons']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_agent_action_demo()
