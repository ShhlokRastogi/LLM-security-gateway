from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from sdk import ApprovalRequiredError, SecurityDenialError, SecurityGateway


# Mock Target Tool Implementations (Real business logic behind security boundary)
def search_orders(query: str, customer_id: str = None, limit: int = 10) -> list:
    print(f"   [TOOL EXECUTION] >>> search_orders executed: query='{query}', limit={limit}")
    return [{"order_id": "ORD-101", "item": "ThinkPad P1", "status": "shipped"}]


def refund_payment(order_id: str, amount: float, currency: str = "USD", reason: str = "") -> dict:
    print(f"   [TOOL EXECUTION] >>> refund_payment executed: order='{order_id}', amount=${amount:.2f} {currency}")
    return {"refund_id": "REF-8899", "status": "processed", "amount": amount}


def delete_database(database_name: str) -> dict:
    print(f"   [TOOL EXECUTION] >>> DANGER: delete_database executed on {database_name}!")
    return {"status": "dropped"}


def run_agentic_workflow_demo():
    print("=" * 80)
    print("AUTONOMOUS AGENT + SECURITY GATEWAY BOUNDARY DEMONSTRATION")
    print("=" * 80)

    gateway = SecurityGateway(base_url="http://localhost:8000", client_id="acme_corp")
    agent_id = "customer_support_agent"

    # Step 0: Register Agent Permissions
    print("\n[Step 0] Configuring Agent Role & Permissions on Security Gateway...")
    gateway.set_agent_permissions(
        agent_id=agent_id,
        allowed_tools=["search_orders", "get_customer", "refund_payment", "send_email"],
        denied_tools=["delete_database", "execute_code", "query_database"],
        description="Tier-1 Customer Support Bot",
    )
    print(f" -> Agent '{agent_id}' configured with strict action whitelist and explicit denylist.")

    # --------------------------------------------------------------------------
    # Flow 1: Safe Action
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Flow 1] Agent proposes safe action: search_orders(query='ThinkPad')")
    
    try:
        result = gateway.secure_execute(
            agent_id=agent_id,
            tool_name="search_orders",
            arguments={"query": "ThinkPad", "limit": 5},
            tool_callable=search_orders,
            context={"environment": "production"},
        )
        print(f" -> Gateway Decision: ALLOW")
        print(f" -> Tool Output Received: {result}")
    except SecurityDenialError as err:
        print(f" -> Gateway Decision: DENY ({err})")

    # --------------------------------------------------------------------------
    # Flow 2: Dangerous High-Value Action (Requires Human Approval)
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Flow 2] Agent proposes high-value financial action: refund_payment(amount=$10,000)")
    
    approval_token = None
    try:
        gateway.secure_execute(
            agent_id=agent_id,
            tool_name="refund_payment",
            arguments={"order_id": "ORD-101", "amount": 10000.0, "currency": "USD"},
            tool_callable=refund_payment,
            context={"environment": "production"},
        )
    except ApprovalRequiredError as err:
        print(f" -> Gateway Decision: REQUIRE_APPROVAL")
        print(f" -> Enforcement: Direct execution paused. Created Approval Request ID: {err.approval_id}")
        approval_token = err.approval_id

    if approval_token:
        # Simulate Human Supervisor Reviewing & Authorizing via Gateway API
        print(f"\n   [Human Supervisor Action] Supervisor Sarah logs into Security Dashboard...")
        print(f"   [Human Supervisor Action] Approving Request {approval_token} with reason: 'Verified VIP customer warranty claim'...")
        gateway.approve_action(
            approval_id=approval_token,
            approver_id="supervisor_sarah",
            approver_role="finance_lead",
            reason="Verified VIP customer warranty claim",
        )

        # Now Agent resumes execution presenting the cryptographically bound approval token
        print(f"\n -> Agent resumes execution with approval_id='{approval_token}'...")
        res = gateway.secure_execute(
            agent_id=agent_id,
            tool_name="refund_payment",
            arguments={"order_id": "ORD-101", "amount": 10000.0, "currency": "USD"},
            tool_callable=refund_payment,
            approval_id=approval_token,
            context={"environment": "production"},
        )
        print(f" -> Post-Approval Gateway Decision: ALLOW")
        print(f" -> Authorized Tool Execution Result: {res}")

        # Attempt Replay Attack (trying to use the same approval token again)
        print(f"\n   [Adversarial Replay Test] Attacker attempts to replay the same approval token for a second refund...")
        try:
            gateway.secure_execute(
                agent_id=agent_id,
                tool_name="refund_payment",
                arguments={"order_id": "ORD-101", "amount": 10000.0, "currency": "USD"},
                tool_callable=refund_payment,
                approval_id=approval_token,
                context={"environment": "production"},
            )
        except SecurityDenialError as replay_err:
            print(f" -> Gateway Replay Defense: BLOCKED! ({replay_err})")

    # --------------------------------------------------------------------------
    # Flow 3: Forbidden Destructive Action
    # --------------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[Flow 3] Compromised Agent attempts forbidden action: delete_database('prod_users')")
    try:
        gateway.secure_execute(
            agent_id=agent_id,
            tool_name="delete_database",
            arguments={"database_name": "prod_users"},
            tool_callable=delete_database,
            context={"environment": "production"},
        )
        print(" -> ERROR: Tool executed unexpectedly!")
    except SecurityDenialError as err:
        print(f" -> Gateway Decision: DENY")
        print(f" -> Enforcement: Execution strictly blocked before tool invoked.")
        print(f" -> Denial Reason: {err}")

    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE: All 3 security boundaries successfully enforced.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_agentic_workflow_demo()
