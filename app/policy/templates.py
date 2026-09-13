from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional
import yaml
from app.models.requests import ActionArgumentConstraint, ActionPolicyConfig
from app.models.responses import PolicyTemplateInfo


BUILTIN_TEMPLATES: Dict[str, ActionPolicyConfig] = {
    "read_only_agent": ActionPolicyConfig(
        description="Restricts the agent strictly to non-mutating search and read tools. All writes, updates, deletions, and commands are blocked.",
        allowed_tools=[
            "web_search",
            "read_file",
            "search_kb",
            "search_documentation",
            "query_database",
            "get_weather",
            "list_directory",
            "list_dir",
            "inspect_element",
        ],
        denied_tools=[
            "write_file",
            "delete_file",
            "execute_command",
            "bash",
            "powershell",
            "execute_sql",
            "send_email",
            "create_user",
            "update_record",
            "delete_record",
        ],
        approval_required_tools=[],
        allow_unknown_tools=False,
    ),
    "sql_analyst": ActionPolicyConfig(
        description="Permits SQL database query execution while strictly prohibiting destructive DDL and DML statements (DROP, TRUNCATE, ALTER, DELETE, UPDATE, INSERT).",
        allowed_tools=[
            "sql_query",
            "run_sql",
            "explain_query",
            "describe_table",
            "list_tables",
            "get_schema",
            "read_file",
        ],
        denied_tools=[
            "execute_command",
            "bash",
            "powershell",
            "write_file",
            "delete_file",
            "send_email",
        ],
        approval_required_tools=[],
        allow_unknown_tools=False,
        argument_constraints={
            "sql_query": {
                "query": ActionArgumentConstraint(
                    forbidden_keywords=["DROP", "TRUNCATE", "ALTER", "DELETE", "UPDATE", "INSERT", "GRANT", "REVOKE"]
                )
            },
            "run_sql": {
                "query": ActionArgumentConstraint(
                    forbidden_keywords=["DROP", "TRUNCATE", "ALTER", "DELETE", "UPDATE", "INSERT", "GRANT", "REVOKE"]
                )
            },
        },
    ),
    "coding_agent_sandboxed": ActionPolicyConfig(
        description="Provides coding agent filesystem access confined to safe workspace directories and prevents path traversal (../) or dangerous system commands.",
        allowed_tools=[
            "read_file",
            "write_file",
            "list_dir",
            "run_linter",
            "run_tests",
            "search_code",
        ],
        denied_tools=[
            "sudo",
            "format_disk",
            "reboot",
            "shutdown",
            "drop_db",
        ],
        approval_required_tools=["run_tests"],
        allow_unknown_tools=False,
        argument_constraints={
            "read_file": {
                "path": ActionArgumentConstraint(
                    forbidden_patterns=[
                        r"(?:^|[\\/])\.\.(?:[\\/]|$)",
                        r"^[a-zA-Z]:\\(?:Windows|Program Files)",
                        r"^/(?:etc|root|var|boot|sys)",
                    ]
                )
            },
            "write_file": {
                "path": ActionArgumentConstraint(
                    forbidden_patterns=[
                        r"(?:^|[\\/])\.\.(?:[\\/]|$)",
                        r"^[a-zA-Z]:\\(?:Windows|Program Files)",
                        r"^/(?:etc|root|var|boot|sys)",
                    ]
                )
            },
        },
    ),
    "customer_support_agent": ActionPolicyConfig(
        description="Allows standard customer service lookups, but enforces human approval on state-altering or financial actions (refunds, external emails, password resets).",
        allowed_tools=[
            "lookup_customer",
            "get_order_status",
            "search_faq",
            "view_ticket",
            "draft_reply",
            "issue_refund",
            "send_email",
            "reset_password",
            "cancel_order",
        ],
        denied_tools=[
            "execute_command",
            "run_sql",
            "delete_customer",
            "drop_table",
        ],
        approval_required_tools=[
            "issue_refund",
            "send_email",
            "reset_password",
            "cancel_order",
        ],
        allow_unknown_tools=False,
    ),
    "full_access_supervised": ActionPolicyConfig(
        description="General tool access allowed, but any high-risk operating system or direct database administration commands mandate human authorization.",
        allowed_tools=["*"],
        denied_tools=[],
        approval_required_tools=[
            "execute_command",
            "bash",
            "powershell",
            "execute_sql",
            "delete_database",
            "deploy_production",
        ],
        allow_unknown_tools=True,
    ),
    "financial_agent": ActionPolicyConfig(
        description="Governs financial operations, transfers, and refunds with strict monetary limits and approval gates.",
        allowed_tools=[
            "search_orders",
            "get_customer",
            "refund_payment",
            "check_balance",
            "transfer_funds",
        ],
        denied_tools=[
            "execute_code",
            "delete_file",
            "query_database",
        ],
        approval_required_tools=["refund_payment", "transfer_funds"],
        allow_unknown_tools=False,
        argument_constraints={
            "refund_payment": {
                "amount": ActionArgumentConstraint(max_value=10000.0),
            }
        },
    ),
    "production_agent": ActionPolicyConfig(
        description="High-security production deployment agent with read access and mandatory supervisor oversight.",
        allowed_tools=[
            "search_orders",
            "get_customer",
            "read_file",
            "send_email",
        ],
        denied_tools=[
            "delete_file",
            "execute_code",
            "query_database",
            "sudo",
            "format_disk",
        ],
        approval_required_tools=["send_email"],
        allow_unknown_tools=False,
    ),
}


class PolicyTemplateRegistry:
    """Registry managing pre-existing, versioned, and custom action policy templates."""

    TEMPLATE_VERSIONS = {
        "read_only_agent": "1.0",
        "sql_analyst": "1.0",
        "coding_agent_sandboxed": "1.0",
        "customer_support_agent": "1.0",
        "financial_agent": "1.0",
        "production_agent": "1.0",
        "full_access_supervised": "1.0",
    }

    def __init__(self, templates_file: Optional[str] = None) -> None:
        self.templates: Dict[str, ActionPolicyConfig] = dict(BUILTIN_TEMPLATES)
        if templates_file:
            self.load_from_file(templates_file)
        else:
            default_path = Path("config/action_templates.yaml")
            if default_path.exists():
                self.load_from_file(str(default_path))

    def load_from_file(self, file_path: str) -> None:
        p = Path(file_path)
        if not p.exists():
            return
        try:
            content = p.read_text(encoding="utf-8")
            raw_data = yaml.safe_load(content)
            if raw_data and "templates" in raw_data:
                for name, t_data in raw_data["templates"].items():
                    constraints: Dict[str, Dict[str, ActionArgumentConstraint]] = {}
                    if "argument_constraints" in t_data:
                        for tool, arg_map in t_data["argument_constraints"].items():
                            constraints[tool] = {}
                            for arg, rule in arg_map.items():
                                constraints[tool][arg] = ActionArgumentConstraint(**rule)

                    self.templates[name] = ActionPolicyConfig(
                        description=t_data.get("description", ""),
                        allowed_tools=t_data.get("allowed_tools"),
                        denied_tools=t_data.get("denied_tools", []),
                        approval_required_tools=t_data.get("approval_required_tools", []),
                        allow_unknown_tools=t_data.get("allow_unknown_tools", False),
                        argument_constraints=constraints,
                    )
        except Exception:
            pass

    def get(self, name: str) -> Optional[ActionPolicyConfig]:
        # Handle versioned name syntax: e.g. "sql_analyst@1.0" or "sql_analyst"
        base_name = name.split("@")[0] if "@" in name else name
        return self.templates.get(base_name)

    def get_version(self, name: str) -> str:
        base_name = name.split("@")[0] if "@" in name else name
        if "@" in name:
            return name.split("@")[1]
        return self.TEMPLATE_VERSIONS.get(base_name, "1.0")

    def list(self) -> Dict[str, ActionPolicyConfig]:
        return dict(self.templates)

    def get_template_info_list(self) -> List[PolicyTemplateInfo]:
        infos = []
        for name, cfg in self.templates.items():
            version = self.TEMPLATE_VERSIONS.get(name, "1.0")
            infos.append(
                PolicyTemplateInfo(
                    name=name,
                    version=version,
                    description=cfg.description or "",
                    allowed_tools=cfg.allowed_tools,
                    denied_tools=cfg.denied_tools or [],
                    approval_required_tools=cfg.approval_required_tools or [],
                    has_argument_constraints=bool(cfg.argument_constraints),
                )
            )
        return infos


default_template_registry = PolicyTemplateRegistry()

__all__ = ["PolicyTemplateRegistry", "default_template_registry", "BUILTIN_TEMPLATES"]
