class SecurityGatewayError(Exception):
    """Base exception for Security Gateway operations."""
    pass


class SecurityDenialError(SecurityGatewayError):
    """Raised when an action or tool execution is prohibited by security policy."""
    def __init__(self, tool_name: str, reasons: list[str]):
        self.tool_name = tool_name
        self.reasons = reasons
        super().__init__(f"Action '{tool_name}' DENIED by Security Gateway: {'; '.join(reasons)}")


class ApprovalRequiredError(SecurityGatewayError):
    """Raised when an action cannot be executed automatically and requires human approval."""
    def __init__(self, tool_name: str, approval_id: str, reasons: list[str]):
        self.tool_name = tool_name
        self.approval_id = approval_id
        self.reasons = reasons
        super().__init__(f"Action '{tool_name}' requires human approval ({approval_id}): {'; '.join(reasons)}")
