from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CheckInputRequest(BaseModel):
    text: str = Field(..., description="User prompt or incoming input to inspect")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Context metadata such as application id, user id, or session id")
    policy_override: Optional[Dict[str, Any]] = Field(default=None, description="Optional per-request policy overrides")


class CheckOutputRequest(BaseModel):
    text: str = Field(..., description="LLM generated completion or output to inspect")
    evidence_context: Optional[List[str]] = Field(default=None, description="Retrieved evidence chunks or reference passages for factual grounding")
    evidence_sources: Optional[List[str]] = Field(default=None, description="Expected source identifiers or filenames")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Context metadata")
    policy_override: Optional[Dict[str, Any]] = Field(default=None, description="Optional per-request policy overrides")


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionProxyRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = "llama-3.3-70b-versatile"
    temperature: Optional[float] = 0.0
    evidence_context: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


# --- Action Permissions Models ---

class ActionArgumentConstraint(BaseModel):
    """Constraints placed on a specific tool argument."""
    allowed_prefixes: Optional[List[str]] = Field(default=None, description="Paths or strings must start with one of these prefixes")
    forbidden_keywords: Optional[List[str]] = Field(default=None, description="Keywords that must not appear in string arguments (case-insensitive)")
    forbidden_patterns: Optional[List[str]] = Field(default=None, description="Regex patterns that trigger a block if matched")
    allowed_values: Optional[List[Any]] = Field(default=None, description="Exact permitted values for the parameter")
    max_length: Optional[int] = Field(default=None, description="Maximum length of string argument")


class ActionPolicyConfig(BaseModel):
    """Configurable permission policy for tool execution."""
    description: Optional[str] = Field(default="", description="Human-readable policy description")
    allowed_tools: Optional[List[str]] = Field(default=None, description="List of permitted tool names. If None or contains '*', all non-denied tools are allowed.")
    denied_tools: Optional[List[str]] = Field(default_factory=list, description="Explicitly forbidden tools that are always blocked.")
    approval_required_tools: Optional[List[str]] = Field(default_factory=list, description="Tools requiring human-in-the-loop approval before execution.")
    argument_constraints: Optional[Dict[str, Dict[str, ActionArgumentConstraint]]] = Field(
        default_factory=dict,
        description="Tool-specific argument rules: tool_name -> arg_name -> constraint"
    )
    allow_unknown_tools: bool = Field(default=False, description="Whether tools not explicitly in allowed_tools are permitted")


class CheckActionRequest(BaseModel):
    """Request to inspect an agent's proposed tool action."""
    tool_name: str = Field(..., description="Name of the tool or action being invoked (e.g. 'read_file', 'sql_query')")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Dictionary of argument names and values passed to the tool")
    agent_id: Optional[str] = Field(default=None, description="Identifier of the calling agent (e.g. 'research_agent', 'support_bot')")
    client_id: Optional[str] = Field(default=None, description="Identifier of the client or tenant")
    policy_template: Optional[str] = Field(default=None, description="Pre-existing policy template to evaluate against (e.g. 'read_only_agent', 'sql_analyst')")
    custom_policy: Optional[ActionPolicyConfig] = Field(default=None, description="Custom inline policy or overrides to apply")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context metadata")


class CheckBatchActionsRequest(BaseModel):
    """Request to inspect multiple tool actions proposed in parallel."""
    actions: List[CheckActionRequest] = Field(..., description="List of proposed tool calls")
    policy_template: Optional[str] = Field(default=None, description="Default policy template for actions missing one")
    custom_policy: Optional[ActionPolicyConfig] = Field(default=None, description="Default custom policy for actions missing one")
    agent_id: Optional[str] = Field(default=None)
    client_id: Optional[str] = Field(default=None)
