from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolRiskCategory(str, Enum):
    READ_ONLY = "read_only"
    DATA_MUTATION = "data_mutation"
    SYSTEM_COMMAND = "system_command"
    FINANCIAL = "financial"
    PRIVILEGED = "privileged"
    EXTERNAL_COMMUNICATION = "external_communication"
    GENERAL = "general"


class ArgumentType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class ToolParameterSchema(BaseModel):
    name: str = Field(..., description="Parameter name")
    type: ArgumentType = Field(default=ArgumentType.STRING, description="Expected parameter data type")
    description: Optional[str] = Field(default="", description="Description of the parameter")
    required: bool = Field(default=True, description="Whether this argument is required")
    allowed_values: Optional[List[Any]] = Field(default=None, description="Enumerated permitted values")
    min_value: Optional[float] = Field(default=None, description="Minimum numeric value or length")
    max_value: Optional[float] = Field(default=None, description="Maximum numeric value")
    max_length: Optional[int] = Field(default=None, description="Maximum string length")
    regex_pattern: Optional[str] = Field(default=None, description="Regex pattern the argument must match")
    forbidden_keywords: Optional[List[str]] = Field(default=None, description="Keywords that must not appear in string arguments")
    forbidden_patterns: Optional[List[str]] = Field(default=None, description="Regex patterns that trigger rejection")


class ToolDefinition(BaseModel):
    tool_id: str = Field(..., description="Unique tool identifier")
    tool_name: str = Field(..., description="Human-readable tool/action name (e.g. refund_payment)")
    description: str = Field(default="", description="Description of what the tool accomplishes")
    client_id: str = Field(default="default", description="Tenant/client that owns this tool")
    parameters: Dict[str, ToolParameterSchema] = Field(default_factory=dict, description="Parameter schemas")
    risk_category: ToolRiskCategory = Field(default=ToolRiskCategory.GENERAL, description="Inherent risk classification")
    is_enabled: bool = Field(default=True, description="Whether tool can currently be called")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")


class ToolRegistrationRequest(BaseModel):
    tool_name: str
    description: Optional[str] = ""
    client_id: Optional[str] = "default"
    parameters: Optional[Dict[str, ToolParameterSchema]] = Field(default_factory=dict)
    risk_category: Optional[ToolRiskCategory] = ToolRiskCategory.GENERAL
    is_enabled: Optional[bool] = True
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ToolUpdateRequest(BaseModel):
    description: Optional[str] = None
    parameters: Optional[Dict[str, ToolParameterSchema]] = None
    risk_category: Optional[ToolRiskCategory] = None
    is_enabled: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class ArgumentValidationError(BaseModel):
    parameter: str
    rule: str
    message: str
    provided_value: Optional[Any] = None
