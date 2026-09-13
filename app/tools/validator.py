from __future__ import annotations

import re
from typing import Any, Dict, List
from app.tools.models import ArgumentType, ArgumentValidationError, ToolDefinition, ToolParameterSchema


class ArgumentValidator:
    """Validates action arguments against registered tool schemas and security constraints."""

    PATH_TRAVERSAL_REGEX = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)", re.IGNORECASE)
    DANGEROUS_COMMANDS = [
        re.compile(r"\brm\s+-(?:r[fF]|f[rR])\b", re.IGNORECASE),
        re.compile(r"\b(?:sudo|mkfs|format|fdisk|dd\s+if=)\b", re.IGNORECASE),
        re.compile(r"\bcurl\s+[^|]+\|\s*(?:ba|z)?sh\b", re.IGNORECASE),
        re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    ]

    def validate(self, tool: ToolDefinition, arguments: Dict[str, Any]) -> List[ArgumentValidationError]:
        errors: List[ArgumentValidationError] = []
        args = arguments or {}

        # 1. Check required parameters
        for p_name, p_schema in tool.parameters.items():
            if p_schema.required and p_name not in args:
                errors.append(
                    ArgumentValidationError(
                        parameter=p_name,
                        rule="required",
                        message=f"Required parameter '{p_name}' is missing.",
                    )
                )

        # 2. Check each provided argument
        for p_name, val in args.items():
            schema = tool.parameters.get(p_name)
            if not schema:
                # Argument not defined in schema: check universal security heuristics
                self._check_universal_security(p_name, val, errors)
                continue

            # Type Validation
            if not self._check_type(val, schema.type):
                errors.append(
                    ArgumentValidationError(
                        parameter=p_name,
                        rule="type_mismatch",
                        message=f"Parameter '{p_name}' expected type '{schema.type.value}', got '{type(val).__name__}'.",
                        provided_value=val,
                    )
                )
                continue

            # Allowed Values
            if schema.allowed_values is not None and val not in schema.allowed_values:
                errors.append(
                    ArgumentValidationError(
                        parameter=p_name,
                        rule="allowed_values",
                        message=f"Value for '{p_name}' must be one of {schema.allowed_values}.",
                        provided_value=val,
                    )
                )

            # Numeric Checks (min/max)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                if schema.min_value is not None and val < schema.min_value:
                    errors.append(
                        ArgumentValidationError(
                            parameter=p_name,
                            rule="min_value",
                            message=f"Parameter '{p_name}' ({val}) is below minimum allowed value ({schema.min_value}).",
                            provided_value=val,
                        )
                    )
                if schema.max_value is not None and val > schema.max_value:
                    errors.append(
                        ArgumentValidationError(
                            parameter=p_name,
                            rule="max_value",
                            message=f"Parameter '{p_name}' ({val}) exceeds maximum allowed value ({schema.max_value}).",
                            provided_value=val,
                        )
                    )

            # String Checks
            if isinstance(val, str):
                if schema.max_length is not None and len(val) > schema.max_length:
                    errors.append(
                        ArgumentValidationError(
                            parameter=p_name,
                            rule="max_length",
                            message=f"Parameter '{p_name}' length ({len(val)}) exceeds maximum permitted length ({schema.max_length}).",
                            provided_value=val,
                        )
                    )

                if schema.regex_pattern:
                    if not re.search(schema.regex_pattern, val):
                        errors.append(
                            ArgumentValidationError(
                                parameter=p_name,
                                rule="regex_pattern",
                                message=f"Parameter '{p_name}' does not match required format pattern.",
                                provided_value=val,
                            )
                        )

                if schema.forbidden_keywords:
                    val_upper = val.upper()
                    for kw in schema.forbidden_keywords:
                        if re.search(rf"\b{re.escape(kw.upper())}\b", val_upper):
                            errors.append(
                                ArgumentValidationError(
                                    parameter=p_name,
                                    rule="forbidden_keyword",
                                    message=f"Parameter '{p_name}' contains prohibited keyword '{kw}'.",
                                    provided_value=val,
                                )
                            )
                            break

                if schema.forbidden_patterns:
                    for pat in schema.forbidden_patterns:
                        if re.search(pat, val):
                            errors.append(
                                ArgumentValidationError(
                                    parameter=p_name,
                                    rule="forbidden_pattern",
                                    message=f"Parameter '{p_name}' matches prohibited pattern '{pat}'.",
                                    provided_value=val,
                                )
                            )
                            break

            # Universal security checks
            self._check_universal_security(p_name, val, errors)

        return errors

    def _check_type(self, val: Any, expected: ArgumentType) -> bool:
        if val is None:
            return True
        if expected == ArgumentType.STRING:
            return isinstance(val, str)
        if expected == ArgumentType.INTEGER:
            return isinstance(val, int) and not isinstance(val, bool)
        if expected == ArgumentType.FLOAT:
            return isinstance(val, (int, float)) and not isinstance(val, bool)
        if expected == ArgumentType.BOOLEAN:
            return isinstance(val, bool)
        if expected == ArgumentType.ARRAY:
            return isinstance(val, list)
        if expected == ArgumentType.OBJECT:
            return isinstance(val, dict)
        return True

    def _check_universal_security(self, param_name: str, val: Any, errors: List[ArgumentValidationError]) -> None:
        if not isinstance(val, str):
            return

        # Path traversal guard
        if any(k in param_name.lower() for k in ["path", "file", "dir", "dest", "target"]):
            if self.PATH_TRAVERSAL_REGEX.search(val):
                errors.append(
                    ArgumentValidationError(
                        parameter=param_name,
                        rule="path_traversal",
                        message=f"Path traversal sequence ('..') detected in parameter '{param_name}'.",
                        provided_value=val,
                    )
                )

        # Shell command guard
        if any(k in param_name.lower() for k in ["command", "cmd", "exec", "script", "code"]):
            for d_regex in self.DANGEROUS_COMMANDS:
                if d_regex.search(val):
                    errors.append(
                        ArgumentValidationError(
                            parameter=param_name,
                            rule="dangerous_command",
                            message=f"Dangerous shell command signature detected in parameter '{param_name}'.",
                            provided_value=val,
                        )
                    )
                    break


default_argument_validator = ArgumentValidator()

__all__ = ["ArgumentValidator", "default_argument_validator"]
