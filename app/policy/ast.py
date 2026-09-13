from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


class ConditionEvaluator:
    """Safe, constrained AST condition evaluator supporting AND / OR / NOT and comparison operators.
    Guaranteed zero execution of arbitrary Python code."""

    @staticmethod
    def extract_field(context: Dict[str, Any], field_path: str) -> Any:
        parts = field_path.split(".")
        current = context
        for p in parts:
            if isinstance(current, dict):
                current = current.get(p)
            elif hasattr(current, p):
                current = getattr(current, p)
            else:
                return None
            if current is None:
                return None
        return current

    @classmethod
    def evaluate(cls, condition_tree: Optional[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        if not condition_tree:
            return True

        # 1. Logical AND ('all')
        if "all" in condition_tree:
            sub_conds = condition_tree["all"]
            if not isinstance(sub_conds, list):
                return False
            return all(cls.evaluate(c, context) for c in sub_conds)

        # 2. Logical OR ('any')
        if "any" in condition_tree:
            sub_conds = condition_tree["any"]
            if not isinstance(sub_conds, list):
                return False
            return any(cls.evaluate(c, context) for c in sub_conds)

        # 3. Logical NOT ('not')
        if "not" in condition_tree:
            sub_cond = condition_tree["not"]
            return not cls.evaluate(sub_cond, context)

        # 4. Atomic Condition: { field, operator, value }
        field_path = condition_tree.get("field")
        op = str(condition_tree.get("operator", "equals")).lower()
        expected = condition_tree.get("value")

        if not field_path:
            return True

        actual = cls.extract_field(context, field_path)
        return cls._compare(actual, op, expected)

    @classmethod
    def _compare(cls, actual: Any, op: str, expected: Any) -> bool:
        try:
            if op in ["equals", "eq", "=="]:
                return actual == expected
            if op in ["not_equals", "neq", "!="]:
                return actual != expected
            if op in ["greater_than", "gt", ">"]:
                return actual is not None and float(actual) > float(expected)
            if op in ["greater_than_or_equal", "gte", ">="]:
                return actual is not None and float(actual) >= float(expected)
            if op in ["less_than", "lt", "<"]:
                return actual is not None and float(actual) < float(expected)
            if op in ["less_than_or_equal", "lte", "<="]:
                return actual is not None and float(actual) <= float(expected)
            if op in ["in"]:
                if isinstance(expected, (list, tuple, set)):
                    return actual in expected
                return False
            if op in ["not_in"]:
                if isinstance(expected, (list, tuple, set)):
                    return actual not in expected
                return True
            if op in ["contains"]:
                if isinstance(actual, (list, tuple, set, str)) and expected is not None:
                    return expected in actual
                return False
            if op in ["matches_regex", "regex"]:
                if isinstance(actual, str) and isinstance(expected, str):
                    return bool(re.search(expected, actual, re.IGNORECASE))
                return False
            if op in ["exists"]:
                return (actual is not None) == bool(expected)
        except (ValueError, TypeError):
            return False

        return False


__all__ = ["ConditionEvaluator"]
