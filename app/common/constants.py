from __future__ import annotations

import re
from typing import List, Pattern, Tuple

# Path Traversal Heuristic
PATH_TRAVERSAL_REGEX: Pattern[str] = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)", re.IGNORECASE)

# Dangerous OS / Shell Commands
DANGEROUS_SHELL_COMMANDS: List[Pattern[str]] = [
    re.compile(r"\brm\s+-(?:r[fF]|f[rR])\b", re.IGNORECASE),
    re.compile(r"\b(?:sudo|mkfs|format|fdisk|dd\s+if=)\b", re.IGNORECASE),
    re.compile(r"\bcurl\s+[^|]+\|\s*(?:ba|z)?sh\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
]

# Destructive SQL & System Action Keywords
DESTRUCTIVE_KEYWORDS: List[str] = [
    "DROP", "TRUNCATE", "DELETE", "PURGE", "DESTROY", "FORMAT", "RM -RF", "SHUTDOWN", "KILL", "DROP_DATABASE"
]

# Sensitive Parameter Inspection Keywords
PATH_PARAM_KEYWORDS: Tuple[str, ...] = ("path", "file", "dir", "dest", "target")
SHELL_PARAM_KEYWORDS: Tuple[str, ...] = ("command", "cmd", "exec", "script", "code")

# PII Scrubber Regex Patterns for Audit Logs
DEFAULT_AUDIT_PII_SCRUBBERS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED_CARD]"),
]
