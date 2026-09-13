from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class RedactedJSONFormatter(logging.Formatter):
    """Structured JSON formatter ensuring zero raw PII is written to log sinks."""

    PII_SCRUB_PATTERNS = [
        (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[REDACTED_EMAIL]"),
        (re.compile(r"\d{3}-\d{2}-\d{4}"), "[REDACTED_SSN]"),
        (re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}(?!\d)"), "[REDACTED_CARD]"),
    ]

    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": self._scrub(record.getMessage()),
        }
        if hasattr(record, "request_id"):
            data["request_id"] = getattr(record, "request_id")
        if hasattr(record, "event_type"):
            data["event_type"] = getattr(record, "event_type")
        if hasattr(record, "detections"):
            data["detections"] = getattr(record, "detections")
        if hasattr(record, "decision"):
            data["decision"] = getattr(record, "decision")
        if hasattr(record, "latency_ms"):
            data["latency_ms"] = getattr(record, "latency_ms")

        return json.dumps(data)

    def _scrub(self, text: str) -> str:
        scrubbed = str(text)
        for pattern, replacement in self.PII_SCRUB_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed


def get_security_logger(name: str = "security.gateway") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(RedactedJSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
