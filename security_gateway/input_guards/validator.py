from __future__ import annotations

from typing import List
from security_gateway.models import ThreatFinding, ThreatType


class InputValidator:
    """Validates structural bounds such as length and character limits."""

    def __init__(self, max_length: int = 32000) -> None:
        self.max_length = max_length

    def validate(self, text: str) -> List[ThreatFinding]:
        findings = []
        if len(text) > self.max_length:
            findings.append(
                ThreatFinding(
                    threat_type=ThreatType.LENGTH_VIOLATION,
                    severity="high",
                    confidence=1.0,
                    description=f"Input length {len(text)} exceeds maximum allowed limit {self.max_length}",
                    span=(0, len(text)),
                )
            )
        return findings
