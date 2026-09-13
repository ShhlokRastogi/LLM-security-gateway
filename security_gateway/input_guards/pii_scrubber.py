from __future__ import annotations

from typing import List, Tuple
from security_gateway.models import RedactionRecord, ThreatFinding, ThreatType
from security_gateway.sanitizers.pii_masker import PIIMasker


class InputPIIScrubber:
    """Detects and scrubs sensitive PII from incoming prompts before LLM forwarding."""

    def __init__(self, masker: PIIMasker) -> None:
        self.masker = masker

    def process(self, text: str) -> Tuple[str, List[ThreatFinding], List[RedactionRecord]]:
        """Scrub input text and return sanitized string with security findings and redaction records."""
        sanitized, raw_redactions = self.masker.mask_text(text, context_origin="input_prompt")

        threats = []
        redactions = []

        for r in raw_redactions:
            rec = RedactionRecord(
                entity_type=r["type"],
                masked_value=f"[REDACTED_{r['type']}]",
                original_snippet=r["match"],
                start=r.get("start"),
                end=r.get("end"),
            )
            redactions.append(rec)
            threats.append(
                ThreatFinding(
                    threat_type=ThreatType.PII_INPUT,
                    severity="medium",
                    confidence=1.0,
                    description=f"Detected sensitive {r['type']} in input prompt",
                    matched_pattern=r["match"],
                    span=(r.get("start", 0), r.get("end", 0)),
                )
            )

        return sanitized, threats, redactions
