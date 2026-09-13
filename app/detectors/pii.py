from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from app.models.responses import DetectionItem


def is_luhn_valid(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", card_number)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIDetector:
    """Mathematics-safe, high-precision PII detection and redaction engine."""

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    PHONE_PATTERN = re.compile(
        r"(?:\b|\+)(?:\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
    )
    SSN_PATTERN = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )
    API_KEY_PATTERNS = [
        (re.compile(r"\b(?:gsk|sk)_[a-zA-Z0-9]{24,}\b"), "api_key"),
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"), "github_token"),
        (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key"),
        (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{24,}\b"), "bearer_token"),
    ]
    CARD_CANDIDATE_PATTERN = re.compile(
        r"\b(?:\d[ -]?){13,19}\b"
    )

    def detect_and_redact(self, text: str) -> Tuple[str, List[DetectionItem]]:
        detections: List[DetectionItem] = []
        sanitized = text

        # 1. API Keys
        for pattern, key_type in self.API_KEY_PATTERNS:
            matches = list(pattern.finditer(sanitized))
            for match in reversed(matches):
                val = match.group(0)
                sanitized = sanitized[:match.start()] + "[REDACTED_KEY]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="api_key",
                    confidence=1.0,
                    details=f"Detected {key_type}",
                    metadata={"redaction": "[REDACTED_KEY]"}
                ))

        # 2. Credit Cards with Luhn Checksum
        card_matches = list(self.CARD_CANDIDATE_PATTERN.finditer(sanitized))
        for match in reversed(card_matches):
            raw = match.group(0)
            digits_only = re.sub(r"\D", "", raw)
            if is_luhn_valid(digits_only):
                sanitized = sanitized[:match.start()] + "[REDACTED_CARD]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="credit_card",
                    confidence=1.0,
                    details="Valid Luhn credit card number detected",
                    metadata={"redaction": "[REDACTED_CARD]"}
                ))

        # 3. Emails
        email_matches = list(self.EMAIL_PATTERN.finditer(sanitized))
        for match in reversed(email_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_EMAIL]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="email",
                confidence=1.0,
                details="Email address detected",
                metadata={"redaction": "[REDACTED_EMAIL]"}
            ))

        # 4. SSNs
        ssn_matches = list(self.SSN_PATTERN.finditer(sanitized))
        for match in reversed(ssn_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_SSN]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="ssn",
                confidence=1.0,
                details="Social Security Number detected",
                metadata={"redaction": "[REDACTED_SSN]"}
            ))

        # 5. Phones
        phone_matches = list(self.PHONE_PATTERN.finditer(sanitized))
        for match in reversed(phone_matches):
            raw = match.group(0)
            if "." in raw and not any(sep in raw for sep in ["-", "(", ")", "+", " "]):
                continue
            sanitized = sanitized[:match.start()] + "[REDACTED_PHONE]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="phone",
                confidence=0.95,
                details="Phone number detected",
                metadata={"redaction": "[REDACTED_PHONE]"}
            ))

        return sanitized, detections
