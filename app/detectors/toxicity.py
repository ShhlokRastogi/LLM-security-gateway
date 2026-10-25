from __future__ import annotations

import re
from typing import List
from app.models.responses import DetectionItem


class ToxicityDetector:
    """Keyword and regex-based detector for hate speech, severe insults, and dangerous content."""

    TOXIC_PATTERNS = [
        (re.compile(r"(?i)\b(kill|murder|bomb|assassinate|slaughter)\s+(all|the|every)\b"), "threat_violence", 0.90),
        (re.compile(r"(?i)\bhow\s+to\s+(build|make|manufacture)\s+(a\s+bomb|explosives|bioweapon)\b"), "dangerous_content", 0.98),
        (re.compile(r"(?i)\b(suicide|self-harm)\s+instructions\b"), "self_harm", 0.95),
    ]

    def scan(self, text: str) -> List[DetectionItem]:
        detections: List[DetectionItem] = []
        for pattern, category, confidence in self.TOXIC_PATTERNS:
            match = pattern.search(text)
            if match:
                detections.append(DetectionItem(
                    type="toxicity",
                    category=category,
                    confidence=confidence,
                    details=f"Detected severe toxicity or harmful intent: '{match.group(0)}'"
                ))
        return detections
