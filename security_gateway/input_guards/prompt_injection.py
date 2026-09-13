from typing import List, NamedTuple, Tuple
from app.detectors.injection import InjectionDetector


class PromptInjectionFinding(NamedTuple):
    matched_pattern: str
    confidence: float
    category: str


class PromptInjectionDetector(InjectionDetector):
    def scan(self, text: str) -> List[PromptInjectionFinding]:
        detections = super().scan(text)
        return [
            PromptInjectionFinding(
                matched_pattern=d.details or d.category,
                confidence=d.confidence,
                category=d.category,
            )
            for d in detections
        ]

    def neutralize(
        self,
        text: str,
        replacement: str = "[UNTRUSTED_INSTRUCTION_NEUTRALIZED]",
    ) -> Tuple[str, bool]:
        return super().neutralize(text, replacement=replacement)


__all__ = ["PromptInjectionDetector", "PromptInjectionFinding"]
