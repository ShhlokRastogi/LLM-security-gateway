from typing import Any, List, Optional
from app.detectors.grounding import GroundingDetector

class GroundingDecision:
    def __init__(
        self,
        action: str,
        status: str,
        unsupported_claims: List[str],
        safe_answer: str = "",
        is_refusal: bool = False,
        threats: Optional[List[Any]] = None,
    ):
        self.action = action
        self.status = status
        self.unsupported_claims = unsupported_claims
        self.safe_answer = safe_answer
        self.is_refusal = is_refusal
        self.threats = threats or []

    def __iter__(self):
        yield self.safe_answer
        yield self.threats
        yield self.is_refusal


class GroundingGuard(GroundingDetector):
    def verify(
        self,
        text: Optional[str] = None,
        evidence_context: Optional[List[str]] = None,
        evidence_sources: Optional[List[str]] = None,
        raw_answer: Optional[str] = None,
        evidence_corpus: Optional[List[str]] = None,
        **kwargs,
    ) -> GroundingDecision:
        active_text = raw_answer if raw_answer is not None else (text or "")
        active_evidence = evidence_corpus if evidence_corpus is not None else evidence_context

        detections = super().verify(active_text, active_evidence, evidence_sources)
        unsupported = []
        for d in detections:
            if "unsupported_claims" in (d.metadata or {}):
                unsupported.extend(d.metadata["unsupported_claims"])

        is_refusal = len(detections) > 0
        status = "ungrounded" if is_refusal else "grounded"
        safe_ans = (
            "Refused: The response contained unsupported claims not substantiated by the reference context."
            if is_refusal else active_text
        )

        return GroundingDecision(
            action="block" if is_refusal else "allow",
            status=status,
            unsupported_claims=unsupported,
            safe_answer=safe_ans,
            is_refusal=is_refusal,
            threats=detections,
        )

__all__ = ["GroundingGuard", "GroundingDecision"]
