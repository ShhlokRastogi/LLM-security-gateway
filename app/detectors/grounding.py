from __future__ import annotations

from pathlib import Path
import re
from typing import List, Optional, Set
from app.models.responses import DetectionItem


class GroundingDetector:
    """Model-agnostic factual grounding verification and citation provenance auditor."""

    STOPWORDS = {
        "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "with", "is",
        "was", "are", "were", "by", "from", "that", "this", "it", "its", "of", "as"
    }

    def __init__(self, min_claim_overlap: float = 0.50) -> None:
        self.min_claim_overlap = min_claim_overlap

    def verify(
        self,
        text: str,
        evidence_context: Optional[List[str]] = None,
        evidence_sources: Optional[List[str]] = None,
    ) -> List[DetectionItem]:
        detections: List[DetectionItem] = []

        if not text.strip():
            return detections

        # If no evidence context was supplied, we cannot verify grounding
        if evidence_context is None:
            return detections

        # If evidence context is empty, all claims are ungrounded
        if not evidence_context:
            detections.append(DetectionItem(
                type="grounding",
                category="hallucination",
                confidence=1.0,
                details="Output claims presented with zero supporting evidence context."
            ))
            return detections

        normalized_corpus = " ".join(evidence_context).lower().replace("_", " ")

        # 1. Audit citations
        citations = re.findall(r"\[Source:\s*([^,\]]+)(?:,\s*p\.(\d+))?\]", text)
        if citations and evidence_sources is not None:
            norm_allowed = {Path(s).name.lower() for s in evidence_sources}
            norm_stems = {Path(s).stem.lower() for s in evidence_sources}
            for source_name, _ in citations:
                src_clean = source_name.strip().lower()
                src_stem = Path(src_clean).stem
                if src_clean not in norm_allowed and src_stem not in norm_stems:
                    detections.append(DetectionItem(
                        type="grounding",
                        category="citation_hallucination",
                        confidence=0.90,
                        details=f"Hallucinated citation source '{source_name}' not present in retrieved context."
                    ))

        # 2. Claim overlap check
        claims = [c.strip() for c in re.split(r"(?<=[.!?])\s+", text) if len(c.strip()) > 15]
        unsupported_claims: List[str] = []

        for claim in claims:
            # Clean claim of citations
            clean_claim = re.sub(r"\[Source:[^\]]+\]", "", claim).strip()
            all_words = set(re.findall(r"\b[a-zA-Z0-9]{2,}\b", clean_claim.lower()))
            content_words = {w for w in all_words if w not in self.STOPWORDS}
            if not content_words:
                continue
            matched_words = {w for w in content_words if w in normalized_corpus}
            overlap = len(matched_words) / len(content_words)
            if overlap < self.min_claim_overlap:
                unsupported_claims.append(clean_claim)

        if unsupported_claims:
            overlap_ratio = len(unsupported_claims) / max(len(claims), 1)
            confidence = min(1.0, 0.5 + 0.5 * overlap_ratio)
            detections.append(DetectionItem(
                type="grounding",
                category="hallucination",
                confidence=round(confidence, 2),
                details=f"{len(unsupported_claims)} unsupported claim(s) detected.",
                metadata={"unsupported_claims": unsupported_claims[:3]}
            ))

        return detections
