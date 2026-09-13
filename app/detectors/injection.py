from __future__ import annotations

import html
import re
from typing import List, Tuple
from app.models.responses import DetectionItem


class InjectionDetector:
    """High-recall scanner for direct and indirect prompt injection, jailbreaks, and system prompt leakage."""

    INJECTION_PATTERNS = [
        # Instruction Overrides
        (re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)\b"), "instruction_override", 0.95),
        (re.compile(r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system|directives)\b"), "instruction_override", 0.95),
        (re.compile(r"(?i)\bforget\s+(everything|all\s+instructions)\b"), "instruction_override", 0.90),
        
        # System Prompt Leakage
        (re.compile(r"(?i)\b(reveal|output|print|show|repeat)\s+(?:the\s+|your\s+|all\s+)?(?:secret\s+)?(system\s+prompt|initial\s+instructions|system\s+message)\b"), "system_prompt_exfiltration", 0.92),
        (re.compile(r"(?i)\bwhat\s+(is|are)\s+your\s+(?:initial|secret|system|\s)+instructions\b"), "system_prompt_exfiltration", 0.90),

        # Jailbreaks & Persona Breaks
        (re.compile(r"(?i)\b(DAN|do\s+anything\s+now)\b"), "jailbreak_dan", 0.98),
        (re.compile(r"(?i)\bdeveloper\s+mode\s+(is\s+)?enabled\b"), "jailbreak_developer_mode", 0.95),
        (re.compile(r"(?i)\bpretend\s+you\s+have\s+no\s+(rules|restrictions|filters|guidelines)\b"), "jailbreak_unrestricted", 0.95),
        (re.compile(r"(?i)\byou\s+are\s+now\s+in\s+(maintenance|debug|unfiltered)\s+mode\b"), "jailbreak_mode", 0.95),
        (re.compile(r"(?i)\broleplay\s+as\s+(an\s+evil|an\s+unfiltered|a\s+malicious)\b"), "jailbreak_roleplay", 0.90),

        # Delimiter & Context Breakout
        (re.compile(r"(?i)(---|===|###)\s*(BEGIN|END)\s*(CONTEXT|SYSTEM|PROMPT|INSTRUCTIONS)"), "delimiter_breakout", 0.88),
        (re.compile(r"(?i)</?(system|context|instruction|untrusted_evidence)>"), "xml_tag_injection", 0.85),
    ]

    def scan(self, text: str) -> List[DetectionItem]:
        detections: List[DetectionItem] = []
        for pattern, category, confidence in self.INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_snippet = match.group(0)
                detections.append(
                    DetectionItem(
                        type="prompt_injection" if "jailbreak" not in category else "jailbreak",
                        category=category,
                        confidence=confidence,
                        details=f"Matched signature: '{matched_snippet}'",
                        metadata={"snippet": matched_snippet},
                    )
                )
        return detections

    def neutralize(self, text: str, replacement: str = "[FILTERED_INSTRUCTION]") -> Tuple[str, bool]:
        sanitized = text
        neutralized = False
        for pattern, _, _ in self.INJECTION_PATTERNS:
            if pattern.search(sanitized):
                sanitized = pattern.sub(replacement, sanitized)
                neutralized = True
        return sanitized, neutralized
