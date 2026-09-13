from __future__ import annotations

import re
from typing import List
from security_gateway.models import ThreatFinding, ThreatType


class ToxicityDetector:
    """Heuristic detector for dangerous, toxic, or exploit instructions in LLM responses."""

    HARMFUL_PATTERNS = [
        (re.compile(r"\b(?:here\s+is\s+how\s+to\s+build\s+a\s+bomb|synthesize\s+(?:ricin|sarin|anthrax))\b", re.I), "Weapons & Explosives Synthesis", "critical"),
        (re.compile(r"\b(?:create\s+ransomware|exploit\s+payload\s+script|zero-day\s+shellcode)\b", re.I), "Malware & Cyberattack Generation", "critical"),
    ]

    def scan(self, text: str) -> List[ThreatFinding]:
        findings = []
        for pat, desc, severity in self.HARMFUL_PATTERNS:
            m = pat.search(text)
            if m:
                findings.append(
                    ThreatFinding(
                        threat_type=ThreatType.TOXICITY,
                        severity=severity,
                        confidence=0.98,
                        description=desc,
                        matched_pattern=m.group(),
                        span=m.span(),
                    )
                )
        return findings
