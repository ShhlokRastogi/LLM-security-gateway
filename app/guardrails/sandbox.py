from __future__ import annotations

import html
import re
from typing import Tuple


class ContextSandbox:
    """Sanitizes untrusted text and context boundaries to prevent delimiter breakout."""

    DELIMITER_CHARS = [("---", "-- -"), ("===", "== ="), ("###", "## #")]

    DELIMITER_BLOCK_PATTERN = re.compile(
        r"---\s*(?:BEGIN|END)\s+CONTEXT\s+BLOCK\s*---",
        re.IGNORECASE,
    )

    def sanitize_untrusted_text(self, text: str) -> Tuple[str, bool]:
        sanitized = text
        detected = False

        # 1. Delimiter block replacement
        if self.DELIMITER_BLOCK_PATTERN.search(sanitized):
            sanitized = self.DELIMITER_BLOCK_PATTERN.sub("[ESCAPED_DELIMITER]", sanitized)
            detected = True

        # 2. Neutralize standard instruction framing delimiters
        for target, replacement in self.DELIMITER_CHARS:
            if target in sanitized:
                sanitized = sanitized.replace(target, replacement)
                detected = True

        # 3. Escape raw HTML/XML tags
        if re.search(r"</?[a-zA-Z][^>]*>", sanitized):
            sanitized = html.escape(sanitized, quote=False)
            detected = True

        return sanitized, detected

    def wrap_evidence(self, text: str, source_id: str = "doc") -> str:
        clean, _ = self.sanitize_untrusted_text(text)
        return f"<evidence source=\"{source_id}\">\n{clean}\n</evidence>"
