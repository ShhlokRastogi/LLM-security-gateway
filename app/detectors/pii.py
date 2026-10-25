from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from app.models.responses import DetectionItem


def is_luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
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


def is_imei_valid(imei_raw: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", imei_raw)]
    if len(digits) != 15:
        return False
    # Standard Luhn check for IMEI (doubling every odd index from right / 2nd digit from left)
    checksum = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def is_iban_valid(iban_raw: str) -> bool:
    clean = re.sub(r"[\s-]", "", iban_raw).upper()
    if not (15 <= len(clean) <= 34):
        return False
    rearranged = clean[4:] + clean[:4]
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric_str) % 97 == 1
    except ValueError:
        return False


class PIIDetector:
    """Mathematics-safe, high-precision PII detection and redaction engine."""

    # 1. Communications & Identity
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    PHONE_PATTERN = re.compile(
        r"(?:\b|\+)(?:\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]\d{3,4}[-.\s]\d{4}\b"
    )
    SSN_PATTERN = re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )
    PHONEIMEI_PATTERN = re.compile(
        r"\b(?:\d{2}[- ]\d{6}[- ]\d{6}[- ]\d|\d{15})\b"
    )

    # 2. Network & Hardware
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    IPV6_PATTERN = re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?::[0-9a-fA-F]{1,4}){0,6}\b|"
        r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b"
    )
    MAC_PATTERN = re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
    )

    # 3. Vehicles
    VEHICLEVIN_PATTERN = re.compile(
        r"\b[A-HJ-NPR-Z0-9]{17}\b"
    )
    VEHICLEVRM_PATTERN = re.compile(
        r"\b[A-Z]{2}[0-9]{2}\s?[A-Z]{3}\b"
    )

    # 4. Cryptocurrencies
    BITCOIN_PATTERN = re.compile(
        r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b"
    )
    ETHEREUM_PATTERN = re.compile(
        r"\b0x[a-fA-F0-9]{40}\b"
    )
    LITECOIN_PATTERN = re.compile(
        r"\b(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{39,59})\b"
    )

    # 5. Banking & Finance
    IBAN_PATTERN = re.compile(
        r"\b[A-Z]{2}\d{2}[A-Za-z0-9]{11,30}\b"
    )
    BIC_PATTERN = re.compile(
        r"\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9](?:[A-Z0-9]{3})?\b"
    )
    CARD_CANDIDATE_PATTERN = re.compile(
        r"\b(?:\d[ -]?){13,19}\b"
    )

    # 6. Credentials
    API_KEY_PATTERNS = [
        (re.compile(r"\b(?:gsk|sk)_[a-zA-Z0-9]{24,}\b"), "api_key"),
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"), "github_token"),
        (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key"),
        (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{24,}\b"), "bearer_token"),
    ]

    # 7. Name Lexicons & Patterns (NER + Lexicon Hybrid)
    TITLES_PATTERN = re.compile(
        r"\b(Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Shri|Smt)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
    )
    TRIPLET_NAME_PATTERN = re.compile(
        r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\s+([A-Z][a-z]+)\b"
    )
    NAME_TRIGGER_PATTERN = re.compile(
        r"\b([A-Z][a-z]+)\s+(?:sent|called|emailed|asked|wrote|replied|spoke|visited|reported|submitted)\b"
    )

    # Name Lexicons (Global / Multi-lingual coverage)
    LEXICON_FIRSTNAMES: Set[str] = {
        "rahul", "john", "alex", "david", "michael", "priya", "amit", "emma", "sarah", "james",
        "robert", "mary", "patricia", "jennifer", "linda", "william", "richard", "joseph", "thomas",
        "charles", "daniel", "matthew", "anthony", "mark", "donald", "steven", "paul", "andrew",
        "joshua", "kenneth", "kevin", "brian", "george", "edward", "ronald", "timothy", "jason",
        "jeffrey", "ryan", "jacob", "gary", "nicholas", "eric", "jonathan", "stephen", "larry",
        "justin", "scott", "brandon", "benjamin", "samuel", "gregory", "frank", "alexander",
        "raymond", "patrick", "jack", "dennis", "jerry", "tyler", "aaron", "jose", "adam",
        "nathan", "henry", "douglas", "zachary", "peter", "kyle", "walter", "ethan", "jeremy",
        "harold", "keith", "christian", "roger", "noah", "gerald", "carl", "terry", "sean",
        "austin", "arthur", "lawrence", "jesse", "dylan", "bryan", "joe", "jordan", "billy",
        "albert", "bruce", "willie", "gabriel", "logan", "alan", "juan", "wayne", "roy", "ralph",
        "aarav", "vihaan", "aditya", "arjun", "sai", "reyansh", "ayan", "krishna", "ishaan",
        "shaurya", "rohan", "ananya", "diya", "aditi", "meera", "pooja", "deepak", "suresh", "ramesh"
    }

    LEXICON_MIDDLENAMES: Set[str] = {
        "kumar", "singh", "lee", "marie", "ann", "jean", "james", "ray", "chandra", "prasad",
        "nath", "lal", "prakash", "kant", "mohan", "babu", "raj", "swarup", "shankar", "amani",
        "alan", "allen", "david", "edward", "joseph", "lynn", "michael", "paul", "rose", "wayne"
    }

    LEXICON_LASTNAMES: Set[str] = {
        "sharma", "verma", "gupta", "smith", "johnson", "williams", "brown", "jones", "garcia",
        "miller", "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez", "wilson",
        "anderson", "thomas", "taylor", "moore", "jackson", "martin", "lee", "perez", "thompson",
        "white", "harris", "sanchez", "clark", "ramirez", "lewis", "robinson", "walker", "young",
        "allen", "king", "wright", "scott", "torres", "nguyen", "hill", "flores", "green", "adams",
        "nelson", "baker", "hall", "rivera", "campbell", "mitchell", "carter", "roberts", "patel",
        "singh", "reddy", "kumar", "das", "banerjee", "chatterjee", "iyer", "nair", "rao", "joshi"
    }

    def detect_and_redact(self, text: str) -> Tuple[str, List[DetectionItem]]:
        detections: List[DetectionItem] = []
        sanitized = text

        # 1. API Keys
        for pattern, key_type in self.API_KEY_PATTERNS:
            matches = list(pattern.finditer(sanitized))
            for match in reversed(matches):
                sanitized = sanitized[:match.start()] + "[REDACTED_KEY]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="api_key",
                    confidence=1.0,
                    details=f"Detected {key_type}",
                    metadata={"redaction": "[REDACTED_KEY]"}
                ))

        # 2. Phone IMEI (Run BEFORE Credit Card candidate pattern to prioritize IMEI)
        imei_matches = list(self.PHONEIMEI_PATTERN.finditer(sanitized))
        for match in reversed(imei_matches):
            raw = match.group(0)
            if is_imei_valid(raw):
                sanitized = sanitized[:match.start()] + "[REDACTED_IMEI]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="phone_imei",
                    confidence=0.98,
                    details="Valid IMEI mobile equipment identifier detected",
                    metadata={"redaction": "[REDACTED_IMEI]"}
                ))

        # 3. Credit Cards with Luhn Checksum
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

        # 4. Emails
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

        # 5. SSNs
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

        # 6. Phone Numbers
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

        # 7. IPv4
        ipv4_matches = list(self.IPV4_PATTERN.finditer(sanitized))
        for match in reversed(ipv4_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_IPV4]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="ipv4",
                confidence=0.98,
                details="IPv4 address detected",
                metadata={"redaction": "[REDACTED_IPV4]"}
            ))

        # 8. IPv6
        ipv6_matches = list(self.IPV6_PATTERN.finditer(sanitized))
        for match in reversed(ipv6_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_IPV6]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="ipv6",
                confidence=0.98,
                details="IPv6 address detected",
                metadata={"redaction": "[REDACTED_IPV6]"}
            ))

        # 9. MAC Address
        mac_matches = list(self.MAC_PATTERN.finditer(sanitized))
        for match in reversed(mac_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_MAC]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="mac_address",
                confidence=0.95,
                details="MAC hardware address detected",
                metadata={"redaction": "[REDACTED_MAC]"}
            ))

        # 10. Ethereum Address
        eth_matches = list(self.ETHEREUM_PATTERN.finditer(sanitized))
        for match in reversed(eth_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_ETHEREUM]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="ethereum_address",
                confidence=1.0,
                details="Ethereum cryptocurrency address detected",
                metadata={"redaction": "[REDACTED_ETHEREUM]"}
            ))

        # 11. Bitcoin Address
        btc_matches = list(self.BITCOIN_PATTERN.finditer(sanitized))
        for match in reversed(btc_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_BITCOIN]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="bitcoin_address",
                confidence=0.98,
                details="Bitcoin wallet address detected",
                metadata={"redaction": "[REDACTED_BITCOIN]"}
            ))

        # 12. Litecoin Address
        ltc_matches = list(self.LITECOIN_PATTERN.finditer(sanitized))
        for match in reversed(ltc_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_LITECOIN]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="litecoin_address",
                confidence=0.98,
                details="Litecoin wallet address detected",
                metadata={"redaction": "[REDACTED_LITECOIN]"}
            ))

        # 13. IBAN with Mod-97 Checksum
        iban_matches = list(self.IBAN_PATTERN.finditer(sanitized))
        for match in reversed(iban_matches):
            raw = match.group(0)
            if is_iban_valid(raw):
                sanitized = sanitized[:match.start()] + "[REDACTED_IBAN]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="iban",
                    confidence=1.0,
                    details="Valid IBAN international bank account number detected",
                    metadata={"redaction": "[REDACTED_IBAN]"}
                ))

        # 14. BIC / SWIFT
        bic_matches = list(self.BIC_PATTERN.finditer(sanitized))
        for match in reversed(bic_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_BIC]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="bic",
                confidence=0.90,
                details="BIC/SWIFT bank identifier detected",
                metadata={"redaction": "[REDACTED_BIC]"}
            ))

        # 15. Vehicle VIN
        vin_matches = list(self.VEHICLEVIN_PATTERN.finditer(sanitized))
        for match in reversed(vin_matches):
            val = match.group(0)
            if not val.isdigit() and any(c.isdigit() for c in val):
                sanitized = sanitized[:match.start()] + "[REDACTED_VIN]" + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii",
                    category="vehicle_vin",
                    confidence=0.95,
                    details="Vehicle Identification Number (VIN) detected",
                    metadata={"redaction": "[REDACTED_VIN]"}
                ))

        # 16. Vehicle VRM
        vrm_matches = list(self.VEHICLEVRM_PATTERN.finditer(sanitized))
        for match in reversed(vrm_matches):
            sanitized = sanitized[:match.start()] + "[REDACTED_VRM]" + sanitized[match.end():]
            detections.append(DetectionItem(
                type="pii",
                category="vehicle_vrm",
                confidence=0.90,
                details="Vehicle registration mark / license plate detected",
                metadata={"redaction": "[REDACTED_VRM]"}
            ))

        # 17. Structural Name Detection (MIDDLENAME, FIRSTNAME, LASTNAME)
        # A. Triplet Names: "Rahul Kumar Sharma" -> FIRSTNAME, MIDDLENAME, LASTNAME
        triplet_matches = list(self.TRIPLET_NAME_PATTERN.finditer(sanitized))
        for match in reversed(triplet_matches):
            first, middle, last = match.group(1), match.group(2), match.group(3)
            # Check if recognized by lexicons or name structure
            is_valid_structure = (
                middle.lower() in self.LEXICON_MIDDLENAMES
                or first.lower() in self.LEXICON_FIRSTNAMES
                or last.lower() in self.LEXICON_LASTNAMES
            )
            if is_valid_structure:
                replacement = "[REDACTED_FIRSTNAME] [REDACTED_MIDDLENAME] [REDACTED_LASTNAME]"
                sanitized = sanitized[:match.start()] + replacement + sanitized[match.end():]
                detections.extend([
                    DetectionItem(
                        type="pii", category="first_name", confidence=0.95,
                        details=f"First name detected: {first}", metadata={"redaction": "[REDACTED_FIRSTNAME]"}
                    ),
                    DetectionItem(
                        type="pii", category="middle_name", confidence=0.95,
                        details=f"Middle name detected: {middle}", metadata={"redaction": "[REDACTED_MIDDLENAME]"}
                    ),
                    DetectionItem(
                        type="pii", category="last_name", confidence=0.95,
                        details=f"Last name detected: {last}", metadata={"redaction": "[REDACTED_LASTNAME]"}
                    ),
                ])

        # B. Title/Salutation Names: "Mr. Sharma called" -> LASTNAME
        title_matches = list(self.TITLES_PATTERN.finditer(sanitized))
        for match in reversed(title_matches):
            title, name_part = match.group(1), match.group(2)
            parts = name_part.split()
            if len(parts) == 1:
                replacement = f"{title} [REDACTED_LASTNAME]"
                sanitized = sanitized[:match.start()] + replacement + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii", category="last_name", confidence=0.95,
                    details=f"Last name with title detected: {name_part}",
                    metadata={"redaction": "[REDACTED_LASTNAME]"}
                ))
            elif len(parts) == 2:
                replacement = f"{title} [REDACTED_FIRSTNAME] [REDACTED_LASTNAME]"
                sanitized = sanitized[:match.start()] + replacement + sanitized[match.end():]
                detections.extend([
                    DetectionItem(
                        type="pii", category="first_name", confidence=0.95,
                        details=f"First name with title detected: {parts[0]}",
                        metadata={"redaction": "[REDACTED_FIRSTNAME]"}
                    ),
                    DetectionItem(
                        type="pii", category="last_name", confidence=0.95,
                        details=f"Last name with title detected: {parts[1]}",
                        metadata={"redaction": "[REDACTED_LASTNAME]"}
                    ),
                ])

        # C. Firstname Verb Triggers: "Rahul sent the report"
        trigger_matches = list(self.NAME_TRIGGER_PATTERN.finditer(sanitized))
        for match in reversed(trigger_matches):
            cand_first = match.group(1)
            if cand_first.lower() in self.LEXICON_FIRSTNAMES:
                full_match_str = match.group(0)
                verb_part = full_match_str[len(cand_first):]
                replacement = f"[REDACTED_FIRSTNAME]{verb_part}"
                sanitized = sanitized[:match.start()] + replacement + sanitized[match.end():]
                detections.append(DetectionItem(
                    type="pii", category="first_name", confidence=0.90,
                    details=f"First name trigger detected: {cand_first}",
                    metadata={"redaction": "[REDACTED_FIRSTNAME]"}
                ))

        return sanitized, detections
