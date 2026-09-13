from app.detectors.pii import PIIDetector, is_luhn_valid

CATEGORY_TO_TYPE = {
    "credit_card": "CREDIT_CARD",
    "email": "EMAIL",
    "ssn": "SSN",
    "phone": "PHONE",
    "api_key": "API_KEY",
    "github_token": "API_KEY",
    "aws_access_key": "API_KEY",
    "bearer_token": "API_KEY",
}


class PIIMasker(PIIDetector):
    def mask_text(self, text: str, context_origin: str = "general"):
        sanitized, detections = self.detect_and_redact(text)
        redactions = [
            {
                "type": CATEGORY_TO_TYPE.get(d.category, d.category.upper()),
                "match": d.details,
                "origin": context_origin,
            }
            for d in detections
        ]
        return sanitized, redactions


__all__ = ["PIIMasker", "is_luhn_valid", "CATEGORY_TO_TYPE"]
