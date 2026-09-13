import pytest
from app.detectors.pii import PIIDetector, is_luhn_valid


def test_luhn_checksum_validates_real_cards():
    assert is_luhn_valid("4111111111111111") is True
    assert is_luhn_valid("4111 1111 1111 1111") is True
    assert is_luhn_valid("1234567812345670") is True
    # Non-Luhn numbers fail
    assert is_luhn_valid("1234567890123456") is False
    assert is_luhn_valid("12345") is False


def test_pii_scrubber_masks_cards_emails_phones_ssns():
    detector = PIIDetector()
    text = "Call +1 (555) 234-5678 or write to agent@sec.org. SSN is 000-12-3456. Card: 4111 1111 1111 1111."
    sanitized, detections = detector.detect_and_redact(text)

    assert "[REDACTED_PHONE]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_CARD]" in sanitized
    assert len(detections) == 4


def test_pii_detector_preserves_math_and_scientific_notations():
    detector = PIIDetector()
    text = "The measured mass was 1.5 kg, resistance was 10.5 ohms, and Planck constant is 6.626e-34."
    sanitized, detections = detector.detect_and_redact(text)

    assert sanitized == text
    assert len(detections) == 0
