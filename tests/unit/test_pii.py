import pytest
from app.detectors.pii import PIIDetector, is_luhn_valid, is_imei_valid, is_iban_valid


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


def test_pii_detector_network_and_hardware_categories():
    detector = PIIDetector()
    # IPv4, IPv6, MAC, IMEI
    text = (
        "Server IP is 192.168.1.100, Gateway IPv6 is 2001:0db8:85a3:0000:0000:8a2e:0370:7334. "
        "Device MAC: 00:1A:2B:3C:4D:5E and phone IMEI is 490154203237518."
    )
    sanitized, detections = detector.detect_and_redact(text)

    assert "[REDACTED_IPV4]" in sanitized
    assert "[REDACTED_IPV6]" in sanitized
    assert "[REDACTED_MAC]" in sanitized
    assert "[REDACTED_IMEI]" in sanitized
    assert not any(val in sanitized for val in ["192.168.1.100", "00:1A:2B:3C:4D:5E", "490154203237518"])


def test_pii_detector_crypto_addresses():
    detector = PIIDetector()
    text = (
        "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. "
        "ETH to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e and LTC to LYe5KqCgzNf3wLqfKkG9u3U7YyFk8tF9aY."
    )
    sanitized, detections = detector.detect_and_redact(text)

    assert "[REDACTED_BITCOIN]" in sanitized
    assert "[REDACTED_ETHEREUM]" in sanitized
    assert "[REDACTED_LITECOIN]" in sanitized
    assert "0x742d35Cc6634C0532925a3b844Bc454e4438f44e" not in sanitized


def test_pii_detector_banking_iban_and_bic():
    detector = PIIDetector()
    # Real valid GB IBAN passing Mod-97 + BIC
    text = "Wire funds to IBAN GB15MIDL40051512345678 and SWIFT/BIC DEUTDEDDFXX."
    sanitized, detections = detector.detect_and_redact(text)

    assert "[REDACTED_IBAN]" in sanitized
    assert "[REDACTED_BIC]" in sanitized
    assert "GB15MIDL40051512345678" not in sanitized
    assert "DEUTDEDDFXX" not in sanitized


def test_pii_detector_vehicles_vin_and_vrm():
    detector = PIIDetector()
    # 17-char VIN (no I, O, Q) + UK format VRM (e.g. AB12 CDE)
    text = "Vehicle VIN: 1HGCR2F83HA001234 and plate registration is AB12 CDE."
    sanitized, detections = detector.detect_and_redact(text)

    assert "[REDACTED_VIN]" in sanitized
    assert "[REDACTED_VRM]" in sanitized
    assert "1HGCR2F83HA001234" not in sanitized
    assert "AB12 CDE" not in sanitized


def test_pii_detector_first_middle_last_name_decomposition():
    detector = PIIDetector()

    # 1. Firstname verb trigger: "Rahul sent the report"
    text1 = "Rahul sent the report to the compliance officer."
    san1, det1 = detector.detect_and_redact(text1)
    assert "[REDACTED_FIRSTNAME] sent the report" in san1
    assert any(d.category == "first_name" for d in det1)

    # 2. Title with Lastname: "Mr. Sharma called"
    text2 = "Please inform Mr. Sharma called earlier today."
    san2, det2 = detector.detect_and_redact(text2)
    assert "Mr. [REDACTED_LASTNAME] called" in san2
    assert any(d.category == "last_name" for d in det2)

    # 3. Compound Name: "Rahul Kumar Sharma" -> FIRSTNAME, MIDDLENAME, LASTNAME
    text3 = "Employee records show Rahul Kumar Sharma submitted the request."
    san3, det3 = detector.detect_and_redact(text3)
    assert "[REDACTED_FIRSTNAME] [REDACTED_MIDDLENAME] [REDACTED_LASTNAME]" in san3
    categories = [d.category for d in det3]
    assert "first_name" in categories
    assert "middle_name" in categories
    assert "last_name" in categories
