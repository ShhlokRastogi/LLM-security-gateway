from __future__ import annotations

import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()


class SecurityConfig(BaseModel):
    """Configuration settings for LLM Security Gateway."""

    # Policy Mode: "strict" (block on any threat), "balanced" (redact PII, block high-severity attacks), "permissive" (flag only)
    policy_mode: str = Field(default_factory=lambda: os.getenv("SECURITY_POLICY_MODE", "balanced"))

    # Prompt Injection & Jailbreak Defense
    block_prompt_injection: bool = Field(default_factory=lambda: os.getenv("BLOCK_PROMPT_INJECTION", "true").lower() == "true")
    block_jailbreaks: bool = Field(default_factory=lambda: os.getenv("BLOCK_JAILBREAKS", "true").lower() == "true")

    # PII Protection
    redact_input_pii: bool = Field(default_factory=lambda: os.getenv("REDACT_INPUT_PII", "true").lower() == "true")
    redact_output_pii: bool = Field(default_factory=lambda: os.getenv("REDACT_OUTPUT_PII", "true").lower() == "true")
    mask_emails: bool = True
    mask_phones: bool = True
    mask_ssn: bool = True
    mask_cards: bool = True
    mask_secrets: bool = True

    # Output Grounding & Hallucination Defense
    verify_grounding: bool = Field(default_factory=lambda: os.getenv("VERIFY_GROUNDING", "true").lower() == "true")
    min_grounding_overlap: float = Field(default_factory=lambda: float(os.getenv("MIN_GROUNDING_OVERLAP", "0.25")))
    block_ungrounded_output: bool = Field(default_factory=lambda: os.getenv("BLOCK_UNGROUNDED_OUTPUT", "true").lower() == "true")

    # Length & Input Bounds
    max_input_length: int = Field(default_factory=lambda: int(os.getenv("MAX_INPUT_LENGTH", "32000")))
    max_output_length: int = Field(default_factory=lambda: int(os.getenv("MAX_OUTPUT_LENGTH", "32000")))

    # Logging & Telemetry
    log_level: str = Field(default_factory=lambda: os.getenv("SECURITY_LOG_LEVEL", "INFO"))


default_config = SecurityConfig()
