from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class GuardRuleConfig(BaseModel):
    enabled: bool = True
    action: str = "block"  # allow | block | redact | flag
    threshold: float = 0.70


class PolicyConfig(BaseModel):
    version: str = "1.0"
    service_name: str = "llm-security-gateway"
    fail_mode: str = "fail_closed"  # fail_closed | fail_open
    policy_mode: str = "balanced"   # permissive | balanced | strict
    input_guards: Dict[str, Any] = Field(default_factory=lambda: {
        "prompt_injection": {"enabled": True, "action": "block", "threshold": 0.70},
        "jailbreak": {"enabled": True, "action": "block", "threshold": 0.75},
        "pii_scrubber": {"enabled": True, "action": "redact"},
    })
    output_guards: Dict[str, Any] = Field(default_factory=lambda: {
        "pii_leakage": {"enabled": True, "action": "redact"},
        "grounding": {"enabled": True, "action": "block", "min_claim_overlap": 0.25},
        "toxicity": {"enabled": True, "action": "block", "threshold": 0.80},
    })


def load_policy_config(config_path: Optional[str] = None) -> PolicyConfig:
    p = Path(config_path) if config_path else Path("config/policy.yaml")
    if p.exists():
        try:
            content = p.read_text(encoding="utf-8")
            # Simple YAML parser fallback if PyYAML not installed
            try:
                import yaml
                data = yaml.safe_load(content)
                if data and "policy" in data:
                    return PolicyConfig(
                        version=data.get("version", "1.0"),
                        service_name=data.get("service_name", "llm-security-gateway"),
                        fail_mode=data.get("fail_mode", "fail_closed"),
                        input_guards=data["policy"].get("input_guards", {}),
                        output_guards=data["policy"].get("output_guards", {}),
                    )
            except ImportError:
                pass
        except Exception:
            pass

    # Default fallback
    mode = os.getenv("SECURITY_POLICY_MODE", "balanced").lower()
    return PolicyConfig(policy_mode=mode)


GatewayPolicyConfig = PolicyConfig
