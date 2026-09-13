import pytest
from app.models.responses import DetectionItem, SecurityAction
from app.policy.config import PolicyConfig
from app.policy.engine import PolicyEngine


def test_policy_engine_blocks_high_risk_injection():
    cfg = PolicyConfig()
    engine = PolicyEngine(cfg)

    detections = [
        DetectionItem(type="prompt_injection", category="instruction_override", confidence=0.95, details="override")
    ]
    action, risk = engine.evaluate(detections, pipeline_type="input")
    assert action == SecurityAction.BLOCK
    assert risk == 0.95


def test_policy_engine_redacts_pii():
    cfg = PolicyConfig()
    engine = PolicyEngine(cfg)

    detections = [
        DetectionItem(type="pii", category="email", confidence=1.0, details="email found")
    ]
    action, risk = engine.evaluate(detections, pipeline_type="input")
    assert action == SecurityAction.REDACT
    assert risk == 1.0


def test_policy_engine_allows_clean_input():
    cfg = PolicyConfig()
    engine = PolicyEngine(cfg)

    action, risk = engine.evaluate([], pipeline_type="input")
    assert action == SecurityAction.ALLOW
    assert risk == 0.0
