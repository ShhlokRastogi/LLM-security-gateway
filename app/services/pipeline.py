from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from app.detectors.injection import InjectionDetector
from app.detectors.pii import PIIDetector
from app.detectors.grounding import GroundingDetector
from app.detectors.toxicity import ToxicityDetector
from app.guardrails.sandbox import ContextSandbox
from app.models.requests import CheckInputRequest, CheckOutputRequest
from app.models.responses import DetectionItem, SecurityAction, SecurityDecision
from app.policy.config import PolicyConfig, load_policy_config
from app.policy.engine import PolicyEngine
from app.services.logging import get_security_logger

logger = get_security_logger("security.pipeline")


class SecurityPipeline:
    """Coordinated input & output security verification pipeline."""

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self.config = config or load_policy_config()
        self.policy_engine = PolicyEngine(self.config)
        self.pii_detector = PIIDetector()
        self.injection_detector = InjectionDetector()
        self.grounding_detector = GroundingDetector()
        self.toxicity_detector = ToxicityDetector()
        self.sandbox = ContextSandbox()

    def inspect_input(self, req: CheckInputRequest) -> SecurityDecision:
        start_time = time.perf_counter()
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        all_detections: List[DetectionItem] = []
        sanitized_text = req.text

        try:
            # 1. PII Detection & Redaction
            if self.config.input_guards.get("pii_scrubber", {}).get("enabled", True):
                sanitized_text, pii_detections = self.pii_detector.detect_and_redact(sanitized_text)
                all_detections.extend(pii_detections)

            # 2. Prompt Injection & Delimiter Detection
            if self.config.input_guards.get("prompt_injection", {}).get("enabled", True):
                injection_detections = self.injection_detector.scan(req.text)
                all_detections.extend(injection_detections)

            # 3. Policy Evaluation
            action, risk_score = self.policy_engine.evaluate(all_detections, pipeline_type="input")

            # In block mode, text indicates refusal
            final_text = "[BLOCKED BY SECURITY POLICY]" if action == SecurityAction.BLOCK else sanitized_text
            latency_ms = (time.perf_counter() - start_time) * 1000

            decision = SecurityDecision(
                decision=action,
                risk_score=round(risk_score, 4),
                text=final_text,
                detections=all_detections,
                request_id=req_id,
                latency_ms=round(latency_ms, 2),
            )

            logger.info(
                f"Input inspected: decision={action.value}, risk={risk_score:.2f}, detections={len(all_detections)}",
                extra={
                    "request_id": req_id,
                    "event_type": "input_inspection",
                    "decision": action.value,
                    "detections": [d.model_dump() for d in all_detections],
                    "latency_ms": round(latency_ms, 2),
                },
            )
            return decision

        except Exception as e:
            logger.error(f"Detector failure during input inspection: {e}", extra={"request_id": req_id})
            if self.config.fail_mode == "fail_closed":
                return SecurityDecision(
                    decision=SecurityAction.BLOCK,
                    risk_score=1.0,
                    text="[BLOCKED DUE TO SECURITY CHECK FAILURE]",
                    detections=[DetectionItem(type="system_error", category="fail_closed", confidence=1.0, details=str(e))],
                    request_id=req_id,
                    latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                )
            else:
                return SecurityDecision(
                    decision=SecurityAction.FLAG,
                    risk_score=0.5,
                    text=req.text,
                    detections=[DetectionItem(type="system_error", category="fail_open", confidence=0.5, details=str(e))],
                    request_id=req_id,
                    latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                )

    def inspect_output(self, req: CheckOutputRequest) -> SecurityDecision:
        start_time = time.perf_counter()
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        all_detections: List[DetectionItem] = []
        sanitized_text = req.text

        try:
            # 1. Output PII Leakage
            if self.config.output_guards.get("pii_leakage", {}).get("enabled", True):
                sanitized_text, pii_detections = self.pii_detector.detect_and_redact(sanitized_text)
                for p in pii_detections:
                    p.type = "pii_leakage"
                all_detections.extend(pii_detections)

            # 2. Factual Grounding & Citation Audit
            if self.config.output_guards.get("grounding", {}).get("enabled", True):
                grounding_detections = self.grounding_detector.verify(
                    text=req.text,
                    evidence_context=req.evidence_context,
                    evidence_sources=req.evidence_sources,
                )
                all_detections.extend(grounding_detections)

            # 3. Toxicity & Harm Validation
            if self.config.output_guards.get("toxicity", {}).get("enabled", True):
                toxicity_detections = self.toxicity_detector.scan(req.text)
                all_detections.extend(toxicity_detections)

            # 4. Policy Evaluation
            action, risk_score = self.policy_engine.evaluate(all_detections, pipeline_type="output")
            final_text = "[BLOCKED BY SECURITY POLICY]" if action == SecurityAction.BLOCK else sanitized_text
            latency_ms = (time.perf_counter() - start_time) * 1000

            decision = SecurityDecision(
                decision=action,
                risk_score=round(risk_score, 4),
                text=final_text,
                detections=all_detections,
                request_id=req_id,
                latency_ms=round(latency_ms, 2),
            )

            logger.info(
                f"Output inspected: decision={action.value}, risk={risk_score:.2f}, detections={len(all_detections)}",
                extra={
                    "request_id": req_id,
                    "event_type": "output_inspection",
                    "decision": action.value,
                    "detections": [d.model_dump() for d in all_detections],
                    "latency_ms": round(latency_ms, 2),
                },
            )
            return decision

        except Exception as e:
            logger.error(f"Detector failure during output inspection: {e}", extra={"request_id": req_id})
            if self.config.fail_mode == "fail_closed":
                return SecurityDecision(
                    decision=SecurityAction.BLOCK,
                    risk_score=1.0,
                    text="[BLOCKED DUE TO SECURITY CHECK FAILURE]",
                    detections=[DetectionItem(type="system_error", category="fail_closed", confidence=1.0, details=str(e))],
                    request_id=req_id,
                    latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                )
            else:
                return SecurityDecision(
                    decision=SecurityAction.FLAG,
                    risk_score=0.5,
                    text=req.text,
                    detections=[DetectionItem(type="system_error", category="fail_open", confidence=0.5, details=str(e))],
                    request_id=req_id,
                    latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                )
