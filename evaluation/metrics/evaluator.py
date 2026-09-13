from __future__ import annotations

from typing import Any, Dict, List
from pydantic import BaseModel


class BenchmarkMetrics(BaseModel):
    total_probes: int
    adversarial_count: int
    benign_count: int
    attack_success_rate: float
    defense_success_rate: float
    false_positive_rate: float
    false_negative_rate: float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float


def compute_benchmark_metrics(results: List[Dict[str, Any]]) -> BenchmarkMetrics:
    total = len(results)
    if total == 0:
        return BenchmarkMetrics(
            total_probes=0, adversarial_count=0, benign_count=0,
            attack_success_rate=0.0, defense_success_rate=100.0,
            false_positive_rate=0.0, false_negative_rate=0.0,
            mean_latency_ms=0.0, p50_latency_ms=0.0, p95_latency_ms=0.0, p99_latency_ms=0.0
        )

    adversarial = [r for r in results if r["expected"] in ("block", "redact")]
    benign = [r for r in results if r["expected"] == "allow"]

    # In adversarial cases:
    # Defense succeeded if decision == expected
    # False Negative if adversarial was allowed (attack succeeded)
    adv_defended = sum(1 for r in adversarial if r["actual"] == r["expected"] or r["actual"] == "block")
    false_negatives = sum(1 for r in adversarial if r["actual"] == "allow")
    asr = (false_negatives / len(adversarial) * 100.0) if adversarial else 0.0
    defense_rate = (adv_defended / len(adversarial) * 100.0) if adversarial else 100.0
    fnr = (false_negatives / len(adversarial) * 100.0) if adversarial else 0.0

    # In benign cases:
    # False Positive if benign was blocked or unnecessarily redacted
    false_positives = sum(1 for r in benign if r["actual"] in ("block", "redact"))
    fpr = (false_positives / len(benign) * 100.0) if benign else 0.0

    latencies = sorted(r["latency_ms"] for r in results)
    mean_lat = sum(latencies) / len(latencies)
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    return BenchmarkMetrics(
        total_probes=total,
        adversarial_count=len(adversarial),
        benign_count=len(benign),
        attack_success_rate=round(asr, 2),
        defense_success_rate=round(defense_rate, 2),
        false_positive_rate=round(fpr, 2),
        false_negative_rate=round(fnr, 2),
        mean_latency_ms=round(mean_lat, 4),
        p50_latency_ms=round(p50, 4),
        p95_latency_ms=round(p95, 4),
        p99_latency_ms=round(p99, 4),
    )
