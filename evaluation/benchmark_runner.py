from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict, List
import statistics

from security_gateway.config import SecurityConfig
from security_gateway.gateway import SecurityGateway
from security_gateway.models import SecurityAction


def run_security_benchmark(dataset_path: Optional[str] = None, config: Optional[SecurityConfig] = None) -> Dict[str, Any]:
    """Run automated security benchmark calculating ASR, FPR, FNR, and latency."""
    if dataset_path is None:
        dataset_path = str(Path(__file__).parent / "test_datasets" / "prompt_injections.json")

    with open(dataset_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    benign_samples = data.get("benign", [])
    adversarial_samples = data.get("adversarial", [])

    gateway = SecurityGateway(config=config or SecurityConfig(block_prompt_injection=True, policy_mode="strict"))

    latencies: List[float] = []

    # 1. Test Benign Queries (Target: 0% False Positives)
    false_positives = 0
    for sample in benign_samples:
        decision = gateway.inspect_input(sample["text"])
        latencies.append(decision.latency_ms)
        if decision.action == SecurityAction.BLOCK or not decision.allowed:
            false_positives += 1

    # 2. Test Adversarial Attacks (Target: 0% Attack Success Rate / False Negatives)
    successful_attacks = 0  # Allowed attacks (ASR)
    for sample in adversarial_samples:
        decision = gateway.inspect_input(sample["text"])
        latencies.append(decision.latency_ms)
        if decision.allowed or decision.action == SecurityAction.ALLOW:
            successful_attacks += 1

    total_benign = len(benign_samples)
    total_attacks = len(adversarial_samples)

    fpr = (false_positives / total_benign * 100) if total_benign > 0 else 0.0
    asr = (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0.0
    fnr = asr  # An attack that succeeds is a false negative of the filter
    defense_success_rate = 100.0 - asr

    latencies.sort()
    mean_lat = statistics.mean(latencies) if latencies else 0.0
    p50_lat = latencies[len(latencies) // 2] if latencies else 0.0
    p95_lat = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    report = {
        "total_samples": total_benign + total_attacks,
        "total_benign": total_benign,
        "total_attacks": total_attacks,
        "attack_success_rate_pct": round(asr, 2),
        "defense_success_rate_pct": round(defense_success_rate, 2),
        "false_positive_rate_pct": round(fpr, 2),
        "false_negative_rate_pct": round(fnr, 2),
        "latencies_ms": {
            "mean": round(mean_lat, 3),
            "p50": round(p50_lat, 3),
            "p95": round(p95_lat, 3),
            "max": round(max_lat, 3),
        },
    }

    return report


if __name__ == "__main__":
    rep = run_security_benchmark()
    print("=" * 60)
    print(" LLM SECURITY GATEWAY BENCHMARK REPORT ")
    print("=" * 60)
    print(f"Total Samples Evaluated:      {rep['total_samples']}")
    print(f"Attack Success Rate (ASR):    {rep['attack_success_rate_pct']}% (Lower is better)")
    print(f"Defense Success Rate:         {rep['defense_success_rate_pct']}% (Higher is better)")
    print(f"False Positive Rate (FPR):    {rep['false_positive_rate_pct']}%")
    print(f"False Negative Rate (FNR):    {rep['false_negative_rate_pct']}%")
    print(f"Mean Inspection Latency:      {rep['latencies_ms']['mean']} ms")
    print(f"P95 Inspection Latency:       {rep['latencies_ms']['p95']} ms")
    print("=" * 60)
