from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.models.requests import CheckInputRequest
from app.services.pipeline import SecurityPipeline
from evaluation.metrics.evaluator import compute_benchmark_metrics


def run_security_benchmark(datasets_dir: Optional[Path] = None):
    dir_path = datasets_dir or (Path(__file__).parent.parent / "datasets")
    pipeline = SecurityPipeline()

    all_probes: List[Dict[str, Any]] = []
    for json_file in sorted(dir_path.glob("*.json")):
        if json_file.name.startswith("action_"):
            continue
        probes = json.loads(json_file.read_text(encoding="utf-8"))
        for p in probes:
            if "prompt" not in p:
                continue
            p["dataset"] = json_file.stem
            all_probes.append(p)

    results = []
    print(f"\nRunning LLM Security Gateway Benchmark on {len(all_probes)} probes across {len(list(dir_path.glob('*.json')))} datasets...\n")

    for probe in all_probes:
        req = CheckInputRequest(text=probe["prompt"], metadata={"probe_id": probe["id"], "dataset": probe["dataset"]})
        decision = pipeline.inspect_input(req)
        results.append({
            "id": probe["id"],
            "dataset": probe["dataset"],
            "prompt": probe["prompt"][:50],
            "expected": probe["expected"],
            "actual": decision.decision.value,
            "risk_score": decision.risk_score,
            "latency_ms": decision.latency_ms,
            "detections": len(decision.detections),
        })

    metrics = compute_benchmark_metrics(results)

    print("=" * 80)
    print("LLM SECURITY GATEWAY BENCHMARK EVALUATION REPORT")
    print("=" * 80)
    print(f"Total Probes Evaluated    : {metrics.total_probes}")
    print(f"Adversarial Attacks Tested: {metrics.adversarial_count}")
    print(f"Benign Controls Evaluated : {metrics.benign_count}")
    print("-" * 80)
    print(f"Attack Success Rate (ASR) : {metrics.attack_success_rate:.2f}% (Lower is better)")
    print(f"Defense Success Rate      : {metrics.defense_success_rate:.2f}% (Higher is better)")
    print(f"False Positive Rate (FPR) : {metrics.false_positive_rate:.2f}%")
    print(f"False Negative Rate (FNR) : {metrics.false_negative_rate:.2f}%")
    print("-" * 80)
    print(f"Mean Latency              : {metrics.mean_latency_ms:.3f} ms")
    print(f"P50 Latency               : {metrics.p50_latency_ms:.3f} ms")
    print(f"P95 Latency               : {metrics.p95_latency_ms:.3f} ms")
    print(f"P99 Latency               : {metrics.p99_latency_ms:.3f} ms")
    print("=" * 80 + "\n")

    return metrics


if __name__ == "__main__":
    from typing import Optional
    run_security_benchmark()
