from __future__ import annotations

import json
from pathlib import Path
import sys
import time

# Add root directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.decision.engine import default_decision_engine
from app.decision.models import ComprehensiveActionCheckRequest


def run_action_security_benchmark():
    dataset_path = Path(__file__).parent.parent / "datasets" / "action_probes.json"
    if not dataset_path.exists():
        print(f"Dataset not found at {dataset_path}")
        return

    probes = json.loads(dataset_path.read_text(encoding="utf-8"))

    engine = default_decision_engine
    latencies = []
    adversarial_count = 0
    benign_count = 0
    attacks_blocked = 0
    attacks_bypassed = 0
    false_positives = 0
    true_negatives = 0

    print("=" * 80)
    print("ACTION SECURITY BENCHMARK EVALUATION")
    print("=" * 80)

    for probe in probes:
        t0 = time.perf_counter()
        req = ComprehensiveActionCheckRequest(
            client_id=probe.get("client_id", "default"),
            agent_id=probe.get("agent_id", "default_agent"),
            tool_name=probe["tool_name"],
            arguments=probe.get("arguments", {}),
            context=probe.get("context", {"environment": "development"}),
            user=probe.get("user", {"role": "user"}),
        )
        resp = engine.evaluate_action(req)
        lat = (time.perf_counter() - t0) * 1000
        latencies.append(lat)

        is_adv = probe.get("is_adversarial", False)
        exp = probe.get("expected_decision", "DENY")
        act = resp.decision.value

        # Evaluation
        if is_adv:
            adversarial_count += 1
            if act in ["DENY", "REQUIRE_APPROVAL"]:
                attacks_blocked += 1
            else:
                attacks_bypassed += 1
        else:
            benign_count += 1
            if act == "ALLOW":
                true_negatives += 1
            else:
                false_positives += 1

        print(f"[{probe['id']}] {probe['category']:<30} Expected: {exp:<16} Actual: {act:<16} Latency: {lat:.2f}ms")

    # Metrics
    asr = (attacks_bypassed / adversarial_count * 100) if adversarial_count else 0.0
    defense_rate = (attacks_blocked / adversarial_count * 100) if adversarial_count else 100.0
    fpr = (false_positives / benign_count * 100) if benign_count else 0.0
    fnr = asr
    latencies.sort()
    mean_lat = sum(latencies) / len(latencies)
    p95_lat = latencies[int(len(latencies) * 0.95)]

    print("\n" + "=" * 80)
    print("ACTION SECURITY BENCHMARK REPORT")
    print("=" * 80)
    print(f"Total Action Probes Evaluated  : {len(probes)}")
    print(f"Adversarial Attacks Tested     : {adversarial_count}")
    print(f"Benign Controls Evaluated      : {benign_count}")
    print("-" * 80)
    print(f"Attack Success Rate (ASR)      : {asr:.2f}% (Target: 0.0%)")
    print(f"Defense Success Rate           : {defense_rate:.2f}% (Target: 100.0%)")
    print(f"False Positive Rate (FPR)      : {fpr:.2f}% (Target: 0.0%)")
    print(f"False Negative Rate (FNR)      : {fnr:.2f}%")
    print("-" * 80)
    print(f"Mean Decision Latency          : {mean_lat:.3f} ms")
    print(f"P95 Decision Latency           : {p95_lat:.3f} ms")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_action_security_benchmark()
