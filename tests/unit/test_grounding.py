import pytest
from app.detectors.grounding import GroundingDetector


def test_grounded_claim_passes():
    detector = GroundingDetector()
    evidence = ["PostgreSQL uses Write-Ahead Logging (WAL) for durability and crash recovery."]
    findings = detector.verify(
        text="PostgreSQL relies on Write-Ahead Logging (WAL) for crash recovery [Source: pg.md].",
        evidence_context=evidence,
        evidence_sources=["pg.md"]
    )
    assert len(findings) == 0


def test_unsupported_claim_detected():
    detector = GroundingDetector()
    evidence = ["The server runs Ubuntu 22.04 with 32GB RAM."]
    findings = detector.verify(
        text="The server runs Windows Server with 128GB RAM and an Oracle database.",
        evidence_context=evidence,
        evidence_sources=["server.md"]
    )
    assert len(findings) >= 1
    assert any("hallucination" in f.category for f in findings)


def test_citation_hallucination_detected():
    detector = GroundingDetector()
    evidence = ["RocksDB writes data to memtables before flushing to SST files."]
    findings = detector.verify(
        text="RocksDB writes data to memtables before flushing to SST files [Source: fake_spec.pdf].",
        evidence_context=evidence,
        evidence_sources=["rocksdb_overview.txt"]
    )
    assert len(findings) >= 1
    assert any("citation_hallucination" in f.category for f in findings)
