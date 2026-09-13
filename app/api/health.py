from __future__ import annotations

from fastapi import APIRouter
from app.models.responses import HealthResponse, ReadyResponse

router = APIRouter(tags=["Health & Readiness"])


@router.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse()


@router.get("/ready", response_model=ReadyResponse)
def readiness_check():
    return ReadyResponse(
        ready=True,
        detectors_initialized=["pii_scrubber", "prompt_injection", "grounding_guard", "toxicity_filter"]
    )
