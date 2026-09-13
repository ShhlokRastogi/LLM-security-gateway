from __future__ import annotations

import time
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.api.health import router as health_router
from app.api.v1 import router as v1_router

app = FastAPI(
    title="LLM Security Gateway",
    description="Production-grade, Application-Agnostic LLM Security & Guardrails Service",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers_and_trace(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID", f"req-{uuid.uuid4().hex[:8]}")
    request.state.request_id = req_id
    start_time = time.perf_counter()

    response = await call_next(request)

    latency_ms = (time.perf_counter() - start_time) * 1000
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Response-Time-MS"] = f"{latency_ms:.2f}"
    return response


app.include_router(health_router)
app.include_router(v1_router)

# Also expose backwards-compatible alias /v1/inspect/* for smooth migrations
from app.models.requests import CheckInputRequest, CheckOutputRequest
from app.api.v1 import pipeline


@app.post("/v1/inspect/input", include_in_schema=False)
def legacy_inspect_input(req: CheckInputRequest):
    return pipeline.inspect_input(req)


@app.post("/v1/inspect/output", include_in_schema=False)
def legacy_inspect_output(req: CheckOutputRequest):
    return pipeline.inspect_output(req)
