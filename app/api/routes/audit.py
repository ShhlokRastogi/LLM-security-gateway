from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Header, Query

from app.api.dependencies import audit_logger, get_client_id
from app.audit.models import AuditEventsQueryResponse

router = APIRouter(tags=["Audit"])


@router.get("/audit/events", response_model=AuditEventsQueryResponse)
def query_audit_events_endpoint(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    x_client_id: Optional[str] = Header(None),
):
    """Query tenant-isolated, PII-scrubbed security audit records."""
    cid = get_client_id(x_client_id)
    events = audit_logger.query(cid, limit=limit, event_type=event_type)
    return AuditEventsQueryResponse(events=events, count=len(events), client_id=cid)
