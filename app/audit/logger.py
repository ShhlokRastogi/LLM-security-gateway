from __future__ import annotations

import re
import threading
import uuid
from typing import Dict, List, Optional
from app.audit.models import AuditEvent


class AuditLogger:
    """Multi-tenant, PII-scrubbed audit logger suitable for SIEM, database, and compliance auditing."""

    PII_SCRUBBERS = [
        (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[REDACTED_EMAIL]"),
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
        (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED_CARD]"),
    ]

    def __init__(self, max_events_per_tenant: int = 1000) -> None:
        self._lock = threading.RLock()
        self.max_events = max_events_per_tenant
        # Storage: client_id -> list of AuditEvents
        self._events: Dict[str, List[AuditEvent]] = {}

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            cid = event.client_id or "default"
            if not event.event_id:
                event.event_id = f"aud-{uuid.uuid4().hex[:10]}"

            # Scrub sensitive arguments
            if event.arguments:
                event.arguments = self._sanitize_dict(event.arguments)

            if cid not in self._events:
                self._events[cid] = []

            self._events[cid].append(event)
            # Enforce max buffer size
            if len(self._events[cid]) > self.max_events:
                self._events[cid].pop(0)

            return event

    def query(
        self,
        client_id: str,
        limit: int = 50,
        event_type: Optional[str] = None,
    ) -> List[AuditEvent]:
        with self._lock:
            cid = client_id or "default"
            if cid not in self._events:
                return []
            events = self._events[cid]
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def _sanitize_dict(self, d: dict) -> dict:
        clean = {}
        for k, v in d.items():
            if isinstance(v, str):
                s = v
                for pat, rep in self.PII_SCRUBBERS:
                    s = pat.sub(rep, s)
                clean[k] = s
            elif isinstance(v, dict):
                clean[k] = self._sanitize_dict(v)
            else:
                clean[k] = v
        return clean


default_audit_logger = AuditLogger()

__all__ = ["AuditLogger", "default_audit_logger"]
