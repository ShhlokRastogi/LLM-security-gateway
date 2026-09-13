from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple
from app.approvals.models import ApprovalRequest, ApprovalStatus


class ApprovalManager:
    """Cryptographically-bound human approval manager preventing replay attacks and self-approvals."""

    def __init__(self, default_ttl_seconds: int = 900) -> None:
        self.default_ttl = default_ttl_seconds
        self._lock = threading.RLock()
        # Storage: client_id -> approval_id -> ApprovalRequest
        self._approvals: Dict[str, Dict[str, ApprovalRequest]] = {}

    @staticmethod
    def compute_action_hash(
        client_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> str:
        """Deterministic SHA256 binding of the exact action identity and arguments."""
        canonical_args = json.dumps(arguments, sort_keys=True, default=str)
        payload = f"{client_id}:{agent_id}:{tool_name}:{canonical_args}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def create_approval_request(
        self,
        request_id: str,
        client_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        risk_score: float = 0.5,
        risk_level: str = "HIGH",
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalRequest:
        with self._lock:
            cid = client_id or "default"
            aid = agent_id or "anonymous"
            action_hash = self.compute_action_hash(cid, aid, tool_name, arguments)
            
            now = datetime.now(timezone.utc)
            ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
            expires_at = (now + timedelta(seconds=ttl)).isoformat()

            app_id = f"appr-{uuid.uuid4().hex[:10]}"
            req = ApprovalRequest(
                approval_id=app_id,
                request_id=request_id,
                client_id=cid,
                agent_id=aid,
                tool_name=tool_name,
                arguments=arguments,
                action_hash=action_hash,
                risk_score=risk_score,
                risk_level=risk_level,
                status=ApprovalStatus.PENDING,
                created_at=now.isoformat(),
                expires_at=expires_at,
                is_used=False,
            )

            if cid not in self._approvals:
                self._approvals[cid] = {}
            self._approvals[cid][app_id] = req
            return req

    def get_approval(self, client_id: str, approval_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            cid = client_id or "default"
            if cid in self._approvals and approval_id in self._approvals[cid]:
                req = self._approvals[cid][approval_id]
                self._check_expiry(req)
                return req
            return None

    def list_approvals(self, client_id: str, status: Optional[str] = None) -> List[ApprovalRequest]:
        with self._lock:
            cid = client_id or "default"
            if cid not in self._approvals:
                return []
            res = []
            for req in self._approvals[cid].values():
                self._check_expiry(req)
                if not status or req.status.value == status.lower():
                    res.append(req)
            return sorted(res, key=lambda x: x.created_at, reverse=True)

    def approve(
        self,
        client_id: str,
        approval_id: str,
        approver_id: str,
        approver_role: str = "supervisor",
        reason: str = "",
    ) -> Tuple[bool, str, Optional[ApprovalRequest]]:
        with self._lock:
            req = self.get_approval(client_id, approval_id)
            if not req:
                return False, f"Approval request '{approval_id}' not found.", None

            # Security rule: Agent cannot approve its own action
            if approver_id == req.agent_id:
                return False, "Security violation: Autonomous agent cannot approve its own action.", req

            # Check status
            if req.status == ApprovalStatus.EXPIRED:
                return False, "Approval request has expired.", req
            if req.status == ApprovalStatus.APPROVED:
                return False, "Approval request has already been approved.", req
            if req.status == ApprovalStatus.DENIED:
                return False, "Approval request has already been denied.", req

            now = datetime.now(timezone.utc).isoformat()
            req.status = ApprovalStatus.APPROVED
            req.approver_id = approver_id
            req.approver_role = approver_role
            req.decided_at = now
            req.decision_reason = reason or "Authorized by human supervisor"
            return True, "Action approved successfully.", req

    def deny(
        self,
        client_id: str,
        approval_id: str,
        approver_id: str,
        reason: str = "",
    ) -> Tuple[bool, str, Optional[ApprovalRequest]]:
        with self._lock:
            req = self.get_approval(client_id, approval_id)
            if not req:
                return False, f"Approval request '{approval_id}' not found.", None

            now = datetime.now(timezone.utc).isoformat()
            req.status = ApprovalStatus.DENIED
            req.approver_id = approver_id
            req.decided_at = now
            req.decision_reason = reason or "Denied by human supervisor"
            return True, "Action denied.", req

    def consume_approval(
        self,
        client_id: str,
        approval_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Validates approval token, ensures cryptographic action binding, and consumes it (replay prevention)."""
        with self._lock:
            req = self.get_approval(client_id, approval_id)
            if not req:
                return False, f"Approval '{approval_id}' not found."

            if req.status != ApprovalStatus.APPROVED:
                return False, f"Approval '{approval_id}' status is '{req.status.value}', not approved."

            if req.is_used:
                return False, f"Approval replay attack detected: approval '{approval_id}' has already been consumed."

            # Verify cryptographic hash of exact current arguments
            current_hash = self.compute_action_hash(client_id, agent_id, tool_name, arguments)
            if current_hash != req.action_hash:
                return False, "Approval mismatch: action arguments differ from authorized approval request."

            # Mark consumed
            req.is_used = True
            return True, "Approval valid and successfully consumed."

    def _check_expiry(self, req: ApprovalRequest) -> None:
        if req.status == ApprovalStatus.PENDING:
            exp = datetime.fromisoformat(req.expires_at)
            now = datetime.now(timezone.utc)
            if now >= exp:
                req.status = ApprovalStatus.EXPIRED


default_approval_manager = ApprovalManager()

__all__ = ["ApprovalManager", "default_approval_manager"]
