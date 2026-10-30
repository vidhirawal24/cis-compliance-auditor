"""Notification, webhook dispatcher, and ticketing adapter service for CISGuard 360 (Phase 5).

Covers:
- Webhook dispatcher with HMAC-SHA256 payload signing, retry backoff, and delivery deduplication (E26, E27)
- Abstract TicketAdapter interface with Jira, ServiceNow, and generic implementations (E28)
- Notification status recording in cisguard.notifications
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any
from uuid import UUID, uuid4


from cisguard_api.db_models import Notification as DBNotification

logger = logging.getLogger(__name__)


class WebhookDispatcher:
    """Dispatches webhook payloads with cryptographic signatures, dedup IDs, and exponential backoff retry logic."""

    @staticmethod
    def sign_payload(secret: str, payload_bytes: bytes) -> str:
        """Generate HMAC-SHA256 signature for webhook payload."""
        return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def calculate_backoff(attempt: int, base_seconds: int = 2, max_seconds: int = 300) -> int:
        """Calculate exponential backoff seconds: min(max_seconds, base_seconds ** attempt)."""
        return min(max_seconds, base_seconds ** max(1, attempt))

    @staticmethod
    def prepare_delivery(
        event_type: str,
        payload: dict[str, Any],
        secret: str,
        delivery_id: UUID | None = None,
        attempt: int = 1,
    ) -> tuple[dict[str, str], bytes]:
        """Prepare HTTP headers and signed serialized payload for delivery."""
        if delivery_id is None:
            delivery_id = uuid4()

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = WebhookDispatcher.sign_payload(secret, payload_bytes)
        backoff = WebhookDispatcher.calculate_backoff(attempt)

        headers = {
            "Content-Type": "application/json",
            "X-CISGuard-Event": event_type,
            "X-CISGuard-Delivery-Id": str(delivery_id),
            "X-CISGuard-Signature": f"sha256={signature}",
            "X-CISGuard-Attempt": str(attempt),
            "X-CISGuard-Retry-After": str(backoff),
        }
        return headers, payload_bytes

    @staticmethod
    def record_notification(
        db,
        org_id: UUID,
        event_id: UUID,
        status: str = "PENDING",
        attempt_count: int = 0,
    ) -> DBNotification:
        """Record notification attempt in cisguard.notifications."""
        from sqlalchemy.orm import Session
        if not isinstance(db, Session):
            with Session(db, expire_on_commit=False) as session:
                res = WebhookDispatcher.record_notification(session, org_id, event_id, status, attempt_count)
                session.commit()
                return res
        notif = DBNotification(
            id=uuid4(),
            org_id=org_id,
            event_id=event_id,
            status=status,
            attempt_count=attempt_count,
        )
        db.add(notif)
        db.flush()
        return notif


class TicketAdapter(ABC):
    """Abstract interface for third-party compliance ticketing integrations (E28)."""

    @abstractmethod
    def create_ticket_payload(
        self,
        finding: dict[str, Any],
        asset: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Transform a canonical Finding into a platform-specific ticket payload."""
        pass


class JiraTicketAdapter(TicketAdapter):
    """Jira Cloud / Server ticketing integration."""

    def __init__(self, project_key: str = "SEC", default_issue_type: str = "Bug"):
        self.project_key = project_key
        self.default_issue_type = default_issue_type

    def create_ticket_payload(
        self,
        finding: dict[str, Any],
        asset: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        severity = finding.get("severity", "LOW")
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
        priority = priority_map.get(severity, "Low")

        control_id = finding.get("control_id", "UNKNOWN")
        asset_name = asset.get("name") if asset else finding.get("asset_name", "Target")
        title = finding.get("title", f"CIS Finding {control_id}")
        remediation = finding.get("remediation", "Review CIS benchmark recommendations.")
        evidence_ref = finding.get("evidence_ref", "N/A")

        summary = f"[CISGuard {control_id}] {title} on {asset_name}"
        description = (
            f"*CIS Benchmark Non-Compliance Finding*\n\n"
            f"*Control ID:* {control_id}\n"
            f"*Severity:* {severity}\n"
            f"*Status:* {finding.get('status', 'FAIL')}\n"
            f"*Asset:* {asset_name} ({asset.get('target', 'N/A') if asset else 'N/A'})\n\n"
            f"*Remediation Guidance:*\n{remediation}\n\n"
            f"*Immutable Audit Evidence Reference:*\n{evidence_ref}\n"
        )

        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.default_issue_type},
                "priority": {"name": priority},
                "labels": ["cisguard", "compliance", f"cis-{control_id}"],
            }
        }


class ServiceNowTicketAdapter(TicketAdapter):
    """ServiceNow Incident integration."""

    def __init__(self, caller_id: str = "cisguard_auditor"):
        self.caller_id = caller_id

    def create_ticket_payload(
        self,
        finding: dict[str, Any],
        asset: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        severity = finding.get("severity", "LOW")
        impact_urgency = {
            "CRITICAL": ("1", "1"),  # Critical
            "HIGH": ("1", "2"),      # High
            "MEDIUM": ("2", "2"),    # Medium
            "LOW": ("3", "3"),       # Low
        }.get(severity, ("3", "3"))

        control_id = finding.get("control_id", "UNKNOWN")
        asset_name = asset.get("name") if asset else finding.get("asset_name", "Target")

        return {
            "short_description": f"CIS Non-Compliance: {control_id} on {asset_name}",
            "comments": (
                f"Finding ID: {finding.get('finding_id')}\n"
                f"Remediation: {finding.get('remediation')}\n"
                f"Evidence: {finding.get('evidence_ref')}"
            ),
            "impact": impact_urgency[0],
            "urgency": impact_urgency[1],
            "category": "Security",
            "subcategory": "Compliance",
            "caller_id": self.caller_id,
        }


class GenericWebhookTicketAdapter(TicketAdapter):
    """Standard generic JSON ticket adapter."""

    def create_ticket_payload(
        self,
        finding: dict[str, Any],
        asset: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "ticket_type": "security_compliance_finding",
            "finding_id": finding.get("finding_id"),
            "control_id": finding.get("control_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "asset": asset or {"name": finding.get("asset_name"), "target": finding.get("asset_target")},
            "remediation": finding.get("remediation"),
            "evidence_ref": finding.get("evidence_ref"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

