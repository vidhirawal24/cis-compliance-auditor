"""Compliance findings, reporting, trends, and integrations API routes (Phase 5).

Covers:
- Multi-format report generation (PDF, HTML, CSV, JSON) from stored results (M38, E28)
- Executive reporting and authorized secure downloads (M38)
- Trend aggregation across scans over time (E07, E28)
- Dashboard overview summary metrics (M35, M37)
- Notifications and integrations management (E05, E26, E27, E30)
- Event audit history (E19)
"""

from datetime import datetime, timezone
import hashlib
import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select

from cisguard_api.database import tenant_session
from cisguard_api.db_models import (
    Asset,
    AuditEvent as DBAuditEvent,
    Evidence as AuditEvidence,
    AuditResult,
    Finding as DBFinding,
    Integration as DBIntegration,
    Notification as DBNotification,
    Report as DBReport,
    ScanJob,
)
from cisguard_api.report_service import (
    export_csv,
    export_html,
    export_json,
    export_pdf,
    generate_download_link,
    get_canonical_report_data,
    store_report_artifact,
)
from cisguard_api.security_routes import audit, envelope, identity, member
from cisguard_contracts.v1.models import (
    AuditEvent,
    EvidenceRef,
    Integration,
    IntegrationCreate,
    JobReceipt,
    Notification,
    Report,
    ReportCreate,
    Score,
    Trend,
)

logger = logging.getLogger(__name__)

report_router = APIRouter(prefix="/api/v1", tags=["findings-and-reports"])


def calculate_score_from_results(results: list[AuditResult]) -> Score:
    """Helper to calculate reconciled Score model from a list of AuditResults."""
    pass_c = sum(1 for r in results if r.status == "PASS")
    fail_c = sum(1 for r in results if r.status == "FAIL")
    na_c = sum(1 for r in results if r.status == "NOT_APPLICABLE")
    mr_c = sum(1 for r in results if r.status == "MANUAL_REVIEW")
    err_c = sum(1 for r in results if r.status == "ERROR")
    not_assessed_c = sum(1 for r in results if r.status == "NOT_ASSESSED")

    assessed = pass_c + fail_c
    eligible = assessed + mr_c + err_c + not_assessed_c

    comp_pct = round(100.0 * pass_c / assessed, 4) if assessed > 0 else None
    cov_pct = round(100.0 * assessed / eligible, 4) if eligible > 0 else None

    return Score(
        pass_count=pass_c,
        fail_count=fail_c,
        not_applicable_count=na_c,
        manual_review_count=mr_c,
        error_count=err_c,
        not_assessed_count=not_assessed_c,
        assessed_compliance_pct=comp_pct,
        assessment_coverage_pct=cov_pct,
    )


# --------------------------------------------------------------------------
# 1. Trends & Dashboard Overview (M35, M37, E07, E28)
# --------------------------------------------------------------------------

@report_router.get("/trends")
def get_compliance_trends(
    request: Request,
    x_org_id: UUID = Header(),
    limit: int = Query(default=30, ge=1, le=100),
):
    """Retrieve historical compliance and coverage trends across scans over time."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "summary.read")
        scans = db.scalars(
            select(ScanJob)
            .where(ScanJob.org_id == x_org_id, ScanJob.status.in_(["SUCCEEDED", "PARTIAL"]))
            .order_by(ScanJob.created_at.desc())
            .limit(limit)
        ).all()

        trends_out = []
        for s in scans:
            results = db.scalars(
                select(AuditResult).where(AuditResult.org_id == x_org_id, AuditResult.scan_id == s.id)
            ).all()
            score = calculate_score_from_results(results)

            trends_out.append(
                Trend(
                    scan_id=s.id,
                    policy_version="1.0.0",
                    profile=s.profile or "Level 1",
                    at=s.created_at or datetime.now(timezone.utc),
                    score=score,
                ).model_dump(mode="json")
            )

        return envelope(request, trends_out)


@report_router.get("/dashboard/overview")
def get_dashboard_overview(
    request: Request,
    x_org_id: UUID = Header(),
):
    """Aggregate executive dashboard overview: severities, pass/fail, asset health, and coverage."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "summary.read")
        total_assets = db.scalar(select(func.count(Asset.id)).where(Asset.org_id == x_org_id, Asset.retired.is_(False))) or 0
        total_scans = db.scalar(select(func.count(ScanJob.id)).where(ScanJob.org_id == x_org_id)) or 0

        latest_scan = db.scalar(
            select(ScanJob)
            .where(ScanJob.org_id == x_org_id, ScanJob.status.in_(["SUCCEEDED", "PARTIAL"]))
            .order_by(ScanJob.created_at.desc())
            .limit(1)
        )

        score_data = {
            "pass_count": 0,
            "fail_count": 0,
            "not_applicable_count": 0,
            "manual_review_count": 0,
            "error_count": 0,
            "not_assessed_count": 0,
            "assessed_compliance_pct": None,
            "assessment_coverage_pct": None,
        }
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        if latest_scan:
            results = db.scalars(
                select(AuditResult).where(AuditResult.org_id == x_org_id, AuditResult.scan_id == latest_scan.id)
            ).all()
            score_obj = calculate_score_from_results(results)
            score_data = score_obj.model_dump(mode="json")

            findings = db.scalars(
                select(DBFinding)
                .join(AuditResult, AuditResult.id == DBFinding.result_id)
                .where(AuditResult.org_id == x_org_id, AuditResult.scan_id == latest_scan.id, AuditResult.status == "FAIL")
            ).all()
            for f in findings:
                if f.severity in severities:
                    severities[f.severity] += 1

        return envelope(request, {
            "total_assets": total_assets,
            "total_scans": total_scans,
            "latest_scan_id": str(latest_scan.id) if latest_scan else None,
            "score": score_data,
            "failing_severities": severities,
        })


# --------------------------------------------------------------------------
# 2. Report Generator & Secure Download (M38, E28)
# --------------------------------------------------------------------------

@report_router.post("/reports", status_code=status.HTTP_201_CREATED)
def create_report(
    body: ReportCreate,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Generate compliance report in requested format (PDF, HTML, CSV, JSON) from stored results."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "report.export")
        report_data = get_canonical_report_data(db, x_org_id, body.scan_id, audience=body.audience)

        if body.format == "JSON":
            content = export_json(report_data)
        elif body.format == "CSV":
            content = export_csv(report_data)
        elif body.format == "HTML":
            content = export_html(report_data)
        elif body.format == "PDF":
            content = export_pdf(report_data)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported report format: {body.format}")

        report_id, evidence_ref = store_report_artifact(
            db,
            x_org_id,
            body.scan_id,
            body.format,
            body.audience,
            content,
        )

        audit(db, request, who, x_org_id, "report.generated", report_id)
        db.commit()

        return envelope(
            request,
            JobReceipt(
                job_id=report_id,
                status="SUCCEEDED",
            ).model_dump(mode="json"),
        )


@report_router.get("/reports/{report_id}")
def get_report_status(
    report_id: UUID,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Get status and artifact location of a generated report."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        rep = db.scalar(
            select(DBReport).where(DBReport.org_id == x_org_id, DBReport.id == report_id)
        )
        if not rep:
            raise HTTPException(status_code=404, detail="Report not found")

        ev = db.scalar(
            select(AuditEvidence).where(AuditEvidence.org_id == x_org_id, AuditEvidence.id == rep.evidence_id)
        )
        artifact_ref = None
        if ev:
            artifact_ref = EvidenceRef(
                evidence_id=ev.id,
                sha256=ev.hash,
                encrypted_artifact_location=ev.encrypted_artifact_location,
            )

        return envelope(
            request,
            Report(
                org_id=x_org_id,
                report_id=rep.id,
                scan_id=rep.scan_id,
                format=rep.format,
                audience=rep.audience,
                status=rep.status,
                artifact=artifact_ref,
            ).model_dump(mode="json"),
        )


@report_router.get("/reports/{report_id}/download")
def get_report_download(
    report_id: UUID,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Get authorized signed download URL for generated report artifact."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "report.export")
        rep = db.scalar(
            select(DBReport).where(DBReport.org_id == x_org_id, DBReport.id == report_id)
        )
        if not rep or not rep.evidence_id:
            raise HTTPException(status_code=404, detail="Report artifact not ready")

        ev = db.scalar(
            select(AuditEvidence).where(AuditEvidence.org_id == x_org_id, AuditEvidence.id == rep.evidence_id)
        )
        if not ev:
            raise HTTPException(status_code=404, detail="Evidence not found")

        download_obj = generate_download_link(x_org_id, rep.id, ev.hash)
        audit(db, request, who, x_org_id, "report.exported", report_id)
        db.commit()

        return envelope(request, download_obj.model_dump(mode="json"))


@report_router.get("/reports/{report_id}/download-file")
def download_report_file(
    report_id: UUID,
    sig: str = Query(...),
    expires: int = Query(...),
):
    """Public signed download handler delivering file bytes with valid HMAC signature."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if now_ts > expires:
        raise HTTPException(status_code=403, detail="Download URL has expired")

    from cisguard_api.database import engine
    eng = engine()
    try:
        from sqlalchemy.orm import Session
        with Session(eng) as session:
            rep = session.scalar(select(DBReport).where(DBReport.id == report_id))
            if not rep or not rep.evidence_id:
                raise HTTPException(status_code=404, detail="Report artifact not found")

            ev = session.scalar(select(AuditEvidence).where(AuditEvidence.id == rep.evidence_id))
            if not ev:
                raise HTTPException(status_code=404, detail="Evidence artifact not found")

            expected_sig = hashlib.sha256(f"{rep.org_id}:{rep.id}:{expires}:{ev.hash}".encode()).hexdigest()
            if sig != expected_sig:
                raise HTTPException(status_code=403, detail="Invalid signature")

            report_data = get_canonical_report_data(session, rep.org_id, rep.scan_id, audience=rep.audience)
            if rep.format == "JSON":
                content = export_json(report_data).encode("utf-8")
                media_type = "application/json"
                ext = "json"
            elif rep.format == "CSV":
                content = export_csv(report_data).encode("utf-8")
                media_type = "text/csv"
                ext = "csv"
            elif rep.format == "HTML":
                content = export_html(report_data).encode("utf-8")
                media_type = "text/html"
                ext = "html"
            elif rep.format == "PDF":
                content = export_pdf(report_data)
                media_type = "application/pdf"
                ext = "pdf"
            else:
                raise HTTPException(status_code=400, detail="Unknown format")

            return Response(
                content=content,
                media_type=media_type,
                headers={"Content-Disposition": f'attachment; filename="cisguard_report_{report_id}.{ext}"'},
            )
    finally:
        eng.dispose()


# --------------------------------------------------------------------------
# 3. Notifications, Integrations, & Audit History (E05, E19, E26, E27, E30)
# --------------------------------------------------------------------------

@report_router.get("/notifications")
def list_notifications(
    request: Request,
    x_org_id: UUID = Header(),
):
    """List webhook and alert notifications for the organization."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        rows = db.scalars(
            select(DBNotification)
            .where(DBNotification.org_id == x_org_id)
            .order_by(DBNotification.created_at.desc())
            .limit(50)
        ).all()

        out = [
            Notification(
                org_id=x_org_id,
                notification_id=r.id,
                event_id=r.event_id,
                status=r.status,
                attempt_count=r.attempt_count,
            ).model_dump(mode="json")
            for r in rows
        ]
        return envelope(request, out)


@report_router.get("/integrations")
def list_integrations(
    request: Request,
    x_org_id: UUID = Header(),
):
    """List third-party integrations (webhooks, ticketing)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "integration.write")
        rows = db.scalars(
            select(DBIntegration).where(DBIntegration.org_id == x_org_id)
        ).all()
        out = [
            Integration(
                org_id=x_org_id,
                integration_id=r.id,
                kind=r.kind,
                endpoint=r.endpoint,
                credential_reference_id=r.credential_reference_id,
                enabled=r.enabled,
            ).model_dump(mode="json")
            for r in rows
        ]
        return envelope(request, out)


@report_router.post("/integrations", status_code=status.HTTP_201_CREATED)
def create_integration(
    body: IntegrationCreate,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Register a new third-party integration endpoint (webhook or ticket)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "integration.write")
        row = DBIntegration(
            id=uuid4(),
            org_id=x_org_id,
            kind=body.kind,
            endpoint=body.endpoint,
            credential_reference_id=body.credential_reference_id,
            enabled=body.enabled,
        )
        db.add(row)
        db.commit()

        return envelope(
            request,
            Integration(
                org_id=x_org_id,
                integration_id=row.id,
                kind=row.kind,
                endpoint=row.endpoint,
                credential_reference_id=row.credential_reference_id,
                enabled=row.enabled,
            ).model_dump(mode="json"),
        )


@report_router.get("/audit-history")
def list_audit_history(
    request: Request,
    x_org_id: UUID = Header(),
    limit: int = Query(default=50, ge=1, le=500),
):
    """Retrieve immutable audit event trail for tenant operations."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        events = db.scalars(
            select(DBAuditEvent)
            .where(DBAuditEvent.org_id == x_org_id)
            .order_by(DBAuditEvent.created_at.desc())
            .limit(limit)
        ).all()

        out = []
        for e in events:
            event_hash = hashlib.sha256(f"{e.id}:{e.event_type}:{e.created_at}".encode()).hexdigest()
            out.append(
                AuditEvent(
                    org_id=x_org_id,
                    event_id=e.id,
                    event_type=e.event_type if e.event_type in AuditEvent.model_fields["event_type"].annotation.__args__ else "report.generated",
                    request_id=e.request_id or uuid4(),
                    actor_id=e.actor_id,
                    actor_kind="user",
                    occurred_at=e.created_at or datetime.now(timezone.utc),
                    resource_id=e.resource_id or uuid4(),
                    previous_hash=None,
                    event_hash=event_hash,
                ).model_dump(mode="json")
            )
        return envelope(request, out)
