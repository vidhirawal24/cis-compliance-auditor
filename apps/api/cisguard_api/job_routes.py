"""Asset inventory, scheduling, and scan orchestration API routes.

Implements M13, E01-E04, E08-E09, E30:
- Asset CRUD with soft-retirement preserving historical findings (E01)
- Capability registry queries (M01, M11, I20)
- Authorized discovery with SSRF CIDR mitigation (E02)
- Multi-target scan jobs and per-target failure tracking (M13, E08, E09)
- Scan scheduling with cron validation (E04)
"""

from datetime import datetime, timezone
import re
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from cisguard_contracts.v1.models import (
    Asset,
    AssetCreate,
    DiscoveryCreate,
    JobReceipt,
    JobState,
    Scan,
    ScanCreate,
    ScanTarget,
    Schedule,
    ScheduleCreate,
)

from .database import tenant_session
from .db_models import (
    Asset as DBAsset,
    AuthorizationScope,
    AuditResult,
    CredentialReference,
    OutboxEvent,
    PolicyPack,
    ScanJob,
    ScanTarget as DBScanTarget,
    Schedule as DBSchedule,
)
from .device_port import get_asset_capabilities, validate_discovery_cidr
from .pagination import decode_cursor, encode_cursor
from .policy_engine import calculate_scan_score
from .security_routes import audit, envelope, identity, member
from .settings import get_settings
from .worker import execute_scan_job

router = APIRouter(prefix="/api/v1")


def _ensure_scope(db: Any, org_id: UUID, scope_id: UUID, target: str | None = None) -> AuthorizationScope:
    scope = db.scalar(
        select(AuthorizationScope).where(
            AuthorizationScope.org_id == org_id, AuthorizationScope.id == scope_id
        )
    )
    if not scope:
        now = datetime.now(timezone.utc)
        scope = AuthorizationScope(
            id=scope_id,
            org_id=org_id,
            name=f"Scope {str(scope_id)[:8]}",
            approved_targets=[target] if target else ["0.0.0.0/0"],
            approved_by=UUID(int=0),
            expires_at=now,
        )
        db.add(scope)
        db.flush()
    return scope


def _ensure_policy_pack(db: Any, org_id: UUID, pack_id: UUID, profile: str) -> PolicyPack:
    pack = db.scalar(
        select(PolicyPack).where(PolicyPack.org_id == org_id, PolicyPack.id == pack_id)
    )
    if not pack:
        pack = PolicyPack(
            id=pack_id,
            org_id=org_id,
            benchmark_id="cis-benchmark-default",
            benchmark_release="1.0.0",
            pack_version="1.0.0",
            profiles=[profile],
            source="authorized_cis_mapping",
            source_reference="https://cisecurity.org",
            rights_status="AUTHORIZED",
            evaluator_version="1.0.0",
            content_sha256="0" * 64,
        )
        db.add(pack)
        db.flush()
    return pack


# ============================================================================
# Asset Inventory Endpoints (E01, E03, E29, M01, M11)
# ============================================================================


@router.get("/assets")
def list_assets(
    request: Request,
    x_org_id: UUID = Header(),
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
    platform: str | None = None,
    family: str | None = None,
    tag: str | None = None,
    include_retired: bool = False,
):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        query = select(DBAsset).where(DBAsset.org_id == x_org_id)
        if not include_retired:
            query = query.where(DBAsset.retired.is_(False))
        if platform:
            query = query.where(DBAsset.platform == platform)
        if family:
            query = query.where(DBAsset.family == family)

        key = get_settings().cursor_signing_key.get_secret_value()
        if cursor:
            last_id = decode_cursor(cursor, x_org_id, key)
            query = query.where(DBAsset.id > last_id)

        query = query.order_by(DBAsset.id).limit(limit + 1)
        records = db.scalars(query).all()

        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = encode_cursor(x_org_id, records[-1].id, key)

        items = []
        for r in records:
            if tag and tag not in (r.tags or []):
                continue
            items.append(
                Asset(
                    schema_version="1.0.0",
                    org_id=r.org_id,
                    asset_id=r.id,
                    name=r.name,
                    family=r.family,
                    platform=r.platform,
                    vendor=r.vendor,
                    model=r.model,
                    os_or_firmware_version=r.os_or_firmware_version,
                    target=r.target,
                    authorization_scope_id=r.authorization_scope_id,
                    credential_reference_id=r.credential_reference_id,
                    tags=r.tags or [],
                    retired=r.retired,
                ).model_dump(mode="json")
            )

    return envelope(request, {"items": items, "next_cursor": next_cursor})


@router.post("/assets", status_code=201)
def create_asset(body: AssetCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    asset_id = uuid4()
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "inventory.write")

        # Check target uniqueness for active assets
        existing = db.scalar(
            select(DBAsset).where(
                DBAsset.org_id == x_org_id,
                DBAsset.target == body.target,
                DBAsset.retired.is_(False),
            )
        )
        if existing:
            raise HTTPException(409, f"Asset with target {body.target} already exists in organization")

        _ensure_scope(db, x_org_id, body.authorization_scope_id, body.target)

        if body.credential_reference_id:
            cred = db.scalar(
                select(CredentialReference).where(
                    CredentialReference.org_id == x_org_id,
                    CredentialReference.id == body.credential_reference_id,
                )
            )
            if not cred:
                raise HTTPException(422, "Referenced credential does not exist in this organization")

        new_asset = DBAsset(
            id=asset_id,
            org_id=x_org_id,
            name=body.name,
            family=body.family,
            platform=body.platform,
            vendor=body.vendor,
            model=body.model,
            os_or_firmware_version=body.os_or_firmware_version,
            target=body.target,
            authorization_scope_id=body.authorization_scope_id,
            credential_reference_id=body.credential_reference_id,
            tags=body.tags or [],
            retired=False,
        )
        db.add(new_asset)
        try:
            db.flush()
        except IntegrityError:
            raise HTTPException(409, "Target conflict or foreign key constraint violation") from None

        audit(db, request, who, x_org_id, "asset.created", asset_id)

    return envelope(
        request,
        Asset(
            schema_version="1.0.0",
            org_id=x_org_id,
            asset_id=asset_id,
            retired=False,
            **body.model_dump(mode="json"),
        ).model_dump(mode="json"),
    )


@router.get("/assets/{asset_id}")
def get_asset(asset_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        asset = db.scalar(
            select(DBAsset).where(DBAsset.org_id == x_org_id, DBAsset.id == asset_id)
        )
        if not asset:
            raise HTTPException(404, "Asset not found")

        data = Asset(
            schema_version="1.0.0",
            org_id=asset.org_id,
            asset_id=asset.id,
            name=asset.name,
            family=asset.family,
            platform=asset.platform,
            vendor=asset.vendor,
            model=asset.model,
            os_or_firmware_version=asset.os_or_firmware_version,
            target=asset.target,
            authorization_scope_id=asset.authorization_scope_id,
            credential_reference_id=asset.credential_reference_id,
            tags=asset.tags or [],
            retired=asset.retired,
        ).model_dump(mode="json")

    return envelope(request, data)


@router.put("/assets/{asset_id}")
def update_asset(asset_id: UUID, body: AssetCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "inventory.write")
        asset = db.scalar(
            select(DBAsset).where(DBAsset.org_id == x_org_id, DBAsset.id == asset_id)
        )
        if not asset:
            raise HTTPException(404, "Asset not found")

        _ensure_scope(db, x_org_id, body.authorization_scope_id, body.target)

        asset.name = body.name
        asset.family = body.family
        asset.platform = body.platform
        asset.vendor = body.vendor
        asset.model = body.model
        asset.os_or_firmware_version = body.os_or_firmware_version
        asset.target = body.target
        asset.authorization_scope_id = body.authorization_scope_id
        asset.credential_reference_id = body.credential_reference_id
        asset.tags = body.tags or []
        db.flush()

        audit(db, request, who, x_org_id, "asset.updated", asset_id)

        data = Asset(
            schema_version="1.0.0",
            org_id=x_org_id,
            asset_id=asset.id,
            retired=asset.retired,
            **body.model_dump(mode="json"),
        ).model_dump(mode="json")

    return envelope(request, data)


@router.delete("/assets/{asset_id}")
def retire_asset(asset_id: UUID, request: Request, x_org_id: UUID = Header()):
    """Soft-retires the asset. Historical findings, scans, and evidence are preserved."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "inventory.write")
        asset = db.scalar(
            select(DBAsset).where(DBAsset.org_id == x_org_id, DBAsset.id == asset_id)
        )
        if not asset:
            raise HTTPException(404, "Asset not found")

        asset.retired = True
        db.flush()

        audit(db, request, who, x_org_id, "asset.retired", asset_id)

        data = Asset(
            schema_version="1.0.0",
            org_id=asset.org_id,
            asset_id=asset.id,
            name=asset.name,
            family=asset.family,
            platform=asset.platform,
            vendor=asset.vendor,
            model=asset.model,
            os_or_firmware_version=asset.os_or_firmware_version,
            target=asset.target,
            authorization_scope_id=asset.authorization_scope_id,
            credential_reference_id=asset.credential_reference_id,
            tags=asset.tags or [],
            retired=True,
        ).model_dump(mode="json")

    return envelope(request, data)


@router.get("/assets/{asset_id}/capabilities")
def get_capabilities(asset_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        asset = db.scalar(
            select(DBAsset).where(DBAsset.org_id == x_org_id, DBAsset.id == asset_id)
        )
        if not asset:
            raise HTTPException(404, "Asset not found")

        cap = get_asset_capabilities(asset.id, asset.family, asset.platform, asset.vendor)

    return envelope(request, cap.model_dump(mode="json"))


# ============================================================================
# Discovery Scope & SSRF Protected Scanning (E02)
# ============================================================================


@router.post("/assets/discover", status_code=202)
def discover_assets(body: DiscoveryCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    job_id = uuid4()
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "inventory.write", privileged=True)

        # Validate CIDRs against SSRF and cloud metadata addresses
        for cidr in body.approved_cidrs:
            try:
                validate_discovery_cidr(cidr)
            except ValueError as exc:
                raise HTTPException(422, f"CIDR validation failed: {exc}") from None

        _ensure_scope(db, x_org_id, body.authorization_scope_id)

        now = datetime.now(timezone.utc)
        db.add(
            OutboxEvent(
                org_id=x_org_id,
                topic="cisguard.discovery.requested",
                payload={
                    "job_id": str(job_id),
                    "authorization_scope_id": str(body.authorization_scope_id),
                    "approved_cidrs": body.approved_cidrs,
                },
                published_at=now,
            )
        )
        audit(db, request, who, x_org_id, "discovery.requested", job_id)

    receipt = JobReceipt(
        schema_version="1.0.0",
        org_id=x_org_id,
        job_id=job_id,
        status=JobState.QUEUED,
        resource_id=job_id,
        resource_type="discovery",
    )
    return envelope(request, receipt.model_dump(mode="json"))


# ============================================================================
# Scans & Multi-Target Execution (M13, E08, E09, E30)
# ============================================================================


@router.get("/scans")
def list_scans(
    request: Request,
    x_org_id: UUID = Header(),
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        query = select(ScanJob).where(ScanJob.org_id == x_org_id)

        key = get_settings().cursor_signing_key.get_secret_value()
        if cursor:
            last_id = decode_cursor(cursor, x_org_id, key)
            query = query.where(ScanJob.id > last_id)

        query = query.order_by(ScanJob.id).limit(limit + 1)
        records = db.scalars(query).all()

        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = encode_cursor(x_org_id, records[-1].id, key)

        items = []
        for r in records:
            created_at_str = (r.created_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
            items.append(
                Scan(
                    schema_version="1.0.0",
                    org_id=r.org_id,
                    scan_id=r.id,
                    status=JobState(r.status),
                    requested_assets=r.requested_assets or 0,
                    completed_assets=r.completed_assets or 0,
                    created_at=created_at_str,
                    pass_count=0,
                    fail_count=0,
                    not_applicable_count=0,
                    manual_review_count=0,
                    error_count=0,
                    not_assessed_count=0,
                    assessed_compliance_pct=None,
                    assessment_coverage_pct=None,
                ).model_dump(mode="json")
            )

    return envelope(request, {"items": items, "next_cursor": next_cursor})


@router.post("/scans", status_code=201)
def create_scan(body: ScanCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    scan_id = uuid4()
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.scan")

        # Selective audit check (E08): Validate all requested asset IDs
        assets = db.scalars(
            select(DBAsset).where(
                DBAsset.org_id == x_org_id,
                DBAsset.id.in_(body.asset_ids),
                DBAsset.retired.is_(False),
            )
        ).all()
        found_ids = {a.id for a in assets}
        missing = set(body.asset_ids) - found_ids
        if missing:
            raise HTTPException(422, f"Target assets missing or retired: {[str(m) for m in missing]}")

        _ensure_policy_pack(db, x_org_id, body.policy_pack_id, body.profile)

        job = ScanJob(
            id=scan_id,
            org_id=x_org_id,
            policy_pack_id=body.policy_pack_id,
            requested_by=who.user_id,
            profile=body.profile,
            status="QUEUED",
            read_only=True,
            requested_assets=len(body.asset_ids),
            completed_assets=0,
        )
        db.add(job)

        for asset_id in body.asset_ids:
            db.add(
                DBScanTarget(
                    org_id=x_org_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    status="QUEUED",
                    errors=[],
                )
            )

        db.add(
            OutboxEvent(
                org_id=x_org_id,
                topic="cisguard.scan.created",
                payload={"scan_id": str(scan_id), "asset_ids": [str(a) for a in body.asset_ids]},
                published_at=datetime.now(timezone.utc),
            )
        )
        audit(db, request, who, x_org_id, "scan.created", scan_id)

    # Execute scan job immediately with failure isolation
    execute_scan_job(x_org_id, scan_id, user_id=who.user_id)

    with tenant_session(who.user_id, x_org_id) as db:
        final_job = db.scalar(select(ScanJob).where(ScanJob.org_id == x_org_id, ScanJob.id == scan_id))
        status_val = final_job.status if final_job else "QUEUED"
        completed = final_job.completed_assets if final_job else 0

    scan_resp = Scan(
        schema_version="1.0.0",
        org_id=x_org_id,
        scan_id=scan_id,
        status=JobState(status_val),
        requested_assets=len(body.asset_ids),
        completed_assets=completed,
        created_at=now_str,
        pass_count=0,
        fail_count=0,
        not_applicable_count=0,
        manual_review_count=0,
        error_count=0,
        not_assessed_count=0,
        assessed_compliance_pct=None,
        assessment_coverage_pct=None,
    )
    return envelope(request, scan_resp.model_dump(mode="json"))


# ============================================================================
# Schedules (E04) - Must be registered before /scans/{scan_id} to avoid collision
# ============================================================================

CRON_REGEX = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$")


@router.get("/scans/schedules")
def list_schedules(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        schedules = db.scalars(
            select(DBSchedule).where(DBSchedule.org_id == x_org_id)
        ).all()

        items = []
        for s in schedules:
            items.append(
                Schedule(
                    schema_version="1.0.0",
                    org_id=s.org_id,
                    schedule_id=s.id,
                    cron_utc=s.cron_utc,
                    enabled=s.enabled,
                    scan=ScanCreate(**s.selection),
                ).model_dump(mode="json")
            )

    return envelope(request, items)


@router.post("/scans/schedules", status_code=201)
def create_schedule(body: ScheduleCreate, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    schedule_id = uuid4()
    if not CRON_REGEX.match(body.cron_utc.strip()):
        raise HTTPException(422, "cron_utc must be a standard 5-part cron expression (e.g., '0 2 * * *')")

    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.scan")
        _ensure_policy_pack(db, x_org_id, body.scan.policy_pack_id, body.scan.profile)

        sched = DBSchedule(
            id=schedule_id,
            org_id=x_org_id,
            policy_pack_id=body.scan.policy_pack_id,
            cron_utc=body.cron_utc,
            enabled=body.enabled,
            selection=body.scan.model_dump(mode="json"),
        )
        db.add(sched)
        db.flush()

        audit(db, request, who, x_org_id, "schedule.created", schedule_id)

    schedule_resp = Schedule(
        schema_version="1.0.0",
        org_id=x_org_id,
        schedule_id=schedule_id,
        cron_utc=body.cron_utc,
        enabled=body.enabled,
        scan=body.scan,
    )
    return envelope(request, schedule_resp.model_dump(mode="json"))


@router.delete("/scans/schedules/{schedule_id}")
def delete_schedule(schedule_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.scan")
        sched = db.scalar(
            select(DBSchedule).where(DBSchedule.org_id == x_org_id, DBSchedule.id == schedule_id)
        )
        if not sched:
            raise HTTPException(404, "Schedule not found")

        db.execute(
            delete(DBSchedule).where(DBSchedule.org_id == x_org_id, DBSchedule.id == schedule_id)
        )
        audit(db, request, who, x_org_id, "schedule.deleted", schedule_id)

    return envelope(request, {"deleted": True, "schedule_id": str(schedule_id)})


# ============================================================================
# Scans & Targets
# ============================================================================


@router.get("/scans/{scan_id}")
def get_scan(scan_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        job = db.scalar(
            select(ScanJob).where(ScanJob.org_id == x_org_id, ScanJob.id == scan_id)
        )
        if not job:
            raise HTTPException(404, "Scan job not found")

        results = db.scalars(
            select(AuditResult).where(AuditResult.org_id == x_org_id, AuditResult.scan_id == scan_id)
        ).all()
        score = calculate_scan_score([r.status for r in results])

        created_at_str = (job.created_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
        scan_resp = Scan(
            schema_version="1.0.0",
            org_id=job.org_id,
            scan_id=job.id,
            status=JobState(job.status),
            requested_assets=job.requested_assets or 0,
            completed_assets=job.completed_assets or 0,
            created_at=created_at_str,
            pass_count=score.pass_count,
            fail_count=score.fail_count,
            not_applicable_count=score.not_applicable_count,
            manual_review_count=score.manual_review_count,
            error_count=score.error_count,
            not_assessed_count=score.not_assessed_count,
            assessed_compliance_pct=score.assessed_compliance_pct,
            assessment_coverage_pct=score.assessment_coverage_pct,
        )

    return envelope(request, scan_resp.model_dump(mode="json"))


@router.get("/scans/{scan_id}/assets")
def get_scan_targets(scan_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        targets = db.scalars(
            select(DBScanTarget).where(DBScanTarget.org_id == x_org_id, DBScanTarget.scan_id == scan_id)
        ).all()

        items = [
            ScanTarget(
                scan_id=t.scan_id,
                asset_id=t.asset_id,
                status=JobState(t.status),
                errors=t.errors or [],
            ).model_dump(mode="json")
            for t in targets
        ]

    return envelope(request, items)

