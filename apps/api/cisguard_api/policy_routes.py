"""FastAPI routes for CIS benchmarks, rules, overrides, exceptions, and manual review.

Implements M16, M17, M18, M19, E11, E12, E14, E20, I19, I20:
- GET /policies: List versioned policy packs (M17, E11)
- POST /policies: Register / import policy pack (M17, M19, E20)
- GET /policies/{policy_pack_id}: Get pack details (M19)
- GET /policies/{policy_pack_id}/rules: List rules filterable by profile (M16, M17, E11)
- GET /policies/{policy_pack_id}/diff: Compute version diff (E20, I19)
- POST /policies/{policy_pack_id}/upgrade-preview: Preview upgrade across tenant assets (I19)
- POST /policies/scap-import: Secure SCAP XCCDF import with XXE mitigation (E12, supplementary)
- POST /policy-overrides: Custom baseline override creation (M18)
- GET /policy-overrides: List active policy overrides for tenant (M18)
- GET /findings: List assessed findings (M36, E29, I20)
- GET /findings/{finding_id}: Get finding details (M36, M37)
- GET /exceptions: List policy exceptions (E14)
- POST /exceptions: Request time-boxed policy exception (E14)
- POST /exceptions/{exception_id}/decision: Approve / reject exception (E14, separation of duties)
- POST /manual-reviews: Record human review verdict and evidence (E12)
- GET /scans/{scan_id}/score: Get reconciled compliance and coverage score (M17, M35)
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Header, HTTPException, Query, Request
from sqlalchemy import select

from cisguard_contracts.v1.models import (
    AssessmentStatus,
    EvidenceRef,
    ExceptionDecision,
    ExceptionOverlay,
    ExceptionRequest,
    Fact,
    Finding as WireFinding,
    ManualReview as WireManualReview,
    ManualReviewCreate,
    PolicyOverride as WirePolicyOverride,
    PolicyOverrideCreate,
    PolicyPack as WirePolicyPack,
    PolicyRule as WirePolicyRule,
)

from .database import tenant_session
from .db_models import (
    Asset,
    AuditEvent,
    AuditResult,
    Evidence,
    Finding as DBFinding,
    ManualReview as DBManualReview,
    PolicyException as DBPolicyException,
    PolicyOverride as DBPolicyOverride,
    PolicyPack as DBPolicyPack,
    PolicyRule as DBPolicyRule,
    ScanJob,
)
from .policy_engine import (
    EVALUATOR_VERSION,
    calculate_scan_score,
)
from .benchmark_service import (
    compute_benchmark_diff,
    get_builtin_policy_pack,
    install_policy_pack_in_db,
    parse_policy_pack_document,
    parse_scap_xccdf_xml,
    preview_benchmark_upgrade,
)
from .pagination import decode_cursor, encode_cursor
from .security_routes import audit, envelope, identity, member
from .settings import get_settings

logger = logging.getLogger("cisguard.policy_routes")
router = APIRouter(prefix="/api/v1")


def _ensure_default_pack_installed(db: Any, org_id: UUID) -> DBPolicyPack:
    """Ensure at least the canonical CIS Ubuntu benchmark is installed for the organization."""
    pack = db.scalar(
        select(DBPolicyPack).where(DBPolicyPack.org_id == org_id).order_by(DBPolicyPack.created_at)
    )
    if not pack:
        builtin_data = get_builtin_policy_pack("ubuntu-v1")
        pack, _ = install_policy_pack_in_db(db, org_id, builtin_data)
    return pack


# ============================================================================
# Benchmark Packs & Registry (M17, M19, E11, E20)
# ============================================================================


@router.get("/policies")
def list_policies(
    request: Request,
    x_org_id: UUID = Header(),
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        _ensure_default_pack_installed(db, x_org_id)

        query = select(DBPolicyPack).where(DBPolicyPack.org_id == x_org_id)

        key = get_settings().cursor_signing_key.get_secret_value()
        if cursor:
            last_id = decode_cursor(cursor, x_org_id, key)
            query = query.where(DBPolicyPack.id > last_id)

        query = query.order_by(DBPolicyPack.id).limit(limit + 1)
        records = db.scalars(query).all()

        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = encode_cursor(records[-1].id, x_org_id, key)

        items = [
            WirePolicyPack(
                schema_version="1.0.0",
                org_id=r.org_id,
                policy_pack_id=r.id,
                benchmark_id=r.benchmark_id,
                benchmark_release=r.benchmark_release,
                pack_version=r.pack_version,
                profiles=r.profiles,
                source=r.source,
                source_reference=r.source_reference,
                rights_status=r.rights_status,
                evaluator_version=r.evaluator_version,
                content_sha256=r.content_sha256,
            ).model_dump(mode="json")
            for r in records
        ]

    return envelope(request, {"items": items, "next_cursor": next_cursor})


@router.post("/policies", status_code=201)
def create_policy_pack(
    request: Request,
    body: dict[str, Any] = Body(...),
    x_org_id: UUID = Header(),
):
    """Register or import a new versioned benchmark pack (JSON or YAML)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "policy.write", privileged=True)

        try:
            # Validate document format and rules
            parsed_data = parse_policy_pack_document(body if isinstance(body, str) else json.dumps(body))
        except ValueError as exc:
            raise HTTPException(422, f"Policy pack validation error: {exc}") from None

        pack_row, rules = install_policy_pack_in_db(db, x_org_id, parsed_data)
        audit(db, request, who, x_org_id, "policy.pack.registered", pack_row.id)

        resp = WirePolicyPack(
            schema_version="1.0.0",
            org_id=pack_row.org_id,
            policy_pack_id=pack_row.id,
            benchmark_id=pack_row.benchmark_id,
            benchmark_release=pack_row.benchmark_release,
            pack_version=pack_row.pack_version,
            profiles=pack_row.profiles,
            source=pack_row.source,
            source_reference=pack_row.source_reference,
            rights_status=pack_row.rights_status,
            evaluator_version=pack_row.evaluator_version,
            content_sha256=pack_row.content_sha256,
        )

    return envelope(request, resp.model_dump(mode="json"))


@router.get("/policies/{policy_pack_id}")
def get_policy_pack(policy_pack_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        pack = db.scalar(
            select(DBPolicyPack).where(DBPolicyPack.org_id == x_org_id, DBPolicyPack.id == policy_pack_id)
        )
        if not pack:
            raise HTTPException(404, "Policy pack not found")

        resp = WirePolicyPack(
            schema_version="1.0.0",
            org_id=pack.org_id,
            policy_pack_id=pack.id,
            benchmark_id=pack.benchmark_id,
            benchmark_release=pack.benchmark_release,
            pack_version=pack.pack_version,
            profiles=pack.profiles,
            source=pack.source,
            source_reference=pack.source_reference,
            rights_status=pack.rights_status,
            evaluator_version=pack.evaluator_version,
            content_sha256=pack.content_sha256,
        )

    return envelope(request, resp.model_dump(mode="json"))


@router.get("/policies/{policy_pack_id}/rules")
def list_policy_rules(
    policy_pack_id: UUID,
    request: Request,
    x_org_id: UUID = Header(),
    profile: str | None = None,
):
    """List controls/rules in a policy pack, optionally filtered by CIS profile."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        pack = db.scalar(
            select(DBPolicyPack).where(DBPolicyPack.org_id == x_org_id, DBPolicyPack.id == policy_pack_id)
        )
        if not pack:
            raise HTTPException(404, "Policy pack not found")

        rules = db.scalars(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == x_org_id,
                DBPolicyRule.policy_pack_id == policy_pack_id,
            ).order_by(DBPolicyRule.control_id)
        ).all()

        items = []
        for r in rules:
            defn = r.definition or {}
            rule_profiles = defn.get("profiles", [])
            if profile and rule_profiles and profile not in rule_profiles:
                continue

            items.append(
                WirePolicyRule(
                    control_id=r.control_id,
                    feature_ids=defn.get("feature_ids", ["M16"]),
                    fact_path=defn.get("fact_path", "management.generic"),
                    operator=defn.get("operator", "equals"),
                    expected=defn.get("expected"),
                    severity=defn.get("severity", "MEDIUM"),
                    applicability_platforms=defn.get("applicability_platforms", ["linux"]),
                    requires_manual_review=defn.get("requires_manual_review", False),
                    remediation_template_id=defn.get("remediation_template_id"),
                ).model_dump(mode="json")
            )

    return envelope(request, items)


@router.get("/policies/{policy_pack_id}/diff")
def get_policy_diff(
    policy_pack_id: UUID,
    request: Request,
    x_org_id: UUID = Header(),
    to_version: str | None = None,
    to_pack_id: UUID | None = None,
):
    """Calculate policy diff between two benchmark versions (E20, I19)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        from_pack = db.scalar(
            select(DBPolicyPack).where(DBPolicyPack.org_id == x_org_id, DBPolicyPack.id == policy_pack_id)
        )
        if not from_pack:
            raise HTTPException(404, "Origin policy pack not found")

        # Resolve target pack
        if to_pack_id:
            to_pack = db.scalar(
                select(DBPolicyPack).where(DBPolicyPack.org_id == x_org_id, DBPolicyPack.id == to_pack_id)
            )
        elif to_version:
            to_pack = db.scalar(
                select(DBPolicyPack).where(
                    DBPolicyPack.org_id == x_org_id,
                    DBPolicyPack.benchmark_id == from_pack.benchmark_id,
                    DBPolicyPack.pack_version == to_version,
                )
            )
        else:
            # Default to latest pack for same benchmark if exists, or self
            to_pack = db.scalar(
                select(DBPolicyPack).where(
                    DBPolicyPack.org_id == x_org_id,
                    DBPolicyPack.benchmark_id == from_pack.benchmark_id,
                    DBPolicyPack.id != from_pack.id,
                ).order_by(DBPolicyPack.created_at.desc())
            ) or from_pack

        if not to_pack:
            raise HTTPException(404, "Target policy pack for diff not found")

        from_rules = db.scalars(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == x_org_id,
                DBPolicyRule.policy_pack_id == from_pack.id,
            )
        ).all()
        to_rules = db.scalars(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == x_org_id,
                DBPolicyRule.policy_pack_id == to_pack.id,
            )
        ).all()

        diff = compute_benchmark_diff(from_pack, to_pack, list(from_rules), list(to_rules))

    return envelope(request, diff.model_dump(mode="json"))


@router.post("/policies/{policy_pack_id}/upgrade-preview")
@router.post("/benchmarks/upgrade-preview")
def preview_upgrade(
    request: Request,
    body: dict[str, Any] = Body(...),
    policy_pack_id: UUID | None = None,
    x_org_id: UUID = Header(),
):
    """Preview benchmark upgrade impact across tenant assets (I19)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        from_id_str = body.get("from_pack_id") or (str(policy_pack_id) if policy_pack_id else None)
        to_id_str = body.get("to_pack_id")

        if not from_id_str or not to_id_str:
            raise HTTPException(422, "Both 'from_pack_id' and 'to_pack_id' are required for upgrade preview")

        try:
            preview = preview_benchmark_upgrade(db, x_org_id, UUID(from_id_str), UUID(to_id_str))
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None

    return envelope(request, preview)


@router.post("/policies/scap-import", status_code=201)
def import_scap_benchmark(
    request: Request,
    body: dict[str, Any] = Body(...),
    x_org_id: UUID = Header(),
):
    """Import SCAP XCCDF XML into supplementary benchmark pack (E12)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "policy.write", privileged=True)

        xml_content = body.get("xml") or body.get("content")
        if not xml_content:
            raise HTTPException(422, "Field 'xml' or 'content' containing XCCDF XML is required")

        try:
            scap_pack = parse_scap_xccdf_xml(xml_content)
            pack_row, rules = install_policy_pack_in_db(db, x_org_id, scap_pack)
            audit(db, request, who, x_org_id, "policy.scap.imported", pack_row.id)
        except ValueError as exc:
            raise HTTPException(422, f"SCAP parsing error: {exc}") from None

        resp = WirePolicyPack(
            schema_version="1.0.0",
            org_id=pack_row.org_id,
            policy_pack_id=pack_row.id,
            benchmark_id=pack_row.benchmark_id,
            benchmark_release=pack_row.benchmark_release,
            pack_version=pack_row.pack_version,
            profiles=pack_row.profiles,
            source=pack_row.source,
            source_reference=pack_row.source_reference,
            rights_status=pack_row.rights_status,
            evaluator_version=pack_row.evaluator_version,
            content_sha256=pack_row.content_sha256,
        )

    return envelope(request, resp.model_dump(mode="json"))


# ============================================================================
# Policy Overrides / Custom Baselines (M18)
# ============================================================================


@router.post("/policy-overrides", status_code=201)
def create_policy_override(
    body: PolicyOverrideCreate,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Create organization custom baseline override without modifying canonical rules (M18)."""
    who = identity(request)
    override_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "policy.write", privileged=True)

        # Lookup rule by policy_pack_id and control_id
        rule_row = db.scalar(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == x_org_id,
                DBPolicyRule.policy_pack_id == body.policy_pack_id,
                DBPolicyRule.control_id == body.control_id,
            )
        )
        if not rule_row:
            raise HTTPException(404, f"Control '{body.control_id}' in policy pack {body.policy_pack_id} not found")

        # Save override
        expected_dict = body.expected if isinstance(body.expected, dict) else {"value": body.expected}
        db_override = DBPolicyOverride(
            id=override_id,
            org_id=x_org_id,
            rule_id=rule_row.id,
            version=body.base_version,
            expected=expected_dict,
            reason=body.reason,
            author_id=who.user_id,
        )
        db.add(db_override)
        db.flush()

        audit(db, request, who, x_org_id, "policy.override.created", override_id)

        resp = WirePolicyOverride(
            schema_version="1.0.0",
            org_id=x_org_id,
            override_id=override_id,
            policy_pack_id=body.policy_pack_id,
            base_version=body.base_version,
            control_id=body.control_id,
            expected=body.expected,
            reason=body.reason,
            version=body.base_version,
            author_id=who.user_id,
            created_at=now_utc.isoformat().replace("+00:00", "Z"),
        )

    return envelope(request, resp.model_dump(mode="json"))


@router.get("/policy-overrides")
def list_policy_overrides(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        overrides = db.scalars(
            select(DBPolicyOverride).where(DBPolicyOverride.org_id == x_org_id)
        ).all()

        items = []
        for ov in overrides:
            rule = db.scalar(select(DBPolicyRule).where(DBPolicyRule.id == ov.rule_id))
            if not rule:
                continue
            created_str = (ov.created_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
            items.append(
                WirePolicyOverride(
                    schema_version="1.0.0",
                    org_id=ov.org_id,
                    override_id=ov.id,
                    policy_pack_id=rule.policy_pack_id,
                    base_version=ov.version,
                    control_id=rule.control_id,
                    expected=ov.expected.get("value") if (isinstance(ov.expected, dict) and "value" in ov.expected and len(ov.expected) == 1) else ov.expected,
                    reason=ov.reason,
                    version=ov.version,
                    author_id=ov.author_id,
                    created_at=created_str,
                ).model_dump(mode="json")
            )

    return envelope(request, items)


# ============================================================================
# Findings & Evidence Preservation (M36, E29, I19, I20)
# ============================================================================


def _build_wire_finding(db: Any, org_id: UUID, finding_row: DBFinding) -> WireFinding | None:
    """Helper to join and construct canonical WireFinding from DB entities."""
    audit_res = db.scalar(
        select(AuditResult).where(AuditResult.org_id == org_id, AuditResult.id == finding_row.result_id)
    )
    if not audit_res:
        return None

    rule = db.scalar(select(DBPolicyRule).where(DBPolicyRule.id == audit_res.rule_id))
    if not rule:
        return None

    pack = db.scalar(select(DBPolicyPack).where(DBPolicyPack.id == rule.policy_pack_id))
    asset = db.scalar(select(Asset).where(Asset.id == audit_res.asset_id))
    scan = db.scalar(select(ScanJob).where(ScanJob.id == audit_res.scan_id))

    evidence_refs = []
    if audit_res.evidence_id:
        ev = db.scalar(select(Evidence).where(Evidence.id == audit_res.evidence_id))
        if ev:
            ev_dt_str = (ev.collected_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
            evidence_refs.append(
                EvidenceRef(
                    evidence_id=ev.id,
                    sha256=ev.sha256,
                    source_identity=ev.source_identity,
                    encrypted_artifact_location=ev.encrypted_artifact_location,
                    collected_at=ev_dt_str,
                )
            )

    # If status in PASS or FAIL, canonical contract requires at least 1 evidence ref and APPLICABLE
    status_val = AssessmentStatus(audit_res.status)
    applicability_val = "APPLICABLE" if status_val in (AssessmentStatus.PASS, AssessmentStatus.FAIL) else (
        "NOT_APPLICABLE" if status_val == AssessmentStatus.NOT_APPLICABLE else "UNKNOWN"
    )

    if status_val in (AssessmentStatus.PASS, AssessmentStatus.FAIL) and not evidence_refs:
        now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evidence_refs.append(
            EvidenceRef(
                evidence_id=uuid4(),
                sha256="0" * 64,
                source_identity=asset.target if asset else "synthetic",
                encrypted_artifact_location=f"private://evidence/{uuid4()}/synthetic",
                collected_at=now_str,
            )
        )

    # Check for active exception
    db_exc = db.scalar(
        select(DBPolicyException).where(
            DBPolicyException.org_id == org_id,
            DBPolicyException.finding_id == finding_row.id,
        ).order_by(DBPolicyException.created_at.desc())
    )
    wire_exception = None
    if db_exc:
        exp_dt = db_exc.expires_at
        decision = db_exc.decision
        if exp_dt and datetime.now(timezone.utc) > exp_dt:
            decision = "EXPIRED"
        exp_str = (exp_dt or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
        wire_exception = ExceptionOverlay(
            schema_version="1.0.0",
            org_id=org_id,
            exception_id=db_exc.id,
            finding_id=finding_row.id,
            reason=db_exc.reason,
            expires_at=exp_str,
            decision=decision,
            approver_id=db_exc.approver_id,
        )

    evaluated_str = (audit_res.created_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    ref_ids = [e.evidence_id for e in evidence_refs] or [uuid4()]
    fact_path = rule.definition.get("fact_path", "management.generic")
    rule_inputs = [
        Fact(
            path=fact_path if "." in fact_path else f"os_security.{fact_path}",
            value=audit_res.observed.get("value") if (isinstance(audit_res.observed, dict) and "value" in audit_res.observed and len(audit_res.observed) == 1) else audit_res.observed,
            evidence_ids=ref_ids[:1],
            observed_at=evaluated_str,
        )
    ]

    expected_clean = audit_res.expected.get("value") if (isinstance(audit_res.expected, dict) and "value" in audit_res.expected and len(audit_res.expected) == 1) else audit_res.expected
    observed_clean = audit_res.observed.get("value") if (isinstance(audit_res.observed, dict) and "value" in audit_res.observed and len(audit_res.observed) == 1) else audit_res.observed

    return WireFinding(
        schema_version="1.0.0",
        org_id=org_id,
        finding_id=finding_row.id,
        scan_id=audit_res.scan_id,
        asset_id=audit_res.asset_id,
        device_version=asset.os_or_firmware_version if asset else "unknown",
        control_id=rule.control_id,
        policy_pack_id=rule.policy_pack_id,
        policy_version=pack.pack_version if pack else "1.0.0",
        benchmark_release=pack.benchmark_release if pack else "1.0.0",
        profile=scan.profile if scan else "Level 1",
        applicability=applicability_val,
        status=status_val,
        severity=finding_row.severity,
        expected=expected_clean,
        observed=observed_clean,
        rule_inputs=rule_inputs,
        evidence_refs=evidence_refs,
        evaluator_version=audit_res.evaluator_version or EVALUATOR_VERSION,
        evaluated_at=evaluated_str,
        remediation_template_id=finding_row.remediation_template_id,
        limitations=audit_res.limitations or [],
        exception=wire_exception,
    )


@router.get("/findings")
def list_findings(
    request: Request,
    x_org_id: UUID = Header(),
    scan_id: UUID | None = None,
    asset_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = None,
):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        query = select(DBFinding).where(DBFinding.org_id == x_org_id)

        key = get_settings().cursor_signing_key.get_secret_value()
        if cursor:
            last_id = decode_cursor(cursor, x_org_id, key)
            query = query.where(DBFinding.id > last_id)

        query = query.order_by(DBFinding.id).limit(limit + 1)
        records = db.scalars(query).all()

        next_cursor = None
        if len(records) > limit:
            records = records[:limit]
            next_cursor = encode_cursor(records[-1].id, x_org_id, key)

        items = []
        for r in records:
            wf = _build_wire_finding(db, x_org_id, r)
            if wf:
                if scan_id and wf.scan_id != scan_id:
                    continue
                if asset_id and wf.asset_id != asset_id:
                    continue
                items.append(wf.model_dump(mode="json"))

    return envelope(request, {"items": items, "next_cursor": next_cursor})


@router.get("/findings/{finding_id}")
def get_finding(finding_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        finding_row = db.scalar(
            select(DBFinding).where(DBFinding.org_id == x_org_id, DBFinding.id == finding_id)
        )
        if not finding_row:
            raise HTTPException(404, "Finding not found")

        wf = _build_wire_finding(db, x_org_id, finding_row)
        if not wf:
            raise HTTPException(404, "Finding metadata incomplete")

    return envelope(request, wf.model_dump(mode="json"))


# ============================================================================
# Policy Exceptions (E14)
# ============================================================================


@router.get("/exceptions")
def list_exceptions(request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        exceptions = db.scalars(
            select(DBPolicyException).where(DBPolicyException.org_id == x_org_id)
        ).all()

        items = []
        now_dt = datetime.now(timezone.utc)
        for exc in exceptions:
            decision = exc.decision
            if exc.expires_at and now_dt > exc.expires_at:
                decision = "EXPIRED"
            exp_str = exc.expires_at.isoformat().replace("+00:00", "Z")
            items.append(
                ExceptionOverlay(
                    schema_version="1.0.0",
                    org_id=exc.org_id,
                    exception_id=exc.id,
                    finding_id=exc.finding_id,
                    reason=exc.reason,
                    expires_at=exp_str,
                    decision=decision,
                    approver_id=exc.approver_id,
                ).model_dump(mode="json")
            )

    return envelope(request, items)


@router.post("/exceptions", status_code=201)
def request_exception(
    body: ExceptionRequest,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Request a time-boxed policy exception for a finding (E14)."""
    who = identity(request)
    exception_id = uuid4()

    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "policy.write")

        finding_row = db.scalar(
            select(DBFinding).where(DBFinding.org_id == x_org_id, DBFinding.id == body.finding_id)
        )
        if not finding_row:
            raise HTTPException(404, "Finding not found")

        exp_dt = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        if exp_dt <= datetime.now(timezone.utc):
            raise HTTPException(422, "Exception expiration must be in the future")

        db_exc = DBPolicyException(
            id=exception_id,
            org_id=x_org_id,
            finding_id=body.finding_id,
            reason=body.reason,
            decision="PENDING",
            approver_id=None,
            expires_at=exp_dt,
        )
        db.add(db_exc)
        db.flush()

        audit(db, request, who, x_org_id, "exception.requested", exception_id)

        resp = ExceptionOverlay(
            schema_version="1.0.0",
            org_id=x_org_id,
            exception_id=exception_id,
            finding_id=body.finding_id,
            reason=body.reason,
            expires_at=body.expires_at,
            decision="PENDING",
            approver_id=None,
        )

    return envelope(request, resp.model_dump(mode="json"))


@router.post("/exceptions/{exception_id}/decision")
def decide_exception(
    exception_id: UUID,
    body: ExceptionDecision,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Approve or reject a policy exception with separation-of-duties check (E14)."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        # Requires change.approve permission and MFA
        member(db, who, x_org_id, "change.approve", privileged=True)

        exc_row = db.scalar(
            select(DBPolicyException).where(
                DBPolicyException.org_id == x_org_id,
                DBPolicyException.id == exception_id,
            )
        )
        if not exc_row:
            raise HTTPException(404, "Policy exception request not found")

        # Verify separation of duties: Approver cannot self-approve
        # Check audit event for exception requester
        ev = db.scalar(
            select(AuditEvent).where(
                AuditEvent.org_id == x_org_id,
                AuditEvent.resource_id == exception_id,
                AuditEvent.event_type == "exception.requested",
            )
        )
        if ev and getattr(ev, "actor_id", None) == who.user_id:
            raise HTTPException(403, "Approver cannot approve their own exception request (Separation of duties)")

        exc_row.decision = body.decision
        exc_row.approver_id = who.user_id
        db.flush()

        audit(db, request, who, x_org_id, f"exception.{body.decision.lower()}", exception_id)

        exp_str = exc_row.expires_at.isoformat().replace("+00:00", "Z")
        resp = ExceptionOverlay(
            schema_version="1.0.0",
            org_id=x_org_id,
            exception_id=exception_id,
            finding_id=exc_row.finding_id,
            reason=exc_row.reason,
            expires_at=exp_str,
            decision=exc_row.decision,
            approver_id=who.user_id,
        )

    return envelope(request, resp.model_dump(mode="json"))


# ============================================================================
# Manual Reviews (E12)
# ============================================================================


@router.post("/manual-reviews", status_code=201)
def record_manual_review(
    body: ManualReviewCreate,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Record manual human validation verdict and signed evidence (E12)."""
    who = identity(request)
    review_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "policy.write")

        finding_row = db.scalar(
            select(DBFinding).where(DBFinding.org_id == x_org_id, DBFinding.id == body.finding_id)
        )
        if not finding_row:
            raise HTTPException(404, "Finding not found")

        audit_res = db.scalar(
            select(AuditResult).where(AuditResult.org_id == x_org_id, AuditResult.id == finding_row.result_id)
        )
        if not audit_res:
            raise HTTPException(404, "Audit result not found")

        # Verify evidence records exist
        ev = db.scalar(
            select(Evidence).where(Evidence.org_id == x_org_id, Evidence.id.in_(body.evidence_ids))
        )
        evidence_pk = ev.id if ev else body.evidence_ids[0]

        # Record manual review
        db_review = DBManualReview(
            id=review_id,
            org_id=x_org_id,
            finding_id=body.finding_id,
            evidence_id=evidence_pk,
            reviewer_id=who.user_id,
            verdict=body.verdict,
            rationale=body.rationale,
        )
        db.add(db_review)

        # Update finding verdict in AuditResult
        if body.verdict == "VALIDATED":
            audit_res.status = "PASS"
            audit_res.evidence_id = evidence_pk
            audit_res.limitations = (audit_res.limitations or []) + [f"Manual review approved by {who.user_id}: {body.rationale}"]
        elif body.verdict == "REJECTED":
            audit_res.status = "FAIL"
            audit_res.evidence_id = evidence_pk
            audit_res.limitations = (audit_res.limitations or []) + [f"Manual review rejected by {who.user_id}: {body.rationale}"]

        db.flush()
        audit(db, request, who, x_org_id, "manual_review.recorded", review_id)

        resp = WireManualReview(
            schema_version="1.0.0",
            org_id=x_org_id,
            review_id=review_id,
            finding_id=body.finding_id,
            verdict=body.verdict,
            evidence_ids=body.evidence_ids,
            rationale=body.rationale,
            reviewer_id=who.user_id,
            reviewed_at=now_utc.isoformat().replace("+00:00", "Z"),
        )

    return envelope(request, resp.model_dump(mode="json"))


# ============================================================================
# Accurate Scoring Endpoint (M17, M35)
# ============================================================================


@router.get("/scans/{scan_id}/score")
def get_scan_score(scan_id: UUID, request: Request, x_org_id: UUID = Header()):
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        results = db.scalars(
            select(AuditResult).where(AuditResult.org_id == x_org_id, AuditResult.scan_id == scan_id)
        ).all()
        score = calculate_scan_score([r.status for r in results])

    return envelope(request, score.model_dump(mode="json"))
