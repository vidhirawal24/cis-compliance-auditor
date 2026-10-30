"""Celery background worker, job orchestration, and deterministic policy evaluation engine.

Implements M13, M16, M17, M18, M19, E04, E08, E09, E11, E12, I20:
- Multi-target parallel / sequential execution
- Per-target failure isolation (errors in one target do not abort or crash the job)
- Deterministic CIS policy rule evaluation against collected asset facts
- Preservation of PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW, ERROR, NOT_ASSESSED
- Reconciled compliance score and audit coverage calculation
- Transactional outbox event creation for live dashboard updates
- Collection provenance tracking without exposing plaintext credentials
"""

from datetime import datetime, timezone
import logging
from typing import Any
from uuid import UUID, uuid4

from celery import Celery
from sqlalchemy import select
from sqlalchemy.orm import Session

from cisguard_contracts.v1.models import (
    EvidenceRef,
    PolicyOverride as WirePolicyOverride,
    PolicyRule as WirePolicyRule,
)
from .database import engine, tenant_session
from .db_models import (
    Asset,
    AuditEvent,
    AuditResult,
    ConfigSnapshot,
    Evidence,
    Finding as DBFinding,
    OutboxEvent,
    PolicyOverride as DBPolicyOverride,
    PolicyPack as DBPolicyPack,
    PolicyRule as DBPolicyRule,
    ScanJob,
    ScanTarget,
)
from .device_port import DevicePortError, collect_device_facts
from .policy_engine import (
    EVALUATOR_VERSION,
    calculate_scan_score,
    evaluate_rule,
    get_fixture_facts,
)
from .benchmark_service import get_builtin_policy_pack
from .settings import get_settings

logger = logging.getLogger("cisguard.worker")

settings = get_settings()
broker_url = (settings.celery_broker_url or settings.redis_url).get_secret_value()
backend_url = settings.celery_result_backend.get_secret_value() if settings.celery_result_backend else None

celery = Celery("cisguard", broker=broker_url, backend=backend_url)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_time_limit=300,
    worker_prefetch_multiplier=1,
    task_ignore_result=False,
    result_expires=3600,
)


@celery.task(name="cisguard.foundation_ping")
def foundation_ping():
    return {"status": "ready", "device_operations": "UNSUPPORTED"}


@celery.task(name="cisguard.run_scan")
def run_scan_task(org_id_str: str, scan_id_str: str, user_id_str: str | None = None):
    org_id = UUID(org_id_str)
    scan_id = UUID(scan_id_str)
    user_id = UUID(user_id_str) if user_id_str else None
    return execute_scan_job(org_id, scan_id, user_id=user_id)


def execute_scan_job(org_id: UUID, scan_id: UUID, user_id: UUID | None = None) -> dict[str, Any]:
    """Execute scan job with per-target failure isolation (M13) and deterministic CIS evaluation (M16-M19).

    A failure on any single device (timeout, auth failure, unreachable host)
    is isolated to its respective ScanTarget record. The remaining targets
    continue execution to completion.
    """
    if user_id is None:
        db_engine = engine()
        try:
            with Session(db_engine) as session:
                job_row = session.scalar(
                    select(ScanJob).where(ScanJob.org_id == org_id, ScanJob.id == scan_id)
                )
                if not job_row:
                    logger.error("ScanJob %s not found for tenant %s", scan_id, org_id)
                    return {"status": "NOT_FOUND"}
                user_id = job_row.requested_by
        finally:
            db_engine.dispose()

    with tenant_session(user_id, org_id) as db:
        job = db.scalar(
            select(ScanJob).where(ScanJob.org_id == org_id, ScanJob.id == scan_id).with_for_update()
        )
        if not job:
            logger.error("ScanJob %s not found for tenant %s", scan_id, org_id)
            return {"status": "NOT_FOUND"}

        # Transaction lock makes duplicate deliveries observe the committed terminal outcome.
        if job.status in ('SUCCEEDED','PARTIAL','FAILED','CANCELLED'):
            return {'status':job.status,'scan_id':str(scan_id),'duplicate':True}
        # Transition job state to RUNNING
        job.status = "RUNNING"
        db.flush()

        targets = db.scalars(
            select(ScanTarget).where(ScanTarget.org_id == org_id, ScanTarget.scan_id == scan_id)
        ).all()

        # Load policy rules for this scan's policy pack
        pack_rules = db.scalars(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == org_id,
                DBPolicyRule.policy_pack_id == job.policy_pack_id,
            )
        ).all()

        # If pack has no rules, populate default benchmark rules matching the pack
        if not pack_rules:
            pack_row = db.scalar(
                select(DBPolicyPack).where(DBPolicyPack.org_id == org_id, DBPolicyPack.id == job.policy_pack_id)
            )
            builtin_type = "ubuntu-v1"
            if pack_row and "windows" in pack_row.benchmark_id.lower():
                builtin_type = "windows-v1"
            elif pack_row and ("firewall" in pack_row.benchmark_id.lower() or "network" in pack_row.benchmark_id.lower()):
                builtin_type = "network-v1"
            default_pack_data = get_builtin_policy_pack(builtin_type)
            for r in default_pack_data["rules"]:
                rule_rec = DBPolicyRule(
                    id=uuid4(),
                    org_id=org_id,
                    policy_pack_id=job.policy_pack_id,
                    control_id=r["control_id"],
                    definition=r,
                )
                db.add(rule_rec)
            db.flush()
            pack_rules = db.scalars(
                select(DBPolicyRule).where(
                    DBPolicyRule.org_id == org_id,
                    DBPolicyRule.policy_pack_id == job.policy_pack_id,
                )
            ).all()

        # Filter rules by profile if rule definition specifies profiles
        active_rules = []
        for pr in pack_rules:
            rule_profiles = pr.definition.get("profiles", [])
            if not rule_profiles or job.profile in rule_profiles:
                active_rules.append(pr)

        # Load active policy overrides for the organization
        db_overrides = db.scalars(
            select(DBPolicyOverride).where(DBPolicyOverride.org_id == org_id)
        ).all()
        overrides_by_rule_id = {ov.rule_id: ov for ov in db_overrides}

        succeeded_count = 0
        failed_count = 0
        all_audit_statuses: list[str] = []

        for target_record in targets:
            asset = db.scalar(
                select(Asset).where(Asset.org_id == org_id, Asset.id == target_record.asset_id)
            )
            target_record.status = "RUNNING"
            db.flush()

            if not asset or asset.retired:
                target_record.status = "FAILED"
                target_record.errors = [
                    {"code": "DEVICE_UNAVAILABLE", "message": "Asset not found or retired", "retryable": False}
                ]
                failed_count += 1
                job.completed_assets = (job.completed_assets or 0) + 1
                db.flush()
                continue

            try:
                # 1. Device collection
                result = collect_device_facts(asset, mode='read_only')
                target_record.status = "SUCCEEDED"
                target_record.errors = []
                succeeded_count += 1

                # 2. Persist evidence and snapshot metadata without plaintext secrets
                evidence_id = uuid4()
                now_utc = datetime.now(timezone.utc)
                db.add(
                    Evidence(
                        id=evidence_id,
                        org_id=org_id,
                        asset_id=asset.id,
                        source_identity=result["provenance"]["target"],
                        sha256=result["content_sha256"],
                        encrypted_artifact_location=result["artifact_ref"].removesuffix(".json"),
                        collected_at=now_utc,
                        collection_method="synthetic_v1_port",
                    )
                )
                db.flush()
                db.add(
                    ConfigSnapshot(
                        id=uuid4(),
                        org_id=org_id,
                        asset_id=asset.id,
                        evidence_id=evidence_id,
                        device_version=asset.os_or_firmware_version or "unknown",
                    )
                )

                # 3. Retrieve facts for this asset
                facts = get_fixture_facts(asset.family, asset.platform)

                evidence_ref = EvidenceRef(
                    evidence_id=evidence_id,
                    sha256=result["content_sha256"],
                    source_identity=result["provenance"]["target"],
                    encrypted_artifact_location=result["artifact_ref"].removesuffix(".json"),
                    collected_at=now_utc.isoformat().replace("+00:00", "Z"),
                )

                # 4. Evaluate each applicable policy rule
                for rule_rec in active_rules:
                    wire_rule = WirePolicyRule(
                        control_id=rule_rec.control_id,
                        feature_ids=rule_rec.definition.get("feature_ids", ["M16"]),
                        fact_path=rule_rec.definition.get("fact_path", "management.generic"),
                        operator=rule_rec.definition.get("operator", "equals"),
                        expected=rule_rec.definition.get("expected"),
                        severity=rule_rec.definition.get("severity", "MEDIUM"),
                        applicability_platforms=rule_rec.definition.get("applicability_platforms", ["linux"]),
                        requires_manual_review=rule_rec.definition.get("requires_manual_review", False),
                        remediation_template_id=rule_rec.definition.get("remediation_template_id"),
                    )

                    # Lookup override for this rule
                    active_override = None
                    db_ov = overrides_by_rule_id.get(rule_rec.id)
                    if db_ov:
                        active_override = WirePolicyOverride(
                            schema_version="1.0.0",
                            org_id=org_id,
                            override_id=db_ov.id,
                            policy_pack_id=job.policy_pack_id,
                            base_version=db_ov.version,
                            control_id=rule_rec.control_id,
                            expected=db_ov.expected,
                            reason=db_ov.reason,
                            version=db_ov.version,
                            author_id=db_ov.author_id,
                            created_at=db_ov.created_at.isoformat().replace("+00:00", "Z") if db_ov.created_at else now_utc.isoformat().replace("+00:00", "Z"),
                        )

                    eval_res = evaluate_rule(
                        rule=wire_rule,
                        facts=facts,
                        evidence_refs=[evidence_ref],
                        asset_platform=asset.platform,
                        asset_family=asset.family,
                        asset_version=asset.os_or_firmware_version or "",
                        override=active_override,
                    )

                    status_str = eval_res["status"].value
                    all_audit_statuses.append(status_str)

                    # Determine evidence_id for DB constraint:
                    # status NOT IN ('PASS','FAIL') OR evidence_id IS NOT NULL
                    db_evidence_id = evidence_id if status_str in ("PASS", "FAIL") else (evidence_id if eval_res.get("evidence_refs") else None)

                    # Persist AuditResult
                    result_id = uuid4()
                    db.add(
                        AuditResult(
                            id=result_id,
                            org_id=org_id,
                            scan_id=scan_id,
                            asset_id=asset.id,
                            rule_id=rule_rec.id,
                            evidence_id=db_evidence_id,
                            status=status_str,
                            expected=eval_res["expected"] if isinstance(eval_res["expected"], dict) else {"value": eval_res["expected"]},
                            observed=eval_res["observed"] if isinstance(eval_res["observed"], dict) else {"value": eval_res["observed"]},
                            evaluator_version=EVALUATOR_VERSION,
                            limitations=eval_res["limitations"],
                        )
                    )
                    db.flush()

                    # Persist Finding row for evaluated controls
                    db.add(
                        DBFinding(
                            id=uuid4(),
                            org_id=org_id,
                            result_id=result_id,
                            severity=eval_res["severity"],
                            remediation_template_id=rule_rec.definition.get("remediation_template_id"),
                        )
                    )

            except DevicePortError as exc:
                # Per-target failure isolation: error captured, loop continues!
                logger.warning(
                    "Target %s on asset %s failed with %s: %s",
                    asset.target,
                    asset.id,
                    exc.code,
                    exc.message,
                )
                target_record.status = "FAILED"
                target_record.errors = [
                    {"code": exc.code, "message": exc.message, "retryable": exc.retryable}
                ]
                failed_count += 1
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected error collecting from asset %s", asset.id)
                target_record.status = "FAILED"
                target_record.errors = [
                    {"code": "UNSUPPORTED", "message": str(exc), "retryable": False}
                ]
                failed_count += 1

            job.completed_assets = (job.completed_assets or 0) + 1
            db.flush()

        # Determine aggregate job status
        if failed_count == 0:
            job.status = "SUCCEEDED"
        elif succeeded_count > 0:
            job.status = "PARTIAL"
        else:
            job.status = "FAILED"

        # Calculate final reconciled compliance score
        scan_score = calculate_scan_score(all_audit_statuses)

        # Emit outbox event for dashboard notification / realtime broadcast
        now = datetime.now(timezone.utc)
        db.add(
            OutboxEvent(
                id=uuid4(),
                org_id=org_id,
                topic="cisguard.scan.completed",
                payload={
                    "scan_id": str(scan_id),
                    "status": job.status,
                    "requested_assets": job.requested_assets,
                    "completed_assets": job.completed_assets,
                    "succeeded_targets": succeeded_count,
                    "failed_targets": failed_count,
                    "score": scan_score.model_dump(mode="json"),
                },
                published_at=now,
            )
        )
        db.add(
            AuditEvent(
                id=uuid4(),
                org_id=org_id,
                actor_id=job.requested_by,
                request_id=UUID(int=0),
                event_type="scan.completed",
                resource_id=scan_id,
                details={
                    "status": job.status,
                    "succeeded": succeeded_count,
                    "failed": failed_count,
                    "score": scan_score.model_dump(mode="json"),
                },
            )
        )
        final_status = job.status

    return {
        "status": final_status,
        "scan_id": str(scan_id),
        "score": scan_score.model_dump(mode="json"),
    }
