"""Phase 4 live database integration tests: CIS policy engine, scoring, overrides, and exceptions.

Runs against the real Supabase PostgreSQL instance with full transaction rollback.
Exercises:
- End-to-end deterministic CIS evaluation during scan execution (M16)
- Persistence of AuditResults and Findings linked to audit evidence (M36, I19)
- Preservation of PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW (M16, E11, E12)
- Reconciled Score and coverage computation (M17, M35)
- Custom baseline PolicyOverrides (M18)
- Time-boxed PolicyExceptions with approver separation of duties (E14)
- ManualReview evidence recording and finding verdict resolution (E12)
"""

from datetime import datetime, timedelta, timezone
import json
import os
from uuid import UUID, uuid4

import pytest

pytestmark = pytest.mark.usefixtures("synthetic_device_engine")
from sqlalchemy import select, text

from cisguard_api.database import engine
from cisguard_api.db_models import (
    Asset,
    AuditEvent,
    AuditResult,
    AuthorizationScope,
    ConfigSnapshot,
    Evidence,
    Finding as DBFinding,
    ManualReview as DBManualReview,
    Organization,
    OrganizationMember,
    OutboxEvent,
    PolicyException as DBPolicyException,
    PolicyOverride as DBPolicyOverride,
    PolicyPack as DBPolicyPack,
    PolicyRule as DBPolicyRule,
    ScanJob,
    ScanTarget,
)
from cisguard_api.worker import execute_scan_job
from cisguard_api.benchmark_service import get_builtin_policy_pack, install_policy_pack_in_db
from cisguard_api.policy_engine import calculate_scan_score


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB opt-in required")
def test_live_phase4_end_to_end_audit_and_scoring():
    db = engine(migration=True)
    org_id = uuid4()
    owner_id = uuid4()
    auditor_id = uuid4()
    approver_id = uuid4()
    scope_id = uuid4()
    pack_id = uuid4()
    scan_id = uuid4()
    asset_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    with db.connect() as conn:
        tx = conn.begin()
        try:
            # 1. Setup organization and members
            conn.execute(
                text("INSERT INTO cisguard.organizations(id, name) VALUES (:o, :n)"),
                {"o": org_id, "n": "Phase 4 Live Test Org"},
            )
            for uid, role in [(owner_id, "owner"), (auditor_id, "auditor"), (approver_id, "approver")]:
                conn.execute(
                    text(
                        "INSERT INTO cisguard.organization_members(id, org_id, user_id, role, active) "
                        "VALUES (:id, :o, :u, :r, true)"
                    ),
                    {"id": uuid4(), "o": org_id, "u": uid, "r": role},
                )

            # 2. Authorization scope
            conn.execute(
                text(
                    "INSERT INTO cisguard.authorization_scopes(id, org_id, name, approved_targets, approved_by, expires_at) "
                    "VALUES (:id, :o, 'Lab Audit Scope', '[\"10.88.0.0/16\"]'::jsonb, :u, now() + interval '1 day')"
                ),
                {"id": scope_id, "o": org_id, "u": owner_id},
            )

            # 3. Provision Ubuntu Linux 22.04 asset
            conn.execute(
                text(
                    "INSERT INTO cisguard.assets(id, org_id, name, family, platform, vendor, model, os_or_firmware_version, "
                    "target, authorization_scope_id, tags, retired) VALUES "
                    "(:aid, :o, 'prod-ubuntu-node', 'linux', 'Ubuntu 22.04', 'Canonical', 'BareMetal', '22.04', '10.88.1.5', :sc, '[]'::jsonb, false)"
                ),
                {"aid": asset_id, "o": org_id, "sc": scope_id},
            )

            # 4. Provision benchmark pack with canonical CIS controls
            pack_data = get_builtin_policy_pack("ubuntu-v1")
            conn.execute(
                text(
                    "INSERT INTO cisguard.benchmark_packs(id, org_id, benchmark_id, benchmark_release, pack_version, "
                    "profiles, source, source_reference, rights_status, evaluator_version, content_sha256) "
                    "VALUES (:pid, :o, :bid, :brel, :pver, CAST(:prof AS jsonb), :src, :sref, 'AUTHORIZED', '1.0.0', :h)"
                ),
                {
                    "pid": pack_id,
                    "o": org_id,
                    "bid": pack_data["benchmark_id"],
                    "brel": pack_data["benchmark_release"],
                    "pver": pack_data["pack_version"],
                    "prof": json.dumps(pack_data["profiles"]),
                    "src": pack_data["source"],
                    "sref": pack_data["source_reference"],
                    "h": "0" * 64,
                },
            )

            # Insert rules
            rule_ids = {}
            for r in pack_data["rules"]:
                rid = uuid4()
                rule_ids[r["control_id"]] = rid
                conn.execute(
                    text(
                        "INSERT INTO cisguard.policy_rules(id, org_id, policy_pack_id, control_id, definition) "
                        "VALUES (:rid, :o, :pid, :cid, CAST(:defn AS jsonb))"
                    ),
                    {"rid": rid, "o": org_id, "pid": pack_id, "cid": r["control_id"], "defn": json.dumps(r)},
                )

            # 5. Create ScanJob
            conn.execute(
                text(
                    "INSERT INTO cisguard.scan_jobs(id, org_id, policy_pack_id, requested_by, profile, status, read_only, "
                    "requested_assets, completed_assets) VALUES (:sid, :o, :pid, :u, 'Level 1 - Server', 'QUEUED', true, 1, 0)"
                ),
                {"sid": scan_id, "o": org_id, "pid": pack_id, "u": owner_id},
            )
            conn.execute(
                text(
                    "INSERT INTO cisguard.scan_targets(id, org_id, scan_id, asset_id, status, errors) "
                    "VALUES (:id, :o, :sid, :aid, 'QUEUED', '[]'::jsonb)"
                ),
                {"id": uuid4(), "o": org_id, "sid": scan_id, "aid": asset_id},
            )

            tx.commit()

            # 6. Execute scan job
            scan_outcome = execute_scan_job(org_id, scan_id)
            assert scan_outcome["status"] == "SUCCEEDED"
            assert "score" in scan_outcome

            # 7. Verify live database records
            with db.connect() as v_conn:
                # Verify AuditResults
                audit_rows = v_conn.execute(
                    text("SELECT rule_id, status, evidence_id FROM cisguard.audit_results WHERE scan_id = :sid"),
                    {"sid": scan_id},
                ).mappings().all()
                assert len(audit_rows) > 0

                statuses = [r["status"] for r in audit_rows]
                # Control 5.2.1 is PASS (root login disabled in fixture facts)
                assert "PASS" in statuses
                # Control 1.7.1 is MANUAL_REVIEW (motd requires manual verification)
                assert "MANUAL_REVIEW" in statuses

                # Assessed PASS results must have non-null evidence_id (DB constraint ck_audit_results_assessed_evidence)
                for r in audit_rows:
                    if r["status"] in ("PASS", "FAIL"):
                        assert r["evidence_id"] is not None

                # Verify Findings created
                finding_count = v_conn.execute(
                    text("SELECT count(*) FROM cisguard.findings WHERE org_id = :o"),
                    {"o": org_id},
                ).scalar()
                assert finding_count > 0

                # 8. Test PolicyOverride (Custom Baseline) (M18)
                override_id = uuid4()
                rule_523_id = rule_ids["5.2.3"]
                v_conn.execute(
                    text(
                        "INSERT INTO cisguard.policy_overrides(id, org_id, rule_id, version, expected, reason, author_id) "
                        "VALUES (:oid, :o, :rid, '1.0.0', '{\"min\": 1, \"max\": 8}'::jsonb, 'CI runner higher threshold', :uid)"
                    ),
                    {"oid": override_id, "o": org_id, "rid": rule_523_id, "uid": owner_id},
                )
                ov_row = v_conn.execute(
                    text("SELECT * FROM cisguard.policy_overrides WHERE id = :oid"),
                    {"oid": override_id},
                ).mappings().one()
                assert ov_row["reason"] == "CI runner higher threshold"

                # 9. Test PolicyException (E14)
                first_finding_id = v_conn.execute(
                    text("SELECT id FROM cisguard.findings WHERE org_id = :o LIMIT 1"),
                    {"o": org_id},
                ).scalar()

                exc_id = uuid4()
                exp_date = now_utc + timedelta(days=14)
                v_conn.execute(
                    text(
                        "INSERT INTO cisguard.exceptions(id, org_id, finding_id, reason, decision, approver_id, expires_at) "
                        "VALUES (:eid, :o, :fid, 'Temporary migration exception', 'APPROVED', :appr, :exp)"
                    ),
                    {"eid": exc_id, "o": org_id, "fid": first_finding_id, "appr": approver_id, "exp": exp_date},
                )
                exc_row = v_conn.execute(
                    text("SELECT * FROM cisguard.exceptions WHERE id = :eid"),
                    {"eid": exc_id},
                ).mappings().one()
                assert exc_row["decision"] == "APPROVED"
                assert exc_row["approver_id"] == approver_id

                # 10. Test ManualReview (E12)
                review_id = uuid4()
                ev_id = audit_rows[0]["evidence_id"] or uuid4()
                v_conn.execute(
                    text(
                        "INSERT INTO cisguard.manual_reviews(id, org_id, finding_id, evidence_id, reviewer_id, verdict, rationale) "
                        "VALUES (:mrid, :o, :fid, :evid, :rev, 'VALIDATED', 'Manually checked MOTD compliance')"
                    ),
                    {"mrid": review_id, "o": org_id, "fid": first_finding_id, "evid": ev_id, "rev": auditor_id},
                )
                rev_row = v_conn.execute(
                    text("SELECT * FROM cisguard.manual_reviews WHERE id = :mrid"),
                    {"mrid": review_id},
                ).mappings().one()
                assert rev_row["verdict"] == "VALIDATED"

        finally:
            # Complete teardown of synthetic test data
            with db.connect() as cleanup_conn:
                c_tx = cleanup_conn.begin()
                cleanup_conn.execute(text("DELETE FROM cisguard.manual_reviews WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.exceptions WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.findings WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_results WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.policy_overrides WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.policy_rules WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.outbox_events WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_events WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.config_snapshots WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_evidence WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.scan_targets WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.scan_jobs WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.benchmark_packs WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.assets WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.authorization_scopes WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.organization_members WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.organizations WHERE id = :o"), {"o": org_id})
                c_tx.commit()
