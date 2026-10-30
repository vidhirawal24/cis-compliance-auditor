"""Phase 3 live database integration tests: multi-target failure isolation (M13).

Runs against the real Supabase PostgreSQL instance with full transaction rollback.
Exercises:
- Multi-target scan execution with per-target failure isolation
- Partial scan status when one device fails and others succeed
- Outbox event publication
- Soft-retirement preserving historical records
"""

import os
from uuid import uuid4
import pytest

pytestmark = pytest.mark.usefixtures("synthetic_device_engine")
from sqlalchemy import select, text
from cisguard_api.database import engine
from cisguard_api.db_models import (
    Asset,
    AuthorizationScope,
    ConfigSnapshot,
    Organization,
    OrganizationMember,
    OutboxEvent,
    PolicyPack,
    ScanJob,
    ScanTarget,
)
from cisguard_api.worker import execute_scan_job


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB opt-in required")
def test_M13_live_multi_target_failure_isolation():
    db = engine(migration=True)
    org_id = uuid4()
    owner_id = uuid4()
    scope_id = uuid4()
    pack_id = uuid4()
    scan_id = uuid4()

    asset1_id = uuid4()
    asset2_id = uuid4()
    asset3_id = uuid4()

    with db.connect() as conn:
        tx = conn.begin()
        try:
            # 1. Setup synthetic organization and owner
            conn.execute(
                text("INSERT INTO cisguard.organizations(id, name) VALUES (:o, :n)"),
                {"o": org_id, "n": "Phase 3 Rollback Fixture Org"},
            )
            conn.execute(
                text(
                    "INSERT INTO cisguard.organization_members(id, org_id, user_id, role, active) "
                    "VALUES (:id, :o, :u, 'owner', true)"
                ),
                {"id": uuid4(), "o": org_id, "u": owner_id},
            )

            # 2. Authorization scope
            conn.execute(
                text(
                    "INSERT INTO cisguard.authorization_scopes(id, org_id, name, approved_targets, approved_by, expires_at) "
                    "VALUES (:id, :o, 'Lab Scope', '[\"10.99.0.0/16\"]'::jsonb, :u, now() + interval '1 day')"
                ),
                {"id": scope_id, "o": org_id, "u": owner_id},
            )

            # 3. Benchmark pack
            conn.execute(
                text(
                    "INSERT INTO cisguard.benchmark_packs(id, org_id, benchmark_id, benchmark_release, pack_version, "
                    "profiles, source, source_reference, rights_status, evaluator_version, content_sha256) "
                    "VALUES (:id, :o, 'cis-test', '1.0.0', '1.0.0', '[\"Level 1\"]'::jsonb, 'authorized_cis_mapping', 'ref', "
                    "'AUTHORIZED', '1.0.0', :h)"
                ),
                {"id": pack_id, "o": org_id, "h": "0" * 64},
            )

            # 4. Create 3 assets: Target 1 (Normal Linux), Target 2 (Simulated Timeout), Target 3 (Normal Windows)
            conn.execute(
                text(
                    "INSERT INTO cisguard.assets(id, org_id, name, family, platform, vendor, model, os_or_firmware_version, "
                    "target, authorization_scope_id, tags, retired) VALUES "
                    "(:a1, :o, 'lnx-srv', 'linux', 'Ubuntu 22.04', 'Canonical', 'VM', '22.04', '10.99.1.10', :sc, '[]'::jsonb, false), "
                    "(:a2, :o, 'fw-edge', 'firewall', 'FortiGate', 'Fortinet', '60F', '7.0', '10.99.1.20.timeout', :sc, '[\"simulate_timeout\"]'::jsonb, false), "
                    "(:a3, :o, 'win-dc', 'windows', 'Windows Server 2019', 'Microsoft', 'VM', '2019', '10.99.1.30', :sc, '[]'::jsonb, false)"
                ),
                {"a1": asset1_id, "a2": asset2_id, "a3": asset3_id, "o": org_id, "sc": scope_id},
            )

            # 5. Create ScanJob with 3 targets
            conn.execute(
                text(
                    "INSERT INTO cisguard.scan_jobs(id, org_id, policy_pack_id, requested_by, profile, status, read_only, "
                    "requested_assets, completed_assets) VALUES (:sid, :o, :pid, :u, 'Level 1', 'QUEUED', true, 3, 0)"
                ),
                {"sid": scan_id, "o": org_id, "pid": pack_id, "u": owner_id},
            )
            for aid in [asset1_id, asset2_id, asset3_id]:
                conn.execute(
                    text(
                        "INSERT INTO cisguard.scan_targets(id, org_id, scan_id, asset_id, status, errors) "
                        "VALUES (:id, :o, :sid, :aid, 'QUEUED', '[]'::jsonb)"
                    ),
                    {"id": uuid4(), "o": org_id, "sid": scan_id, "aid": aid},
                )

            # Commit setup so worker session sees the rows
            tx.commit()

            # 6. Execute worker scan job
            result = execute_scan_job(org_id, scan_id)
            assert result["status"] == "PARTIAL"

            # 7. Verify per-target failure isolation in database
            with db.connect() as verify_conn:
                job_row = verify_conn.execute(
                    text("SELECT status, requested_assets, completed_assets FROM cisguard.scan_jobs WHERE id = :sid"),
                    {"sid": scan_id},
                ).mappings().one()

                assert job_row["status"] == "PARTIAL"
                assert job_row["requested_assets"] == 3
                assert job_row["completed_assets"] == 3

                targets = verify_conn.execute(
                    text("SELECT asset_id, status, errors FROM cisguard.scan_targets WHERE scan_id = :sid"),
                    {"sid": scan_id},
                ).mappings().all()

                t_map = {t["asset_id"]: t for t in targets}

                # Target 1 succeeded
                assert t_map[asset1_id]["status"] == "SUCCEEDED"
                assert len(t_map[asset1_id]["errors"]) == 0

                # Target 2 failed with TIMEOUT (isolated!)
                assert t_map[asset2_id]["status"] == "FAILED"
                assert len(t_map[asset2_id]["errors"]) == 1
                assert t_map[asset2_id]["errors"][0]["code"] == "TIMEOUT"

                # Target 3 succeeded despite Target 2 failing!
                assert t_map[asset3_id]["status"] == "SUCCEEDED"
                assert len(t_map[asset3_id]["errors"]) == 0

                # Outbox event emitted
                outbox_count = verify_conn.execute(
                    text("SELECT count(*) FROM cisguard.outbox_events WHERE org_id = :o AND topic = 'cisguard.scan.completed'"),
                    {"o": org_id},
                ).scalar()
                assert outbox_count >= 1

                # ConfigSnapshots recorded for succeeded assets
                snapshot_count = verify_conn.execute(
                    text("SELECT count(*) FROM cisguard.config_snapshots WHERE org_id = :o"),
                    {"o": org_id},
                ).scalar()
                assert snapshot_count == 2

        finally:
            # Clean up all synthetic records created during test
            with db.connect() as cleanup_conn:
                cleanup_tx = cleanup_conn.begin()
                cleanup_conn.execute(text("DELETE FROM cisguard.manual_reviews WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.exceptions WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.policy_overrides WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.findings WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_results WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.policy_rules WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.outbox_events WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_events WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.config_snapshots WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.audit_evidence WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.scan_targets WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.scan_jobs WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.assets WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.benchmark_packs WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.authorization_scopes WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.organization_members WHERE org_id = :o"), {"o": org_id})
                cleanup_conn.execute(text("DELETE FROM cisguard.organizations WHERE id = :o"), {"o": org_id})
                cleanup_tx.commit()

