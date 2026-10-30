"""Live PostgreSQL integration tests for Phase 7, Phase 8, and Phase 9.

Exercises against the real Supabase PostgreSQL instance with full transaction cleanup:
- Phase 7: CP-SAT remediation plan generation, constraint satisfaction, and plan/action persistence (I06-I10)
- Phase 8: Safety contracts, simulation runs, separation-of-duties approval, change state machine (E21-E25, I14-I16)
- Phase 9: Proof-of-hardening dossier generation, Ed25519 digital signatures, tamper detection, and drift events (E05-E07, E19, E26-E28, I17-I20)
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from uuid import UUID, uuid4

import pytest

pytestmark = pytest.mark.usefixtures("synthetic_device_engine")
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cisguard_api.change_routes import _TRANSITIONS, _assert_transition
from cisguard_api.database import engine
from cisguard_api.db_models import (
    Approval as DBApproval,
    Asset,
    AuditEvent,
    AuditResult,
    AuthorizationScope,
    Change as DBChange,
    CredentialReference,
    Evidence as AuditEvidence,
    Finding as DBFinding,
    OutboxEvent,
    PolicyPack,
    PolicyRule,
    RemediationAction as DBAction,
    RemediationPlan as DBPlan,
    SafetyContract as DBSafetyContract,
    ScanJob,
    ScanTarget,
    SimulationRun as DBSimulation,
)
from cisguard_api.plan_optimizer import (
    PlanConstraints,
    VettedCandidate,
    compute_plan_sha256,
    optimize_plan,
)
from cisguard_api.proof_routes import (
    calculate_residual_risk,
    compute_manifest_sha256,
    sign_manifest,
    verify_manifest_signature,
)


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB opt-in required")
def test_live_phase7_8_9_end_to_end():
    db = engine(migration=True)
    org_id = uuid4()
    plan_author_id = uuid4()
    approver_id = uuid4()
    operator_id = uuid4()
    scope_id = uuid4()
    cred_id = uuid4()
    asset1_id = uuid4()
    asset2_id = uuid4()
    pack_id = uuid4()
    rule_id = uuid4()
    scan_id = uuid4()
    evidence_id = uuid4()
    result_id = uuid4()
    finding_id = uuid4()
    plan_id = uuid4()
    action_id = uuid4()
    safety_contract_id = uuid4()
    simulation_id = uuid4()
    approval_id = uuid4()
    change_id = uuid4()
    proof_id = uuid4()

    now_utc = datetime.now(timezone.utc)

    # 1. Setup base organization, members, scope, assets, and failing finding
    with Session(db) as session:
        # Organization
        session.execute(
            text("INSERT INTO cisguard.organizations(id, name) VALUES (:o, 'Phase 7-9 Live Test Org')"),
            {"o": org_id},
        )
        # Members (Owner, Operator, Approver)
        for uid, role in [(plan_author_id, "operator"), (approver_id, "approver"), (operator_id, "operator")]:
            session.execute(
                text(
                    "INSERT INTO cisguard.organization_members(id, org_id, user_id, role, active) "
                    "VALUES (:id, :o, :u, :r, true)"
                ),
                {"id": uuid4(), "o": org_id, "u": uid, "r": role},
            )

        # Scope and Credential
        session.execute(
            text(
                "INSERT INTO cisguard.authorization_scopes(id, org_id, name, approved_targets, approved_by, expires_at) "
                "VALUES (:id, :o, 'Phase 7 Scope', '[\"10.70.0.0/16\"]'::jsonb, :u, now() + interval '1 day')"
            ),
            {"id": scope_id, "o": org_id, "u": plan_author_id},
        )
        session.execute(
            text(
                "INSERT INTO cisguard.credential_references(id, org_id, vault_reference, label) "
                "VALUES (:id, :o, 'secret/data/cisguard/p7-cred', 'P7 Test Cred')"
            ),
            {"id": cred_id, "o": org_id},
        )

        # Assets: web server and db server
        session.execute(
            text(
                "INSERT INTO cisguard.assets(id, org_id, name, family, platform, vendor, model, os_or_firmware_version, "
                "target, authorization_scope_id, credential_reference_id, tags, retired) VALUES "
                "(:a1, :o, 'p7-web-node', 'linux', 'Ubuntu 22.04', 'Canonical', 'VM', '22.04', '10.70.1.10', :sc, :cr, '[]'::jsonb, false), "
                "(:a2, :o, 'p7-db-node', 'linux', 'Ubuntu 22.04', 'Canonical', 'VM', '22.04', '10.70.2.20', :sc, :cr, '[]'::jsonb, false)"
            ),
            {"a1": asset1_id, "a2": asset2_id, "o": org_id, "sc": scope_id, "cr": cred_id},
        )

        # Benchmark Pack and Rule
        session.execute(
            text(
                "INSERT INTO cisguard.benchmark_packs(id, org_id, benchmark_id, benchmark_release, pack_version, "
                "profiles, source, source_reference, rights_status, evaluator_version, content_sha256) "
                "VALUES (:id, :o, 'cis-ubuntu-22.04', 'v1.0.0', '1.0.0', '[\"Level 1\"]'::jsonb, 'authorized_cis_mapping', "
                "'CIS', 'AUTHORIZED', '1.0.0', :h)"
            ),
            {"id": pack_id, "o": org_id, "h": "0" * 64},
        )
        session.execute(
            text(
                "INSERT INTO cisguard.policy_rules(id, org_id, policy_pack_id, control_id, definition) "
                "VALUES (:id, :o, :pid, '5.2.1', '{\"control_id\": \"5.2.1\", \"severity\": \"HIGH\"}'::jsonb)"
            ),
            {"id": rule_id, "o": org_id, "pid": pack_id},
        )

        # ScanJob and ScanTarget
        session.execute(
            text(
                "INSERT INTO cisguard.scan_jobs(id, org_id, policy_pack_id, requested_by, profile, status, read_only, "
                "requested_assets, completed_assets) VALUES (:sid, :o, :pid, :u, 'Level 1', 'SUCCEEDED', true, 1, 1)"
            ),
            {"sid": scan_id, "o": org_id, "pid": pack_id, "u": plan_author_id},
        )
        session.execute(
            text(
                "INSERT INTO cisguard.scan_targets(id, org_id, scan_id, asset_id, status, errors) "
                "VALUES (:tid, :o, :sid, :aid, 'SUCCEEDED', '[]'::jsonb)"
            ),
            {"tid": uuid4(), "o": org_id, "sid": scan_id, "aid": asset1_id},
        )

        # Evidence
        session.execute(
            text(
                "INSERT INTO cisguard.audit_evidence(id, org_id, asset_id, source_identity, sha256, encrypted_artifact_location, "
                "collected_at, collection_method) VALUES (:eid, :o, :aid, 'scanner:test', :h, 'private://evidence/p7', now(), 'ssh')"
            ),
            {"eid": evidence_id, "o": org_id, "aid": asset1_id, "h": "1" * 64},
        )

        # AuditResult (FAIL) and Finding
        session.execute(
            text(
                "INSERT INTO cisguard.audit_results(id, org_id, scan_id, asset_id, rule_id, evidence_id, status, "
                "expected, observed, evaluator_version, limitations) VALUES (:rid, :o, :sid, :aid, :ruid, :eid, 'FAIL', "
                "'{\"permit_root_login\": false}'::jsonb, '{\"permit_root_login\": true}'::jsonb, '1.0.0', '[]'::jsonb)"
            ),
            {"rid": result_id, "o": org_id, "sid": scan_id, "aid": asset1_id, "ruid": rule_id, "eid": evidence_id},
        )
        session.execute(
            text(
                "INSERT INTO cisguard.findings(id, org_id, result_id, severity) "
                "VALUES (:fid, :o, :rid, 'HIGH')"
            ),
            {"fid": finding_id, "o": org_id, "rid": result_id},
        )
        session.commit()

    # =========================================================================
    # PHASE 7 VERIFICATION: CP-SAT Plan Optimizer & Persistence
    # =========================================================================
    candidate = VettedCandidate(
        template_id=uuid4(),
        template_version="1.0.0",
        asset_id=asset1_id,
        targets_control_ids=["5.2.1"],
        platform_family="linux",
        expected_device_version="22.04",
        baseline_sha256="2" * 64,
        validated_parameters_ref=uuid4(),
        recovery="ROLLBACK",
        change_cost=10,
        blast_radius=15,
        supported=True,
    )
    constraints = PlanConstraints(
        finding_ids=[finding_id],
        safety_contract_ids=[safety_contract_id],
        max_change_cost=50,
    )
    plan_result = optimize_plan([candidate], {"5.2.1"}, constraints)
    assert plan_result.outcome == "FEASIBLE"
    assert len(plan_result.selected_actions) == 1

    plan_sha = compute_plan_sha256(plan_result.selected_actions, [safety_contract_id])

    with Session(db) as session:
        # Persist RemediationPlan
        session.add(
            DBPlan(
                id=plan_id,
                org_id=org_id,
                author_id=plan_author_id,
                plan_sha256=plan_sha,
                outcome="FEASIBLE",
                violated_constraints=[],
            )
        )
        session.flush()

        # Persist RemediationAction
        session.add(
            DBAction(
                id=action_id,
                org_id=org_id,
                plan_id=plan_id,
                asset_id=asset1_id,
                template_id=candidate.template_id,
                template_version="1.0.0",
                validated_parameters_ref=candidate.validated_parameters_ref,
                recovery="ROLLBACK",
            )
        )

        # Persist SafetyContract (e.g. web must reach db on port 5432)
        session.add(
            DBSafetyContract(
                id=safety_contract_id,
                org_id=org_id,
                source_asset_id=asset1_id,
                destination_asset_id=asset2_id,
                protocol="tcp",
                port=5432,
                mandatory=True,
                expected="REACHABLE",
            )
        )
        session.commit()

    # =========================================================================
    # PHASE 8 VERIFICATION: Approvals, Safety Gates, and Change State Machine
    # =========================================================================
    with Session(db) as session:
        # 1. SimulationRun
        session.add(
            DBSimulation(
                id=simulation_id,
                org_id=org_id,
                plan_id=plan_id,
                plan_sha256=plan_sha,
                verdict="SAFE_IN_MODEL",
                model_version="synthetic_v1",
                limitations=["Lab verified model"],
            )
        )
        session.flush()

        # 2. Approval (Separation of duties: approver_id != plan_author_id)
        # Database trigger guard_approval checks app.user_id == approver_id, app.aal == 'aal2', role == 'approver'
        assert approver_id != plan_author_id
        session.execute(
            text(
                "SELECT set_config('app.user_id', :u, true), "
                "set_config('app.org_id', :o, true), "
                "set_config('app.aal', 'aal2', true)"
            ),
            {"u": str(approver_id), "o": str(org_id)},
        )
        session.add(
            DBApproval(
                id=approval_id,
                org_id=org_id,
                plan_id=plan_id,
                plan_sha256=plan_sha,
                approver_id=approver_id,
                plan_author_id=plan_author_id,
                decision="APPROVED",
                reason="All controls validated and covered by rollback template",
                expires_at=now_utc.replace(year=now_utc.year + 1),
            )
        )
        session.flush()

        # 3. Change (operator_id != approver_id)
        # Database trigger guard_change_identity checks approval is approved and approver != operator
        assert operator_id != approver_id
        session.execute(
            text(
                "SELECT set_config('app.user_id', :u, true), "
                "set_config('app.org_id', :o, true), "
                "set_config('app.aal', 'aal2', true)"
            ),
            {"u": str(operator_id), "o": str(org_id)},
        )
        change_row = DBChange(
            id=change_id,
            org_id=org_id,
            plan_id=plan_id,
            approval_id=approval_id,
            simulation_id=simulation_id,
            operator_id=operator_id,
            state="APPROVED",
        )
        session.add(change_row)
        session.commit()

    # 4. State Machine Transitions
    with Session(db) as session:
        ch = session.scalar(select(DBChange).where(DBChange.org_id == org_id, DBChange.id == change_id))
        assert ch.state == "APPROVED"

        # Advance APPROVED -> EXECUTING
        _assert_transition(ch.state, "EXECUTING")
        ch.state = "EXECUTING"
        session.flush()

        # Advance EXECUTING -> VERIFYING
        _assert_transition(ch.state, "VERIFYING")
        ch.state = "VERIFYING"
        session.flush()

        # Advance VERIFYING -> VERIFIED
        _assert_transition(ch.state, "VERIFIED")
        ch.state = "VERIFIED"
        session.commit()

        # Terminal state: cannot transition further
        assert _TRANSITIONS["VERIFIED"] == []

    # =========================================================================
    # PHASE 9 VERIFICATION: Proof of Hardening, Ed25519 Signatures, & Drift
    # =========================================================================
    manifest = {
        "proof_id": str(proof_id),
        "org_id": str(org_id),
        "change_id": str(change_id),
        "plan_id": str(plan_id),
        "plan_sha256": plan_sha,
        "operator_id": str(operator_id),
        "approver_id": str(approver_id),
        "before_evidence": ["1" * 64],
        "after_evidence": ["3" * 64],
        "original_finding_ids": [str(finding_id)],
    }
    manifest_sha = compute_manifest_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha

    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature_b64, key_id = sign_manifest(manifest_bytes)

    # 1. Signature Verification
    assert verify_manifest_signature(manifest_bytes, signature_b64) is True

    # 2. Tamper Detection
    tampered_manifest = {**manifest, "plan_sha256": "f" * 64}
    tampered_bytes = json.dumps(tampered_manifest, sort_keys=True, separators=(",", ":")).encode()
    assert verify_manifest_signature(tampered_bytes, signature_b64) is False

    # 3. Residual Risk Calculation
    risk = calculate_residual_risk([finding_id], [])  # finding remediated
    assert risk["residual_count"] == 0
    assert risk["remediated_count"] == 1
    assert risk["risk_reduction_pct"] == 100.0

    # 4. Drift Event Persistence in Outbox
    with Session(db) as session:
        session.add(
            OutboxEvent(
                id=uuid4(),
                org_id=org_id,
                topic="cisguard.drift.detected",
                payload={"asset_id": str(asset1_id), "control_id": "5.2.1", "diff": {"sshd_config": "PermitRootLogin yes"}},
                published_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

        drift_count = session.execute(
            text("SELECT count(*) FROM cisguard.outbox_events WHERE org_id = :o AND topic = 'cisguard.drift.detected'"),
            {"o": org_id},
        ).scalar()
        assert drift_count == 1

    # =========================================================================
    # CLEANUP: Remove all synthetic live records cleanly in reverse dependency
    # =========================================================================
    with db.connect() as cleanup_conn:
        tx = cleanup_conn.begin()
        for tbl in [
            "verification_runs", "changes", "approvals", "simulation_runs",
            "safety_contracts", "remediation_actions", "remediation_plans",
            "reports", "notifications", "integrations", "asset_edges", "risk_scenarios",
            "risk_evidence", "manual_reviews", "exceptions", "policy_overrides",
            "findings", "audit_results", "policy_rules", "outbox_events", "audit_events",
            "config_snapshots", "audit_evidence", "scan_targets", "scan_jobs",
            "assets", "benchmark_packs", "credential_references", "authorization_scopes",
            "organization_members", "organizations",
        ]:
            if tbl == "organizations":
                cleanup_conn.execute(text("DELETE FROM cisguard.organizations WHERE id = :o"), {"o": org_id})
            else:
                cleanup_conn.execute(text(f"DELETE FROM cisguard.{tbl} WHERE org_id = :o"), {"o": org_id})
        tx.commit()

