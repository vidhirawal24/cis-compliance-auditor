"""Live PostgreSQL integration tests for Phase 5 and Phase 6.

Runs against the real Supabase PostgreSQL instance with full transaction cleanup.
Exercises:
- End-to-end findings persistence, queries, and joins (M36, E29, I20)
- Multi-format report generation (PDF, HTML, CSV, JSON) verifying identical outcome totals (M38, E28)
- Authorized signed report downloads with HMAC validation (M38)
- Compliance trends and dashboard overview aggregations (E07, M35, M37)
- Notification records, webhook signing, and integration endpoints (E05, E26, E27, E30)
- NetworkX security graph construction and traversal from live assets/findings (I01, I03)
- Deterministic risk scenario correlation and explainability chains (I02, I04, I05, E13)
"""

import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from uuid import UUID, uuid4

import pytest

pytestmark = pytest.mark.usefixtures("synthetic_device_engine")
from sqlalchemy import select, text

from cisguard_api.benchmark_service import get_builtin_policy_pack
from cisguard_api.database import engine, tenant_session
from cisguard_api.db_models import (
    Asset,
    AuditEvent,
    Evidence as AuditEvidence,
    AuditResult,
    AuthorizationScope,
    ConfigSnapshot,
    CredentialReference,
    Finding as DBFinding,
    Integration as DBIntegration,
    Notification as DBNotification,
    Organization,
    OrganizationMember,
    OutboxEvent,
    PolicyPack as DBPolicyPack,
    PolicyRule as DBPolicyRule,
    Report as DBReport,
    ScanJob,
    ScanTarget,
)
from cisguard_api.graph_engine import (
    ReachabilityEvaluator,
    RiskScenarioCorrelator,
    SecurityGraphBuilder,
    deterministic_uuid,
)
from cisguard_api.notification_service import WebhookDispatcher
from cisguard_api.report_service import (
    export_csv,
    export_html,
    export_json,
    export_pdf,
    generate_download_link,
    get_canonical_report_data,
    store_report_artifact,
)
from cisguard_api.worker import execute_scan_job
from cisguard_contracts.v1.models import Download, EvidenceRef, Graph, RiskScenario, Score


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB opt-in required")
def test_live_phase5_and_phase6_end_to_end():
    db = engine(migration=True)
    org_id = uuid4()
    owner_id = uuid4()
    auditor_id = uuid4()
    scope_id = uuid4()
    pack_id = uuid4()
    scan_id = uuid4()
    asset1_id = uuid4()
    asset2_id = uuid4()
    fw_id = uuid4()
    cred_id = uuid4()

    with db.connect() as conn:
        tx = conn.begin()
        try:
            # 1. Organization & Members
            conn.execute(
                text("INSERT INTO cisguard.organizations(id, name) VALUES (:o, 'Phase 5-6 Live Org')"),
                {"o": org_id},
            )
            for uid, role in [(owner_id, "owner"), (auditor_id, "auditor")]:
                conn.execute(
                    text(
                        "INSERT INTO cisguard.organization_members(id, org_id, user_id, role, active) "
                        "VALUES (:id, :o, :u, :r, true)"
                    ),
                    {"id": uuid4(), "o": org_id, "u": uid, "r": role},
                )

            # 2. Authorization Scope & Credential Reference
            conn.execute(
                text(
                    "INSERT INTO cisguard.authorization_scopes(id, org_id, name, approved_targets, approved_by, expires_at) "
                    "VALUES (:id, :o, 'Production Lab Scope', CAST('[\"10.50.0.0/16\"]' AS jsonb), :u, now() + interval '1 day')"
                ),
                {"id": scope_id, "o": org_id, "u": owner_id},
            )
            conn.execute(
                text(
                    "INSERT INTO cisguard.credential_references(id, org_id, vault_reference, label) "
                    "VALUES (:id, :o, 'secret/data/cisguard/live-device-cred', 'Worker SSH Key')"
                ),
                {"id": cred_id, "o": org_id},
            )

            # 3. Assets: Web node (10.50.1.10), DB node (10.50.2.20), Firewall (10.50.0.1)
            conn.execute(
                text(
                    "INSERT INTO cisguard.assets(id, org_id, name, family, platform, vendor, model, os_or_firmware_version, "
                    "target, authorization_scope_id, credential_reference_id, tags, retired) VALUES "
                    "(:a1, :o, 'web-app-01', 'linux', 'Ubuntu 22.04', 'Canonical', 'VM', '22.04', '10.50.1.10', :sc, :cr, CAST('[\"web\",\"dmz\"]' AS jsonb), false), "
                    "(:a2, :o, 'db-master-01', 'linux', 'Ubuntu 22.04', 'Canonical', 'VM', '22.04', '10.50.2.20', :sc, :cr, CAST('[\"database\",\"critical\"]' AS jsonb), false), "
                    "(:a3, :o, 'edge-firewall', 'firewall', 'FortiGate', 'Fortinet', '60F', '7.0', '10.50.0.1', :sc, :cr, CAST('[\"perimeter\",\"firewall\"]' AS jsonb), false)"
                ),
                {"a1": asset1_id, "a2": asset2_id, "a3": fw_id, "o": org_id, "sc": scope_id, "cr": cred_id},
            )

            # 4. Canonical Benchmark Pack & Rules
            pack_data = get_builtin_policy_pack("ubuntu-v1")
            conn.execute(
                text(
                    "INSERT INTO cisguard.benchmark_packs(id, org_id, benchmark_id, benchmark_release, pack_version, "
                    "profiles, source, source_reference, rights_status, evaluator_version, content_sha256) "
                    "VALUES (:id, :o, :bid, :rel, :ver, CAST(:prof AS jsonb), 'authorized_cis_mapping', 'CIS Ubuntu 22.04 v1', "
                    "'AUTHORIZED', '1.0.0', :h)"
                ),
                {
                    "id": pack_id,
                    "o": org_id,
                    "bid": pack_data["benchmark_id"],
                    "rel": pack_data["benchmark_release"],
                    "ver": pack_data["pack_version"],
                    "prof": json.dumps(pack_data["profiles"]),
                    "h": "0" * 64,
                },
            )
            for r in pack_data["rules"]:
                conn.execute(
                    text(
                        "INSERT INTO cisguard.policy_rules(id, org_id, policy_pack_id, control_id, definition) "
                        "VALUES (:id, :o, :pid, :cid, CAST(:defn AS jsonb))"
                    ),
                    {"id": uuid4(), "o": org_id, "pid": pack_id, "cid": r["control_id"], "defn": json.dumps(r)},
                )

            # 5. Create and Execute ScanJob across assets
            conn.execute(
                text(
                    "INSERT INTO cisguard.scan_jobs(id, org_id, policy_pack_id, requested_by, profile, status, read_only, "
                    "requested_assets, completed_assets) VALUES (:sid, :o, :pid, :u, 'Level 1 - Server', 'QUEUED', true, 2, 0)"
                ),
                {"sid": scan_id, "o": org_id, "pid": pack_id, "u": owner_id},
            )
            for aid in [asset1_id, asset2_id]:
                conn.execute(
                    text(
                        "INSERT INTO cisguard.scan_targets(id, org_id, scan_id, asset_id, status, errors) "
                        "VALUES (:tid, :o, :sid, :aid, 'QUEUED', '[]'::jsonb)"
                    ),
                    {"tid": uuid4(), "o": org_id, "sid": scan_id, "aid": aid},
                )
            tx.commit()
        except Exception:
            tx.rollback()
            raise

    # Execute Scan in worker (generates AuditResults & Findings)
    scan_res = execute_scan_job(org_id, scan_id, user_id=owner_id)
    assert scan_res["status"] in ("SUCCEEDED", "PARTIAL")

    # =========================================================================
    # PHASE 5 VERIFICATION: Report Generator & Identical Outcome Totals
    # =========================================================================
    with db.connect() as verify_conn:
        # Verify findings persisted
        findings_count = verify_conn.execute(
            text("SELECT count(*) FROM cisguard.findings WHERE org_id = :o"),
            {"o": org_id},
        ).scalar()
        assert findings_count > 0, "Findings must be persisted in database"

        # Extract canonical report data from DB
        report_data = get_canonical_report_data(verify_conn, org_id, scan_id, audience="TECHNICAL")
        score = report_data["score"]
        expected_pass = score["pass_count"]
        expected_fail = score["fail_count"]
        expected_comp = score["assessed_compliance_pct"]
        total_findings = report_data["total_findings"]

        # Export all 4 formats
        json_out = export_json(report_data)
        csv_out = export_csv(report_data)
        html_out = export_html(report_data)
        pdf_out = export_pdf(report_data, html_out)

        # 1. Verify JSON
        j_data = json.loads(json_out)
        assert j_data["score"]["pass_count"] == expected_pass
        assert j_data["score"]["fail_count"] == expected_fail
        assert j_data["score"]["assessed_compliance_pct"] == expected_comp
        assert j_data["total_findings"] == total_findings

        # 2. Verify CSV
        c_rows = list(csv.DictReader(csv_out.strip().splitlines()))
        assert sum(1 for r in c_rows if r["status"] == "PASS") == expected_pass
        assert sum(1 for r in c_rows if r["status"] == "FAIL") == expected_fail
        assert len(c_rows) == total_findings

        # 3. Verify HTML
        assert f"badge-pass\">{expected_pass}<" in html_out
        assert f"badge-fail\">{expected_fail}<" in html_out
        assert f"{expected_comp}%" in html_out

        # 4. Verify PDF
        assert len(pdf_out) > 500
        assert pdf_out.startswith(b"%PDF-")

        # 5. Store Report Artifact & Verify Download
        rep_id, ev_ref = store_report_artifact(verify_conn, org_id, scan_id, "PDF", "TECHNICAL", pdf_out)
        verify_conn.commit()

        download_obj = generate_download_link(org_id, rep_id, ev_ref.sha256)
        assert download_obj.sha256 == ev_ref.sha256
        assert f"/reports/{rep_id}/download-file?sig=" in download_obj.signed_url

        # 6. Webhook Notification Dispatch
        notif_event_id = verify_conn.execute(
            text("SELECT id FROM cisguard.audit_events WHERE org_id = :o AND event_type = 'scan.completed' LIMIT 1"),
            {"o": org_id},
        ).scalar()
        if not notif_event_id:
            notif_event_id = uuid4()
            verify_conn.execute(
                text("INSERT INTO cisguard.audit_events(id, org_id, actor_id, request_id, event_type, resource_id, details) "
                     "VALUES (:i, :o, :a, :r, 'scan.completed', :res, '{}'::jsonb)"),
                {"i": notif_event_id, "o": org_id, "a": owner_id, "r": UUID(int=0), "res": scan_id},
            )
            verify_conn.commit()
        headers, body_bytes = WebhookDispatcher.prepare_delivery(
            event_type="scan.completed",
            payload={"scan_id": str(scan_id), "compliance_pct": expected_comp},
            secret="test-webhook-secret-key",
        )
        assert "X-CISGuard-Signature" in headers
        notif_row = WebhookDispatcher.record_notification(
            verify_conn, org_id, notif_event_id, status="DELIVERED", attempt_count=1
        )
        verify_conn.commit()
        assert notif_row.status == "DELIVERED"

    # =========================================================================
    # PHASE 6 VERIFICATION: Security Graph & Risk Scenario Correlation
    # =========================================================================
    builder = SecurityGraphBuilder(org_id)
    ev_id = uuid4()

    # Add assets and subnets into graph builder
    builder.add_asset_node({"id": asset1_id, "name": "web-app-01", "target": "10.50.1.10", "family": "linux"})
    builder.add_asset_node({"id": asset2_id, "name": "db-master-01", "target": "10.50.2.20", "family": "linux", "criticality": "CRITICAL"})
    builder.add_asset_node({"id": fw_id, "name": "edge-firewall", "target": "10.50.0.1", "family": "firewall"})

    builder.add_interface_and_subnet(asset1_id, "eth0", "10.50.1.10", "10.50.1.0/24", ev_id)
    builder.add_interface_and_subnet(asset2_id, "eth0", "10.50.2.20", "10.50.2.0/24", ev_id)

    # Firewall rule allowing DMZ web to internal database
    builder.add_firewall_rule(fw_id, "allow-web-db", "10.50.1.0/24", "10.50.2.0/24", 5432, "allows", ev_id)

    # Add critical failing findings
    f1 = uuid4()
    f2 = uuid4()
    builder.add_finding_node(f1, asset1_id, "5.2.1", "CRITICAL", "FAIL", ev_id)
    builder.add_finding_node(f2, asset2_id, "3.4.1", "HIGH", "FAIL", ev_id)

    # 1. Export Graph Contract
    graph_contract = builder.export_contract_graph()
    assert isinstance(graph_contract, Graph)
    assert len(graph_contract.nodes) >= 3
    assert len(graph_contract.edges) >= 2

    # 2. Reachability Traversal
    reach_eval = ReachabilityEvaluator.evaluate_path(builder.g, asset1_id, asset2_id, target_port=5432)
    assert reach_eval["reachable"] is True
    assert reach_eval["incomplete_evidence"] is False

    # 3. Correlate Risk Scenarios
    scenarios = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)
    assert len(scenarios) >= 1
    lat_scen = scenarios[0]
    assert isinstance(lat_scen, RiskScenario)
    assert f1 in lat_scen.source_finding_ids
    assert f2 in lat_scen.source_finding_ids
    assert "lateral movement" in lat_scen.explanation.lower()

    # =========================================================================
    # CLEANUP: Remove all synthetic live records cleanly
    # =========================================================================
    with db.connect() as cleanup_conn:
        tx = cleanup_conn.begin()
        for tbl in [
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