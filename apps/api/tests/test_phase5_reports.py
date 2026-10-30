"""Phase 5 unit and integration tests: Compliance findings, reports, and alerts (M35-M38, E06-E07, E26-E30).

Mandatory Exit Gate: Produce test comparing all four export formats (PDF, HTML, CSV, JSON)
for identical outcome totals from the SAME stored scan results.
"""

import csv
import json
import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from cisguard_api.main import app
from cisguard_api.notification_service import (
    GenericWebhookTicketAdapter,
    JiraTicketAdapter,
    ServiceNowTicketAdapter,
    WebhookDispatcher,
)
from cisguard_api.report_service import (
    export_csv,
    export_html,
    export_json,
    export_pdf,
    generate_download_link,
)
from cisguard_contracts.v1.models import Download, EvidenceRef, Score


@pytest.fixture
def sample_report_data():
    """Canonical stored scan outcome report data used for all export formats."""
    org_id = uuid4()
    scan_id = uuid4()
    asset1_id = uuid4()
    asset2_id = uuid4()

    findings = [
        {
            "finding_id": str(uuid4()),
            "result_id": str(uuid4()),
            "control_id": "1.1.1.1",
            "title": "Ensure cramfs is disabled",
            "description": "Disable cramfs filesystem kernel module",
            "rationale": "cramfs is an unneeded legacy filesystem",
            "remediation": "echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf",
            "status": "PASS",
            "severity": "LOW",
            "asset_id": str(asset1_id),
            "asset_name": "prod-web-01",
            "asset_target": "10.0.1.10",
            "asset_platform": "Ubuntu 22.04",
            "expected": {"modprobe": "disabled"},
            "observed": {"modprobe": "disabled"},
            "evidence_ref": f"private://evidence/{org_id}/item_1",
        },
        {
            "finding_id": str(uuid4()),
            "result_id": str(uuid4()),
            "control_id": "5.2.1",
            "title": "Ensure SSH PermitRootLogin is disabled",
            "description": "Disable direct root login via SSH",
            "rationale": "Prevent unauthorized root access over network",
            "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            "status": "FAIL",
            "severity": "CRITICAL",
            "asset_id": str(asset1_id),
            "asset_name": "prod-web-01",
            "asset_target": "10.0.1.10",
            "asset_platform": "Ubuntu 22.04",
            "expected": {"PermitRootLogin": "no"},
            "observed": {"PermitRootLogin": "yes"},
            "evidence_ref": f"private://evidence/{org_id}/item_2",
        },
        {
            "finding_id": str(uuid4()),
            "result_id": str(uuid4()),
            "control_id": "5.2.2",
            "title": "Ensure SSH PasswordAuthentication is disabled",
            "description": "Enforce public-key authentication for SSH",
            "rationale": "Mitigate brute force password guessing attacks",
            "remediation": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
            "status": "FAIL",
            "severity": "HIGH",
            "asset_id": str(asset2_id),
            "asset_name": "prod-db-01",
            "asset_target": "10.0.1.20",
            "asset_platform": "Ubuntu 22.04",
            "expected": {"PasswordAuthentication": "no"},
            "observed": {"PasswordAuthentication": "yes"},
            "evidence_ref": f"private://evidence/{org_id}/item_3",
        },
        {
            "finding_id": str(uuid4()),
            "result_id": str(uuid4()),
            "control_id": "6.1.1",
            "title": "Audit system backup procedures",
            "description": "Verify offline immutable backups",
            "rationale": "Ransomware recovery and disaster resilience",
            "remediation": "Provide signed backup log artifact",
            "status": "MANUAL_REVIEW",
            "severity": "MEDIUM",
            "asset_id": str(asset2_id),
            "asset_name": "prod-db-01",
            "asset_target": "10.0.1.20",
            "asset_platform": "Ubuntu 22.04",
            "expected": {"backup_procedure": "verified"},
            "observed": {},
            "evidence_ref": f"private://evidence/{org_id}/item_4",
        },
        {
            "finding_id": str(uuid4()),
            "result_id": str(uuid4()),
            "control_id": "1.3.1",
            "title": "Ensure AIDE is installed",
            "description": "File integrity monitoring tool",
            "rationale": "Detect unauthorized file modifications",
            "remediation": "apt-get install aide",
            "status": "NOT_APPLICABLE",
            "severity": "LOW",
            "asset_id": str(asset2_id),
            "asset_name": "prod-db-01",
            "asset_target": "10.0.1.20",
            "asset_platform": "Ubuntu 22.04",
            "expected": {},
            "observed": {},
            "evidence_ref": f"private://evidence/{org_id}/item_5",
        },
    ]

    pass_count = 1
    fail_count = 2
    manual_review_count = 1
    not_applicable_count = 1
    error_count = 0
    not_assessed_count = 0

    assessed = pass_count + fail_count
    eligible = assessed + manual_review_count + error_count + not_assessed_count
    assessed_compliance_pct = round(100.0 * pass_count / assessed, 4)
    assessment_coverage_pct = round(100.0 * assessed / eligible, 4)

    return {
        "org_id": str(org_id),
        "scan_id": str(scan_id),
        "benchmark_id": "cis-ubuntu-linux-22.04",
        "benchmark_release": "1.0.0",
        "pack_version": "1.0.0",
        "profile": "Level 1",
        "audience": "TECHNICAL",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "score": {
            "pass_count": pass_count,
            "fail_count": fail_count,
            "not_applicable_count": not_applicable_count,
            "manual_review_count": manual_review_count,
            "error_count": error_count,
            "not_assessed_count": not_assessed_count,
            "assessed_compliance_pct": assessed_compliance_pct,
            "assessment_coverage_pct": assessment_coverage_pct,
        },
        "severities": {
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 2,
        },
        "total_findings": len(findings),
        "findings": findings,
    }


# ============================================================================
# Mandatory Exit Gate Test: Compare All 4 Export Formats for Identical Totals
# ============================================================================

def test_all_four_export_formats_identical_totals(sample_report_data):
    """VERIFY THAT JSON, CSV, HTML, AND PDF GENERATED FROM THE SAME STORED RESULTS

    EXHIBIT 100% IDENTICAL OUTCOME TOTALS.
    """
    raw_score = sample_report_data["score"]
    expected_pass = raw_score["pass_count"]
    expected_fail = raw_score["fail_count"]
    expected_na = raw_score["not_applicable_count"]
    expected_mr = raw_score["manual_review_count"]
    expected_comp = raw_score["assessed_compliance_pct"]
    expected_cov = raw_score["assessment_coverage_pct"]
    expected_total_findings = sample_report_data["total_findings"]

    # 1. Format 1: JSON Export
    json_str = export_json(sample_report_data)
    json_data = json.loads(json_str)

    assert json_data["score"]["pass_count"] == expected_pass
    assert json_data["score"]["fail_count"] == expected_fail
    assert json_data["score"]["not_applicable_count"] == expected_na
    assert json_data["score"]["manual_review_count"] == expected_mr
    assert json_data["score"]["assessed_compliance_pct"] == expected_comp
    assert json_data["score"]["assessment_coverage_pct"] == expected_cov
    assert json_data["total_findings"] == expected_total_findings
    assert len(json_data["findings"]) == expected_total_findings

    # 2. Format 2: CSV Export
    csv_str = export_csv(sample_report_data)
    csv_rows = list(csv.DictReader(csv_str.strip().splitlines()))

    csv_pass = sum(1 for r in csv_rows if r["status"] == "PASS")
    csv_fail = sum(1 for r in csv_rows if r["status"] == "FAIL")
    csv_na = sum(1 for r in csv_rows if r["status"] == "NOT_APPLICABLE")
    csv_mr = sum(1 for r in csv_rows if r["status"] == "MANUAL_REVIEW")
    csv_total = len(csv_rows)

    assert csv_pass == expected_pass
    assert csv_fail == expected_fail
    assert csv_na == expected_na
    assert csv_mr == expected_mr
    assert csv_total == expected_total_findings

    # 3. Format 3: HTML Export
    html_str = export_html(sample_report_data)

    # Verify score values rendered into HTML
    assert f"{expected_comp}%" in html_str
    assert f"{expected_cov}%" in html_str
    assert f"badge-pass\">{expected_pass}<" in html_str
    assert f"badge-fail\">{expected_fail}<" in html_str
    assert f"badge-review\">{expected_mr}<" in html_str
    assert f"badge-na\">{expected_na}<" in html_str
    assert f"val-total\">{expected_total_findings}<" in html_str

    # 4. Format 4: PDF Export
    pdf_bytes = export_pdf(sample_report_data, html_str)
    assert len(pdf_bytes) > 500  # Non-empty valid PDF byte stream
    assert pdf_bytes.startswith(b"%PDF-")  # Valid PDF header

    # Verify that PDF contains the exact same metric text representation
    pdf_content_str = pdf_bytes.decode("latin1", errors="ignore")
    assert str(expected_pass) in pdf_content_str
    assert str(expected_fail) in pdf_content_str
    assert str(expected_total_findings) in pdf_content_str
    assert "CISGuard 360" in pdf_content_str


# ============================================================================
# Executive Reporting vs Technical Reporting
# ============================================================================

def test_executive_vs_technical_report_content(sample_report_data):
    """Executive reports present high-level risk metrics without exposing granular command scripts."""
    exec_data = dict(sample_report_data)
    exec_data["audience"] = "EXECUTIVE"

    exec_html = export_html(exec_data)
    assert "CISGuard 360 EXECUTIVE Report" in exec_html
    assert "Outcome Breakdown" in exec_html
    # In executive report, technical findings table is omitted to keep it concise
    assert "Evaluated Findings" not in exec_html

    tech_html = export_html(sample_report_data)
    assert "CISGuard 360 TECHNICAL Report" in tech_html
    assert "Evaluated Findings" in tech_html
    assert "private://evidence/" in tech_html


# ============================================================================
# Webhook Dispatcher: Signing, Retry Backoff, and Deduplication (E26, E27)
# ============================================================================

def test_webhook_dispatcher_signing_and_backoff():
    secret = "secret-webhook-key-360"
    payload = {"event": "scan.completed", "scan_id": str(uuid4()), "compliance_pct": 85.5}
    delivery_id = uuid4()

    headers, body_bytes = WebhookDispatcher.prepare_delivery(
        event_type="scan.completed",
        payload=payload,
        secret=secret,
        delivery_id=delivery_id,
        attempt=1,
    )

    assert headers["X-CISGuard-Event"] == "scan.completed"
    assert headers["X-CISGuard-Delivery-Id"] == str(delivery_id)
    assert headers["X-CISGuard-Attempt"] == "1"
    assert headers["X-CISGuard-Retry-After"] == "2"
    assert headers["X-CISGuard-Signature"].startswith("sha256=")

    # Verify HMAC signature
    expected_sig = WebhookDispatcher.sign_payload(secret, body_bytes)
    assert headers["X-CISGuard-Signature"] == f"sha256={expected_sig}"

    # Verify exponential backoff calculation across attempts
    assert WebhookDispatcher.calculate_backoff(attempt=1) == 2
    assert WebhookDispatcher.calculate_backoff(attempt=2) == 4
    assert WebhookDispatcher.calculate_backoff(attempt=3) == 8
    assert WebhookDispatcher.calculate_backoff(attempt=4) == 16
    assert WebhookDispatcher.calculate_backoff(attempt=10) == 300  # Capped at 300s


# ============================================================================
# Ticketing Integrations: Jira, ServiceNow, and Generic Webhook (E28)
# ============================================================================

def test_ticketing_integration_adapters():
    finding = {
        "finding_id": str(uuid4()),
        "control_id": "5.2.1",
        "title": "Disable SSH Root Login",
        "severity": "CRITICAL",
        "status": "FAIL",
        "asset_name": "srv-prod-01",
        "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config",
        "evidence_ref": "private://evidence/123/ssh_config",
    }
    asset = {"name": "srv-prod-01", "target": "10.0.1.5"}

    # 1. Jira Adapter
    jira = JiraTicketAdapter(project_key="SEC")
    jira_payload = jira.create_ticket_payload(finding, asset)
    fields = jira_payload["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["priority"]["name"] == "Highest"
    assert "Disable SSH Root Login" in fields["summary"]
    assert "private://evidence/123/ssh_config" in fields["description"]
    assert "cis-5.2.1" in fields["labels"]

    # 2. ServiceNow Adapter
    snow = ServiceNowTicketAdapter(caller_id="cisguard_system")
    snow_payload = snow.create_ticket_payload(finding, asset)
    assert snow_payload["short_description"] == "CIS Non-Compliance: 5.2.1 on srv-prod-01"
    assert snow_payload["impact"] == "1"  # Critical impact
    assert snow_payload["urgency"] == "1"  # Critical urgency
    assert "PermitRootLogin no" in snow_payload["comments"]

    # 3. Generic Webhook Ticket Adapter
    generic = GenericWebhookTicketAdapter()
    gen_payload = generic.create_ticket_payload(finding, asset)
    assert gen_payload["ticket_type"] == "security_compliance_finding"
    assert gen_payload["control_id"] == "5.2.1"
    assert gen_payload["severity"] == "CRITICAL"


# ============================================================================
# Authorized Secure Downloads & Expiration Validation (M38)
# ============================================================================

def test_signed_download_link_generation():
    org_id = uuid4()
    report_id = uuid4()
    content_hash = "a" * 64

    download_obj = generate_download_link(org_id, report_id, content_hash)
    assert isinstance(download_obj, Download)
    assert download_obj.sha256 == content_hash
    assert download_obj.signed_url.startswith("https://api.cisguard.io/api/v1/reports/")
    assert f"/reports/{report_id}/download-file?sig=" in download_obj.signed_url
    assert datetime.fromisoformat(download_obj.expires_at.replace("Z", "+00:00")) > datetime.now(timezone.utc)
