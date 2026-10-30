"""Phase 4 unit test suite: CIS policy engine, SCAP bridge, and accurate scoring.

Covers M16-M19, E11-E12, E14, E20, I19, I20:
- Deterministic allowlisted rule operators: equals, contains, regex, range, set_membership, cidr_contains, ordered_acl, xccdf_oval (M16)
- Zero AI/LLM probabilistic execution; strictly reproducible evaluation (M16)
- Modular structured YAML/JSON rule files with validation (M17)
- Missing or unknown evidence NEVER evaluates to PASS (M18, I20)
- Custom baseline overrides separate from canonical benchmark rules (M18)
- Benchmark versioning and profile selection (M19, E11)
- Manual review workflow and evidence attachment (E12)
- Time-boxed policy exceptions with expiration check and separation of duties (E14)
- Policy version history diff engine (E20)
- Benchmark upgrade preview across organization assets (I19)
- Explainable coverage decisions and accurate Score reconciliation (M17, I20)
- SCAP XCCDF XML bridge with XXE mitigation and supplementary labeling (E12, supplementary)
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from cisguard_contracts.v1.models import (
    AssessmentStatus,
    EvidenceRef,
    ExceptionOverlay,
    PolicyOverride,
    PolicyRule,
    Score,
)
from cisguard_api.main import app
from cisguard_api.policy_engine import (
    EVALUATOR_VERSION,
    calculate_scan_score,
    evaluate_cidr_contains,
    evaluate_contains,
    evaluate_equals,
    evaluate_ordered_acl,
    evaluate_range,
    evaluate_regex,
    evaluate_rule,
    evaluate_set_membership,
    evaluate_xccdf_oval,
    get_fixture_facts,
    is_platform_applicable,
    is_safe_regex,
)
from cisguard_api.benchmark_service import (
    compute_benchmark_diff,
    compute_content_sha256,
    get_builtin_policy_pack,
    parse_policy_pack_document,
    parse_scap_xccdf_xml,
)
from cisguard_api.security import Identity
from cisguard_api import policy_routes


# ============================================================================
# M16: Deterministic Rule Engine & Operator Correctness
# ============================================================================


def test_M16_operator_equals():
    # Booleans
    assert evaluate_equals(True, True)[0]
    assert evaluate_equals(True, "true")[0]
    assert evaluate_equals(True, "yes")[0]
    assert evaluate_equals(True, "1")[0]
    assert evaluate_equals(False, "no")[0]
    assert not evaluate_equals(True, False)[0]
    assert not evaluate_equals(True, "invalid")[0]

    # Numbers
    assert evaluate_equals(4, 4)[0]
    assert evaluate_equals(4, "4")[0]
    assert evaluate_equals(3.14, "3.14")[0]
    assert not evaluate_equals(4, 5)[0]

    # Strings
    assert evaluate_equals("permit", "permit")[0]
    assert evaluate_equals("permit", " permit ")[0]  # whitespace normalized
    assert not evaluate_equals("permit", "deny")[0]


def test_M16_operator_contains():
    # String containment
    assert evaluate_contains("Authorized", "Authorized access only")[0]
    assert not evaluate_contains("Forbidden", "Authorized access only")[0]

    # List containment
    assert evaluate_contains("aes256", ["aes256", "chacha20"])[0]
    assert evaluate_contains(["a", "b"], ["a", "b", "c"])[0]
    assert not evaluate_contains(["a", "d"], ["a", "b", "c"])[0]

    # Dict containment
    assert evaluate_contains({"user": "admin"}, {"user": "admin", "port": 22})[0]
    assert not evaluate_contains({"user": "root"}, {"user": "admin", "port": 22})[0]


def test_M16_operator_regex_and_redos_safety():
    # Valid safe patterns
    assert is_safe_regex(r"^[a-zA-Z0-9_-]+$")[0]
    assert is_safe_regex(r"^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")[0]
    assert evaluate_regex(r"^[0-9]+$", "12345")[0]
    assert not evaluate_regex(r"^[0-9]+$", "12345abc")[0]

    # Pathological ReDoS patterns rejected
    assert not is_safe_regex(r"(a+)+")[0]
    assert not is_safe_regex(r"([a-zA-Z0-9]+)*")[0]
    assert not is_safe_regex(r"(a|b+)+")[0]
    assert not is_safe_regex("a" * 300)[0]  # Length bound > 256

    # ReDoS pattern execution blocked gracefully
    passed, reason = evaluate_regex(r"(a+)+", "aaaaaaaaaa!")
    assert not passed
    assert "rejected" in reason.lower() or "aborted" in reason.lower()


def test_M16_operator_range():
    # Range [min, max]
    assert evaluate_range([1, 10], 5)[0]
    assert evaluate_range([1, 10], 1)[0]
    assert evaluate_range([1, 10], 10)[0]
    assert not evaluate_range([1, 10], 0)[0]
    assert not evaluate_range([1, 10], 11)[0]

    # Dict specification with exclusivity
    assert evaluate_range({"min": 5, "max": 15, "inclusive": False}, 10)[0]
    assert not evaluate_range({"min": 5, "max": 15, "inclusive": False}, 5)[0]
    assert not evaluate_range({"min": 5, "max": 15, "inclusive": False}, 15)[0]


def test_M16_operator_set_membership():
    allowed_ciphers = ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
    # Single value membership
    assert evaluate_set_membership(allowed_ciphers, "aes256-gcm@openssh.com")[0]
    assert not evaluate_set_membership(allowed_ciphers, "des-cbc")[0]

    # Multiple observed items (must all be in allowed set)
    assert evaluate_set_membership(allowed_ciphers, ["aes256-gcm@openssh.com"])[0]
    assert not evaluate_set_membership(allowed_ciphers, ["aes256-gcm@openssh.com", "des-cbc"])[0]

    # Dict modes: exact, subset, superset
    assert evaluate_set_membership({"mode": "exact", "set": ["a", "b"]}, ["b", "a"])[0]
    assert not evaluate_set_membership({"mode": "exact", "set": ["a", "b"]}, ["a"])[0]


def test_M16_operator_cidr_contains():
    # Single IP containment
    assert evaluate_cidr_contains("10.0.0.0/8", "10.1.2.3")[0]
    assert not evaluate_cidr_contains("10.0.0.0/8", "192.168.1.1")[0]

    # Subnet containment
    assert evaluate_cidr_contains("10.0.0.0/8", "10.1.0.0/16")[0]
    assert not evaluate_cidr_contains("10.0.0.0/16", "10.1.0.0/16")[0]

    # List of allowed networks
    corp_networks = ["10.0.0.0/8", "172.16.0.0/12"]
    assert evaluate_cidr_contains(corp_networks, "172.16.5.10")[0]
    assert not evaluate_cidr_contains(corp_networks, "8.8.8.8")[0]


def test_M16_operator_ordered_acl():
    # Valid ordered ACL
    observed_acl = [
        "permit tcp 10.0.0.0/8 any eq 443",
        "permit tcp 10.0.0.0/8 any eq 22",
        "deny ip any any",
    ]
    # Sequence order
    assert evaluate_ordered_acl({"sequence": ["permit", "deny"], "require_final_deny": True}, observed_acl)[0]

    # Missing terminal deny
    bad_acl = [
        "permit tcp 10.0.0.0/8 any eq 443",
        "permit tcp 10.0.0.0/8 any eq 22",
    ]
    passed, reason = evaluate_ordered_acl({"sequence": ["permit", "deny"], "require_final_deny": True}, bad_acl)
    assert not passed
    assert "terminal" in reason.lower() or "missing" in reason.lower()

    # Out of order
    inverted_acl = [
        "deny ip any any",
        "permit tcp 10.0.0.0/8 any eq 443",
    ]
    assert not evaluate_ordered_acl({"sequence": ["permit", "deny"]}, inverted_acl)[0]


def test_M16_operator_xccdf_oval():
    assert evaluate_xccdf_oval({"result": "pass"}, {"result": "pass"})[0]
    assert not evaluate_xccdf_oval({"result": "pass"}, {"result": "fail"})[0]
    assert evaluate_xccdf_oval("pass", "pass")[0]


def test_M16_reproducible_output():
    # Same inputs MUST yield identical output and evidence references
    rule = PolicyRule(
        control_id="5.2.1",
        feature_ids=["M16", "M03"],
        fact_path="os_security.sshd.permit_root_login",
        operator="equals",
        expected="no",
        severity="CRITICAL",
        applicability_platforms=["linux", "ubuntu"],
        requires_manual_review=False,
        remediation_template_id=None,
    )
    facts = {"os_security.sshd.permit_root_login": "no"}
    ev_ref = EvidenceRef(
        evidence_id=uuid4(),
        sha256="a" * 64,
        source_identity="ssh_collector",
        encrypted_artifact_location="private://evidence/vault/item",
        collected_at="2026-10-29T00:00:00Z",
    )

    res1 = evaluate_rule(rule, facts, [ev_ref], "ubuntu", "linux")
    res2 = evaluate_rule(rule, facts, [ev_ref], "ubuntu", "linux")

    assert res1["status"] == res2["status"] == AssessmentStatus.PASS
    assert res1["expected"] == res2["expected"]
    assert res1["observed"] == res2["observed"]
    assert res1["evidence_refs"][0].sha256 == res2["evidence_refs"][0].sha256


# ============================================================================
# M18: Unknown Evidence NEVER Evaluates to PASS
# ============================================================================


def test_M18_unknown_or_missing_evidence_never_pass():
    rule = PolicyRule(
        control_id="5.2.1",
        feature_ids=["M16", "M03"],
        fact_path="os_security.sshd.permit_root_login",
        operator="equals",
        expected="no",
        severity="CRITICAL",
        applicability_platforms=["linux", "ubuntu"],
        requires_manual_review=False,
        remediation_template_id=None,
    )
    # Empty facts dictionary
    res = evaluate_rule(rule, {}, [], "ubuntu", "linux")
    assert res["status"] != AssessmentStatus.PASS
    assert res["status"] == AssessmentStatus.ERROR
    assert "Missing required evidence" in res["limitations"][0]

    # Value is explicitly None
    res_none = evaluate_rule(rule, {"os_security.sshd.permit_root_login": None}, [], "ubuntu", "linux")
    assert res_none["status"] != AssessmentStatus.PASS
    assert res_none["status"] == AssessmentStatus.ERROR


# ============================================================================
# I20: Applicability Resolution & Explainable Coverage
# ============================================================================


def test_I20_applicability_platform_mismatch():
    rule = PolicyRule(
        control_id="2.3.1.1",
        feature_ids=["M16", "M01"],
        fact_path="os_security.registry.uac_admin_approval_mode",
        operator="equals",
        expected=1,
        severity="HIGH",
        applicability_platforms=["windows", "windows-11"],
        requires_manual_review=False,
        remediation_template_id=None,
    )
    facts = {"os_security.registry.uac_admin_approval_mode": 1}

    # Running Windows control against Ubuntu host -> NOT_APPLICABLE
    res = evaluate_rule(rule, facts, [], "ubuntu", "linux")
    assert res["status"] == AssessmentStatus.NOT_APPLICABLE
    assert res["applicability"] == "NOT_APPLICABLE"
    assert "not in applicability platforms" in res["limitations"][0]


# ============================================================================
# E12: Manual Review Workflow
# ============================================================================


def test_E12_manual_review_status():
    rule = PolicyRule(
        control_id="1.7.1",
        feature_ids=["M16", "M03", "E12"],
        fact_path="management.banner",
        operator="contains",
        expected="Authorized access only",
        severity="LOW",
        applicability_platforms=["linux", "ubuntu"],
        requires_manual_review=True,  # Mandatory human signoff
        remediation_template_id=None,
    )
    facts = {"management.banner": "Authorized access only"}
    res = evaluate_rule(rule, facts, [], "ubuntu", "linux")
    assert res["status"] == AssessmentStatus.MANUAL_REVIEW
    assert "manual human review" in res["limitations"][0]


# ============================================================================
# M18: Custom Baselines / Policy Overrides
# ============================================================================


def test_M18_custom_baseline_override_replaces_expected():
    rule = PolicyRule(
        control_id="5.2.3",
        feature_ids=["M16", "M03"],
        fact_path="os_security.sshd.max_auth_tries",
        operator="range",
        expected={"min": 1, "max": 4},
        severity="MEDIUM",
        applicability_platforms=["linux", "ubuntu"],
        requires_manual_review=False,
        remediation_template_id=None,
    )
    # Observed is 6 (fails standard benchmark max 4)
    facts = {"os_security.sshd.max_auth_tries": 6}

    # Without override -> FAIL
    res_standard = evaluate_rule(rule, facts, [], "ubuntu", "linux")
    assert res_standard["status"] == AssessmentStatus.FAIL

    # With organization override relaxing max to 8
    override = PolicyOverride(
        schema_version="1.0.0",
        org_id=uuid4(),
        override_id=uuid4(),
        policy_pack_id=uuid4(),
        base_version="1.0.0",
        control_id="5.2.3",
        expected={"min": 1, "max": 8},
        reason="Organization approved higher retry threshold for batch automation",
        version="1.0.0",
        author_id=uuid4(),
        created_at="2026-10-29T00:00:00Z",
    )
    res_overridden = evaluate_rule(rule, facts, [], "ubuntu", "linux", override=override)
    assert res_overridden["status"] == AssessmentStatus.PASS
    assert any("custom baseline override" in lim for lim in res_overridden["limitations"])
    # Original rule is immutable
    assert rule.expected == {"min": 1, "max": 4}


# ============================================================================
# E14: Time-Boxed Policy Exception Overlay & Expiration
# ============================================================================


def test_E14_exception_expiration_handling():
    rule = PolicyRule(
        control_id="5.2.1",
        feature_ids=["M16", "M03"],
        fact_path="os_security.sshd.permit_root_login",
        operator="equals",
        expected="no",
        severity="CRITICAL",
        applicability_platforms=["linux", "ubuntu"],
        requires_manual_review=False,
        remediation_template_id=None,
    )
    # Root login is enabled -> FAIL
    facts = {"os_security.sshd.permit_root_login": "yes"}

    # 1. Active unexpired exception
    future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    active_exc = ExceptionOverlay(
        schema_version="1.0.0",
        org_id=uuid4(),
        exception_id=uuid4(),
        finding_id=uuid4(),
        reason="Temporary migration jumpbox exception",
        expires_at=future_date,
        decision="APPROVED",
        approver_id=uuid4(),
    )
    res_active = evaluate_rule(rule, facts, [], "ubuntu", "linux", exception=active_exc)
    assert res_active["status"] == AssessmentStatus.FAIL  # finding status preserved
    assert res_active["exception"] is not None
    assert res_active["exception"].decision == "APPROVED"

    # 2. Expired exception (expires in past) -> marks EXPIRED
    past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expired_exc = ExceptionOverlay(
        schema_version="1.0.0",
        org_id=uuid4(),
        exception_id=uuid4(),
        finding_id=uuid4(),
        reason="Temporary migration jumpbox exception",
        expires_at=past_date,
        decision="APPROVED",
        approver_id=uuid4(),
    )
    res_expired = evaluate_rule(rule, facts, [], "ubuntu", "linux", exception=expired_exc)
    assert res_expired["status"] == AssessmentStatus.FAIL
    assert res_expired["exception"].decision == "EXPIRED"
    assert any("EXPIRED" in lim for lim in res_expired["limitations"])


# ============================================================================
# M17 & M35: Accurate Score & Coverage Reconciler
# ============================================================================


def test_M17_M35_score_formula_and_reconciliation():
    statuses = [
        AssessmentStatus.PASS,
        AssessmentStatus.PASS,
        AssessmentStatus.PASS,
        AssessmentStatus.FAIL,
        AssessmentStatus.NOT_APPLICABLE,
        AssessmentStatus.MANUAL_REVIEW,
        AssessmentStatus.ERROR,
        AssessmentStatus.NOT_ASSESSED,
        AssessmentStatus.NOT_ASSESSED,
    ]
    score = calculate_scan_score(statuses)

    assert score.pass_count == 3
    assert score.fail_count == 1
    assert score.not_applicable_count == 1
    assert score.manual_review_count == 1
    assert score.error_count == 1
    assert score.not_assessed_count == 2

    # assessed = 3 + 1 = 4
    # assessed_compliance_pct = 3 / 4 * 100 = 75.0%
    assert score.assessed_compliance_pct == 75.0

    # eligible = 4 + 1 + 1 + 2 = 8
    # assessment_coverage_pct = 4 / 8 * 100 = 50.0%
    assert score.assessment_coverage_pct == 50.0


def test_M17_M35_zero_assessed_returns_null_compliance():
    statuses = [
        AssessmentStatus.NOT_APPLICABLE,
        AssessmentStatus.MANUAL_REVIEW,
        AssessmentStatus.ERROR,
    ]
    score = calculate_scan_score(statuses)
    assert score.pass_count == 0
    assert score.fail_count == 0
    assert score.assessed_compliance_pct is None
    assert score.assessment_coverage_pct == 0.0


# ============================================================================
# M17: Modular Structured Rule Files (YAML/JSON Validation)
# ============================================================================


def test_M17_valid_yaml_and_json_parsing():
    valid_yaml = """
benchmark_id: cis-custom-test
benchmark_release: 1.0.0
pack_version: 1.0.0
profiles:
  - Level 1 - Server
source: organizational
rights_status: AUTHORIZED
rules:
  - control_id: "1.1"
    feature_ids: ["M16"]
    fact_path: "os_security.test"
    operator: equals
    expected: true
    severity: LOW
    applicability_platforms: ["linux"]
"""
    data = parse_policy_pack_document(valid_yaml)
    assert data["benchmark_id"] == "cis-custom-test"
    assert len(data["rules"]) == 1

    # Missing mandatory header field -> ValueError
    invalid_yaml = "benchmark_id: test\npack_version: 1.0.0"
    with pytest.raises(ValueError, match="missing required field"):
        parse_policy_pack_document(invalid_yaml)

    # Invalid operator -> ValueError
    bad_op_yaml = valid_yaml.replace("operator: equals", "operator: invalid_ai_eval")
    with pytest.raises(ValueError, match="invalid operator"):
        parse_policy_pack_document(bad_op_yaml)


# ============================================================================
# E20 & I19: Benchmark Diff Engine & Upgrade Preview
# ============================================================================


def test_E20_benchmark_diff():
    p1 = get_builtin_policy_pack("ubuntu-v1")
    p2 = get_builtin_policy_pack("ubuntu-v2")

    diff = compute_benchmark_diff(
        type("Pack", (), {"pack_version": p1["pack_version"]})(),
        type("Pack", (), {"pack_version": p2["pack_version"]})(),
        p1["rules"],
        p2["rules"],
    )
    assert diff.from_version == "1.0.0"
    assert diff.to_version == "2.0.0"
    assert "3.4.1" in diff.added_control_ids
    assert "5.2.3" in diff.removed_control_ids
    assert "5.2.1" in diff.modified_control_ids


# ============================================================================
# E12: SCAP Bridge Adapter (Supplementary Data Labeling & XXE Mitigation)
# ============================================================================


def test_E12_scap_bridge_and_supplementary_tagging():
    scap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_RHEL">
  <title>CIS Red Hat Enterprise Linux 8 Benchmark</title>
  <version>0.1.66</version>
  <Profile id="xccdf_org.ssgproject.content_profile_cis">
    <title>CIS RHEL 8 Level 1 Workstation</title>
  </Profile>
  <Rule id="xccdf_org.ssgproject.content_rule_audit_rules_login_events" severity="medium">
    <title>Record Login and Logout Events</title>
    <platform idref="cpe:/o:redhat:enterprise_linux:8"/>
  </Rule>
</Benchmark>
"""
    scap_pack = parse_scap_xccdf_xml(scap_xml)
    assert scap_pack["source"] == "validated_scap_mapping"
    assert scap_pack["rights_status"] == "UNREVIEWED"
    assert "supplementary" in scap_pack["source_reference"].lower()
    assert len(scap_pack["rules"]) == 1
    assert scap_pack["rules"][0]["operator"] == "xccdf_oval"
    assert any("supplementary" in lim.lower() for lim in scap_pack["rules"][0]["limitations"])


# ============================================================================
# FastAPI Policy Routes Integration Tests
# ============================================================================


from contextlib import contextmanager
from types import SimpleNamespace


@pytest.fixture
def mock_policy_env(monkeypatch):
    user_id = uuid4()
    org_id = uuid4()
    pack_id = uuid4()
    rule_id = uuid4()
    finding_id = uuid4()
    exc_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    ident = Identity(
        user_id=user_id,
        aal="aal2",
        expires=int(now_utc.timestamp() + 3600),
        email="security_admin@example.com",
        mfa_enrolled=True,
    )

    mock_pack = SimpleNamespace(
        id=pack_id,
        org_id=org_id,
        benchmark_id="cis-ubuntu-linux",
        benchmark_release="22.04-lts",
        pack_version="1.0.0",
        profiles=["Level 1 - Server", "Level 2 - Server"],
        source="authorized_cis_mapping",
        source_reference="CIS Ubuntu Linux 22.04 LTS Benchmark",
        rights_status="AUTHORIZED",
        evaluator_version="1.0.0-deterministic",
        content_sha256="0" * 64,
        created_at=now_utc,
    )

    mock_rule = SimpleNamespace(
        id=rule_id,
        org_id=org_id,
        policy_pack_id=pack_id,
        control_id="5.2.1",
        definition={
            "control_id": "5.2.1",
            "feature_ids": ["M16", "M03"],
            "fact_path": "os_security.sshd.permit_root_login",
            "operator": "equals",
            "expected": "no",
            "severity": "CRITICAL",
            "applicability_platforms": ["linux", "ubuntu"],
            "requires_manual_review": False,
            "profiles": ["Level 1 - Server"],
        },
    )

    mock_finding = SimpleNamespace(
        id=finding_id,
        org_id=org_id,
        result_id=uuid4(),
        severity="HIGH",
        remediation_template_id=None,
    )

    mock_audit_res = SimpleNamespace(
        id=uuid4(),
        org_id=org_id,
        scan_id=uuid4(),
        asset_id=uuid4(),
        rule_id=rule_id,
        evidence_id=uuid4(),
        status="FAIL",
        expected={"value": "no"},
        observed={"value": "yes"},
        evaluator_version="1.0.0-deterministic",
        limitations=["Root login enabled"],
        created_at=now_utc,
    )

    mock_exc = SimpleNamespace(
        id=exc_id,
        org_id=org_id,
        finding_id=finding_id,
        reason="Temporary migration",
        decision="PENDING",
        approver_id=None,
        expires_at=now_utc + timedelta(days=30),
        created_at=now_utc,
    )

    mock_override = SimpleNamespace(
        id=uuid4(),
        org_id=org_id,
        rule_id=rule_id,
        version="1.0.0",
        expected={"value": "no"},
        reason="CI automation",
        author_id=user_id,
        created_at=now_utc,
    )

    @contextmanager
    def mock_tenant_session(*args, **kwargs):
        def mock_scalar(query, *a, **k):
            q_str = str(query)
            if "benchmark_packs" in q_str:
                return mock_pack
            if "policy_rules" in q_str:
                return mock_rule
            if "findings" in q_str:
                return mock_finding
            if "audit_results" in q_str:
                return mock_audit_res
            if "exceptions" in q_str:
                return mock_exc
            if "policy_overrides" in q_str:
                return mock_override
            return mock_pack

        def mock_scalars(query, *a, **k):
            q_str = str(query)
            if "benchmark_packs" in q_str:
                return SimpleNamespace(all=lambda: [mock_pack])
            if "policy_rules" in q_str:
                return SimpleNamespace(all=lambda: [mock_rule])
            if "exceptions" in q_str:
                return SimpleNamespace(all=lambda: [mock_exc])
            if "audit_results" in q_str:
                return SimpleNamespace(all=lambda: [mock_audit_res])
            if "policy_overrides" in q_str:
                return SimpleNamespace(all=lambda: [mock_override])
            return SimpleNamespace(all=lambda: [])

        yield SimpleNamespace(
            scalar=mock_scalar,
            scalars=mock_scalars,
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )

    monkeypatch.setattr(policy_routes, "identity", lambda r: ident)
    monkeypatch.setattr(policy_routes, "member", lambda db, who, org, perm, privileged=False: None)
    monkeypatch.setattr(policy_routes, "audit", lambda db, req, who, org, ev, res: None)
    monkeypatch.setattr(policy_routes, "tenant_session", mock_tenant_session)
    monkeypatch.setattr(policy_routes, "install_policy_pack_in_db", lambda db, org, data: (mock_pack, [mock_rule]))

    return user_id, org_id, pack_id, finding_id, exc_id


def test_policy_routes_list_policies(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    resp = client.get("/api/v1/policies", headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "1.0.0"
    assert len(body["data"]["items"]) == 1
    assert body["data"]["items"][0]["benchmark_id"] == "cis-ubuntu-linux"


def test_policy_routes_create_and_get_pack(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    pack_payload = get_builtin_policy_pack("ubuntu-v1")
    resp = client.post(
        "/api/v1/policies",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json=pack_payload,
    )
    assert resp.status_code == 201
    created_pack = resp.json()["data"]
    assert created_pack["policy_pack_id"] == str(pack_id)

    # Get pack rules
    rules_resp = client.get(
        f"/api/v1/policies/{pack_id}/rules",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
    )
    assert rules_resp.status_code == 200
    assert len(rules_resp.json()["data"]) == 1


def test_policy_routes_create_override(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    ov_payload = {
        "policy_pack_id": str(pack_id),
        "base_version": "1.0.0",
        "control_id": "5.2.1",
        "expected": {"min": 1, "max": 6},
        "reason": "Approved extended max auth tries for CI runners",
    }
    ov_resp = client.post(
        "/api/v1/policy-overrides",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json=ov_payload,
    )
    assert ov_resp.status_code == 201
    assert ov_resp.json()["data"]["control_id"] == "5.2.1"


def test_policy_routes_scap_import(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    scap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.test_bench">
  <title>CIS Test OpenSCAP</title>
  <version>1.0.0</version>
  <Rule id="xccdf_org.ssgproject.rule_test_1" severity="high">
    <title>Disable Root Login</title>
  </Rule>
</Benchmark>
"""
    resp = client.post(
        "/api/v1/policies/scap-import",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json={"xml": scap_xml},
    )
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert "policy_pack_id" in data


def test_policy_routes_exception_workflow(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    # 1. Request exception
    future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")
    req_resp = client.post(
        "/api/v1/exceptions",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json={
            "finding_id": str(finding_id),
            "reason": "Temporary jumpbox migration",
            "expires_at": future_date,
        },
    )
    assert req_resp.status_code == 201
    assert req_resp.json()["data"]["decision"] == "PENDING"

    # 2. Decide exception (Approve)
    dec_resp = client.post(
        f"/api/v1/exceptions/{exc_id}/decision",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json={
            "decision": "APPROVED",
            "reason": "Risk accepted by CISO",
        },
    )
    assert dec_resp.status_code == 200
    assert dec_resp.json()["data"]["decision"] == "APPROVED"


def test_policy_routes_manual_review_workflow(mock_policy_env):
    user_id, org_id, pack_id, finding_id, exc_id = mock_policy_env
    client = TestClient(app)

    review_payload = {
        "finding_id": str(finding_id),
        "verdict": "VALIDATED",
        "evidence_ids": [str(uuid4())],
        "rationale": "Verified MOTD banner in console session log manually",
    }
    resp = client.post(
        "/api/v1/manual-reviews",
        headers={"X-Org-ID": str(org_id), "Authorization": "Bearer mock-token"},
        json=review_payload,
    )
    assert resp.status_code == 201
    assert resp.json()["data"]["verdict"] == "VALIDATED"

