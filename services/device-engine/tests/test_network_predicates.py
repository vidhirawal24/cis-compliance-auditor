from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from cisguard_device.models import AssessmentStatus, FactsEnvelope
from cisguard_device.network_predicates import (
    NetworkControlPolicy,
    evaluate_network_controls,
    predicate_feature_map,
)

ORG_ID = UUID("11111111-1111-4111-8111-111111111111")
ASSET_ID = UUID("22222222-2222-4222-8222-222222222222")


def _facts() -> dict:
    return {
        "capabilities": {"switching": True},
        "management": {
            "telnet_enabled": False,
            "http_enabled": False,
            "ssh_version": "2",
            "vty_lines": [
                {
                    "name": "0-4",
                    "login_method": "authentication_profile",
                    "key_authentication_configured": True,
                    "password_authentication_excluded": True,
                    "exec_timeout_seconds": 300,
                }
            ],
        },
        "acl_bindings": [{"interface": "GigabitEthernet0/0", "acl_id": "EDGE", "direction": "in"}],
        "acl_default_action": "deny",
        "acls": [
            {"id": "EDGE", "order": 1, "syntax": "permit tcp host 10.1.1.5 host 192.0.2.10 eq 443"}
        ],
        "interfaces": [
            {
                "name": "GigabitEthernet1/0/1",
                "configured_shutdown": True,
                "switchport_mode": "access",
                "port_security_configured": True,
            }
        ],
        "dhcp_snooping": {"enabled": True, "vlans": ["10"]},
        "dynamic_arp_inspection": {"vlans": ["10"]},
        "logging": {"destinations": ["192.0.2.50"]},
        "ntp": {"configured_servers": ["192.0.2.123"], "synchronized": True},
        "snmp": {
            "v3_users_present": True,
            "v3_authpriv_users_present": True,
            "insecure_v1_v2c_present": False,
            "default_community_present": False,
            "configuration_complete": True,
        },
    }


def _envelope(
    facts: dict | None = None, *, platform: str = "cisco_switch", errors=None
) -> FactsEnvelope:
    return FactsEnvelope(
        org_id=ORG_ID,
        asset_id=ASSET_ID,
        platform=platform,
        vendor="Cisco",
        model="test-device",
        os_or_firmware_version="IOS-XE 17",
        collector_version="test",
        collection_method="offline_user_supplied_capture",
        collected_at=datetime(2026, 10, 29, tzinfo=UTC),
        facts=deepcopy(_facts() if facts is None else facts),
        evidence_refs=[],
        errors=errors or [],
    )


def _policy(**updates) -> NetworkControlPolicy:
    values = {
        "session_timeout_seconds": 300,
        "required_vlans": ["10"],
        "designated_unused_ports": ["GigabitEthernet1/0/1"],
        "interface_roles": {"GigabitEthernet1/0/1": "access"},
        "management_interface_inventory": ["Vlan99"],
        "management_interface_inventory_complete": True,
        "expected_vty_lines": [0, 1, 2, 3, 4],
    }
    values.update(updates)
    return NetworkControlPolicy(**values)


def _result(check_id: str, facts: dict | None = None, policy=None, *, platform="cisco_switch"):
    result = evaluate_network_controls(_envelope(facts, platform=platform), policy or _policy())
    return next(item for item in result if item.check_id == check_id)


@pytest.mark.parametrize(
    "check_id",
    [
        "DEV-M20-001",
        "DEV-M21-001",
        "DEV-M21-002",
        "DEV-M21-003",
        "DEV-M21-004",
        "DEV-M22-001",
        "DEV-M23-001",
        "DEV-M24-001",
        "DEV-M25-001",
        "DEV-M26-001",
        "DEV-M27-001",
        "DEV-M28-001",
        "DEV-M29-001",
        "DEV-M30-001",
        "DEV-M31-001",
        "DEV-M32-001",
        "DEV-M32-002",
        "DEV-M33-001",
        "DEV-M33-002",
        "DEV-M33-003",
        "DEV-M33-004",
    ],
)
def test_each_network_predicate_passes_with_sufficient_evidence(check_id: str) -> None:
    assert _result(check_id).status == AssessmentStatus.PASS


@pytest.mark.parametrize(
    ("check_id", "feature_id"),
    [
        ("DEV-M20-001", "M20"),
        ("DEV-M21-001", "M20"),
        ("DEV-M21-002", "M21"),
        ("DEV-M21-003", "M21"),
        ("DEV-M21-004", "M21"),
        ("DEV-M22-001", "M22"),
        ("DEV-M23-001", "M23"),
        ("DEV-M24-001", "M24"),
        ("DEV-M25-001", "M25"),
        ("DEV-M26-001", "M26"),
        ("DEV-M27-001", "M27"),
        ("DEV-M28-001", "M28"),
        ("DEV-M29-001", "M29"),
        ("DEV-M30-001", "M30"),
        ("DEV-M31-001", "M31"),
        ("DEV-M32-001", "M32"),
        ("DEV-M32-002", "M32"),
        ("DEV-M33-001", "M33"),
        ("DEV-M33-002", "M33"),
        ("DEV-M33-003", "M33"),
        ("DEV-M33-004", "M33"),
    ],
)
def test_predicate_feature_mapping_matches_project_controls(check_id: str, feature_id: str) -> None:
    assert predicate_feature_map()[check_id] == feature_id
    assert _result(check_id).feature_id == feature_id


def test_login_local_and_generic_aaa_are_not_key_only_failures() -> None:
    facts = _facts()
    facts["management"]["vty_lines"][0].update(
        login_method="local",
        key_authentication_configured=None,
        password_authentication_excluded=None,
    )
    result = _result("DEV-M21-003", facts)
    assert result.status == AssessmentStatus.NOT_ASSESSED
    assert result.remediation is None
    facts["management"]["vty_lines"][0].update(login_method="authentication_profile")
    assert _result("DEV-M21-003", facts).status == AssessmentStatus.NOT_ASSESSED


def test_vty_complete_fixture_flag_is_not_platform_inventory_evidence() -> None:
    facts = _facts()
    facts["management"]["vty_coverage_complete"] = True
    assert (
        _result("DEV-M20-001", facts, _policy(expected_vty_lines=None)).status
        == AssessmentStatus.NOT_ASSESSED
    )


def test_broad_permit_before_final_deny_and_unknown_acl_are_not_erased() -> None:
    facts = _facts()
    facts["acls"] = [
        {"id": "EDGE", "order": 1, "syntax": "permit ip any any"},
        {"id": "EDGE", "order": 2, "syntax": "deny ip any any"},
    ]
    assert _result("DEV-M22-001", facts).status == AssessmentStatus.FAIL
    facts["acls"] = [{"id": "EDGE", "order": 1, "syntax": "permit object-group X any"}]
    assert _result("DEV-M22-001", facts).status == AssessmentStatus.NOT_ASSESSED


def test_snmp_absence_needs_complete_relevant_configuration() -> None:
    facts = _facts()
    facts["snmp"].update(insecure_v1_v2c_present=False, configuration_complete=False)
    assert _result("DEV-M33-002", facts).status == AssessmentStatus.NOT_ASSESSED


def test_switch_control_uses_collected_capability_not_platform_label() -> None:
    facts = _facts()
    facts["capabilities"]["switching"] = False
    assert _result("DEV-M27-001", facts).status == AssessmentStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("check_id", "mutate", "policy_updates"),
    [
        ("DEV-M20-001", lambda f: f["management"].update(telnet_enabled=True), {}),
        ("DEV-M21-001", lambda f: f["management"].update(http_enabled=True), {}),
        ("DEV-M21-002", lambda f: f["management"].update(ssh_version="1"), {}),
        (
            "DEV-M21-003",
            lambda f: f["management"]["vty_lines"][0].update(key_authentication_configured=False),
            {},
        ),
        (
            "DEV-M21-004",
            lambda f: f["management"]["vty_lines"][0].update(exec_timeout_seconds=600),
            {},
        ),
        (
            "DEV-M22-001",
            lambda f: f["acls"].__setitem__(
                0, {"id": "EDGE", "order": 1, "syntax": "permit ip any any"}
            ),
            {},
        ),
        (
            "DEV-M23-001",
            lambda f: f["acls"].__setitem__(
                0, {"id": "EDGE", "order": 1, "syntax": "permit tcp any any eq 22"}
            ),
            {},
        ),
        (
            "DEV-M24-001",
            lambda f: f["acls"].append(
                {
                    "id": "EDGE",
                    "order": 2,
                    "syntax": "deny tcp host 10.1.1.5 host 192.0.2.10 eq 443",
                }
            ),
            {},
        ),
        ("DEV-M25-001", lambda f: f.update(acl_default_action="permit"), {}),
        ("DEV-M26-001", lambda f: f["interfaces"][0].update(configured_shutdown=False), {}),
        ("DEV-M27-001", lambda f: f["interfaces"][0].update(port_security_configured=False), {}),
        ("DEV-M28-001", lambda f: f["dhcp_snooping"].update(enabled=False), {}),
        ("DEV-M29-001", lambda f: f["dynamic_arp_inspection"].update(vlans=[]), {}),
        ("DEV-M30-001", lambda f: None, {"management_interface_inventory": ["Vlan1"]}),
        ("DEV-M31-001", lambda f: f["logging"].update(destinations=[]), {}),
        ("DEV-M32-001", lambda f: f["ntp"].update(configured_servers=[]), {}),
        ("DEV-M32-002", lambda f: f["ntp"].update(synchronized=False), {}),
        ("DEV-M33-001", lambda f: f["snmp"].update(v3_users_present=False), {}),
        ("DEV-M33-002", lambda f: f["snmp"].update(insecure_v1_v2c_present=True), {}),
        ("DEV-M33-003", lambda f: f["snmp"].update(default_community_present=True), {}),
        ("DEV-M33-004", lambda f: f["snmp"].update(v3_authpriv_users_present=False), {}),
    ],
)
def test_each_network_predicate_fails_with_noncompliant_evidence(
    check_id, mutate, policy_updates
) -> None:
    facts = _facts()
    mutate(facts)
    assert _result(check_id, facts, _policy(**policy_updates)).status == AssessmentStatus.FAIL


@pytest.mark.parametrize(
    ("check_id", "path", "policy_updates"),
    [
        ("DEV-M20-001", ("management", "telnet_enabled"), {}),
        ("DEV-M21-001", ("management", "http_enabled"), {}),
        ("DEV-M21-002", ("management", "ssh_version"), {}),
        ("DEV-M21-003", ("management", "vty_lines"), {}),
        ("DEV-M21-004", ("management", "vty_lines"), {}),
        ("DEV-M22-001", ("acl_bindings",), {}),
        ("DEV-M23-001", ("acl_bindings",), {}),
        ("DEV-M24-001", ("acl_bindings",), {}),
        ("DEV-M25-001", ("acl_default_action",), {}),
        ("DEV-M26-001", ("interfaces",), {"designated_unused_ports": None}),
        ("DEV-M27-001", ("interfaces",), {"interface_roles": None}),
        ("DEV-M28-001", ("dhcp_snooping",), {"required_vlans": None}),
        ("DEV-M29-001", ("dynamic_arp_inspection",), {"required_vlans": None}),
        ("DEV-M30-001", ("management_svis",), {"management_interface_inventory": None}),
        ("DEV-M31-001", ("logging",), {}),
        ("DEV-M32-001", ("ntp",), {}),
        ("DEV-M32-002", ("ntp",), {}),
        ("DEV-M33-001", ("snmp",), {}),
        ("DEV-M33-002", ("snmp",), {}),
        ("DEV-M33-003", ("snmp",), {}),
        ("DEV-M33-004", ("snmp",), {}),
    ],
)
def test_each_network_predicate_stays_unassessed_when_evidence_is_missing(
    check_id, path, policy_updates
) -> None:
    facts = _facts()
    if len(path) == 1:
        facts.pop(path[0], None)
    else:
        facts[path[0]].pop(path[1], None)
    assert (
        _result(check_id, facts, _policy(**policy_updates)).status == AssessmentStatus.NOT_ASSESSED
    )


@pytest.mark.parametrize("check_id", ["DEV-M27-001", "DEV-M28-001", "DEV-M29-001", "DEV-M30-001"])
def test_switch_controls_are_not_applicable_on_router(check_id: str) -> None:
    facts = _facts()
    facts["capabilities"]["switching"] = False
    result = _result(check_id, facts, platform="cisco_router")
    assert result.status == AssessmentStatus.NOT_APPLICABLE


@pytest.mark.parametrize("policy", [{"required_vlans": []}])
def test_empty_required_vlan_inventory_is_not_applicable(policy: dict) -> None:
    result = _result("DEV-M28-001", policy=_policy(**policy))
    assert result.status == AssessmentStatus.NOT_APPLICABLE


def test_partial_capture_downgrades_pass_and_collection_error_is_error() -> None:
    facts = _facts()
    facts["import"] = {"completeness": "partial"}
    result = _result("DEV-M20-001", facts)
    assert result.status == AssessmentStatus.NOT_ASSESSED
    assert result.error_code == "INCOMPLETE_CAPTURE"


def test_policy_validates_port_and_vlan_ranges() -> None:
    with pytest.raises(ValueError):
        NetworkControlPolicy(session_timeout_seconds=300, sensitive_ports=[70000])
    with pytest.raises(ValueError):
        NetworkControlPolicy(session_timeout_seconds=300, required_vlans=["5000"])
    with pytest.raises(ValueError):
        NetworkControlPolicy()


def test_snmp_community_secret_is_never_in_result() -> None:
    facts = _facts()
    facts["snmp"].update(insecure_v1_v2c_present=True, communities=["should-not-appear"])
    result = _result("DEV-M33-002", facts)
    assert "should-not-appear" not in result.model_dump_json()


@pytest.mark.parametrize("earlier_action", ["permit", "deny"])
def test_full_shadowing_preserves_rule_order_and_action_difference(earlier_action: str) -> None:
    facts = _facts()
    facts["acls"] = [
        {"id": "EDGE", "order": 1, "syntax": f"{earlier_action} ip any any"},
        {"id": "EDGE", "order": 2, "syntax": "permit tcp host 10.1.1.5 host 192.0.2.10 eq 443"},
    ]
    result = _result("DEV-M24-001", facts)
    assert result.status == AssessmentStatus.FAIL
    shadow = result.actual["shadowed_rules"][0]
    assert (shadow["interface"], shadow["direction"], shadow["rule_order"]) == (
        "GigabitEthernet0/0",
        "in",
        2,
    )
    assert shadow["action_difference"] is (earlier_action == "deny")


def test_address_and_port_containment_prove_full_shadowing() -> None:
    facts = _facts()
    facts["acls"] = [
        {
            "id": "EDGE",
            "order": 1,
            "syntax": "permit tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 range 20 100",
        },
        {"id": "EDGE", "order": 2, "syntax": "deny tcp host 10.1.1.5 host 192.0.2.10 eq 80"},
    ]
    assert _result("DEV-M24-001", facts).status == AssessmentStatus.FAIL


def test_partial_address_overlap_is_not_full_shadowing() -> None:
    facts = _facts()
    facts["acls"] = [
        {
            "id": "EDGE",
            "order": 1,
            "syntax": "permit tcp 10.1.1.0 0.0.0.127 host 192.0.2.10 eq 443",
        },
        {"id": "EDGE", "order": 2, "syntax": "deny tcp 10.1.1.0 0.0.0.255 host 192.0.2.10 eq 443"},
    ]
    result = _result("DEV-M24-001", facts)
    assert result.status == AssessmentStatus.PASS
    assert len(result.actual["partial_overlaps"]) == 1
    assert result.actual["shadowed_rules"] == []


def test_disabled_acl_rule_is_ignored_for_shadowing() -> None:
    facts = _facts()
    facts["acls"] = [
        {"id": "EDGE", "order": 1, "enabled": False, "syntax": "deny ip any any"},
        {"id": "EDGE", "order": 2, "syntax": "permit tcp host 10.1.1.5 host 192.0.2.10 eq 443"},
    ]
    assert _result("DEV-M24-001", facts).status == AssessmentStatus.PASS


@pytest.mark.parametrize(
    ("binding", "extra", "expected"),
    [
        (
            {"interface": "Gi0/0", "acl_id": "EDGE", "direction": "in"},
            {"unsupported_acl_semantics": ["nat"]},
            AssessmentStatus.MANUAL_REVIEW,
        ),
        (
            {"interface": None, "acl_id": "EDGE", "direction": "in"},
            {},
            AssessmentStatus.MANUAL_REVIEW,
        ),
        (
            {"interface": "Gi0/0", "acl_id": "EDGE", "direction": "in"},
            {"unsupported_acl_semantics": ["ipv6_acl"]},
            AssessmentStatus.MANUAL_REVIEW,
        ),
    ],
)
def test_unknown_binding_nat_and_ipv6_block_shadowing(binding, extra, expected) -> None:
    facts = _facts()
    facts.update(extra)
    facts["acl_bindings"] = [binding]
    assert _result("DEV-M24-001", facts).status == expected


def test_unresolved_acl_objects_block_conclusion() -> None:
    facts = _facts()
    facts["acls"] = [{"id": "EDGE", "order": 1, "syntax": "permit tcp object-group WEB any eq 443"}]
    assert _result("DEV-M24-001", facts).status == AssessmentStatus.MANUAL_REVIEW


def test_missing_implicit_action_is_not_assessed() -> None:
    facts = _facts()
    facts["acl_default_action"] = None
    assert _result("DEV-M25-001", facts).status == AssessmentStatus.NOT_ASSESSED


def test_shadowing_complexity_limit_requires_manual_review() -> None:
    facts = _facts()
    facts["acls"] = [
        {"id": "EDGE", "order": 1, "syntax": "permit ip any any"},
        {"id": "EDGE", "order": 2, "syntax": "deny ip any any"},
    ]
    assert (
        _result("DEV-M24-001", facts, _policy(max_acl_complexity=1)).status
        == AssessmentStatus.MANUAL_REVIEW
    )


def test_sensitive_port_without_port_restriction_is_reported() -> None:
    facts = _facts()
    facts["acls"] = [{"id": "EDGE", "order": 1, "syntax": "permit tcp any any"}]
    result = _result("DEV-M23-001", facts)
    assert result.status == AssessmentStatus.FAIL
    assert result.actual["sensitive_port_exposures"][0]["exposed_ports"]
