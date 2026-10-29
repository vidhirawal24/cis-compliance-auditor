import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from cisguard_device.cli import main
from cisguard_device.errors import DeviceEngineError, FixtureInputError
from cisguard_device.remaining_devices import (
    collect_remaining_fixture,
    parse_cisco_ios_sources,
    parse_panos_xml,
    parse_sophos_xml,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "remaining"
FAMILIES = ("sophos_firewall", "palo_alto_panos", "cisco_router", "cisco_switch")


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("state", ("secure", "weak", "unknown"))
def test_vendor_shaped_fixture_matrix(family: str, state: str) -> None:
    path = FIXTURES / family / state / "manifest.json"
    first = collect_remaining_fixture(path)
    assert first.model_dump(mode="json") == collect_remaining_fixture(path).model_dump(mode="json")
    assert first.platform == family
    if state == "unknown" and family.startswith("cisco"):
        assert first.errors[0].code == "SOURCE_DENIED"


def test_sophos_and_panos_vendor_semantics() -> None:
    sophos = _collect("sophos_firewall", "unknown")
    assert sophos.facts["ordered_rules"][0]["source"] == ["MISSING"]
    assert sophos.facts["objects"]["LAN"]["value"] == "10.0.0.0/24"
    running = _collect("palo_alto_panos", "secure")
    candidate = _collect("palo_alto_panos", "weak")
    assert running.facts["configuration_state"] == "running"
    assert candidate.facts["configuration_state"] == "candidate"
    assert running.facts["context"]["panorama_supported"] is False
    assert running.facts["ordered_rules"][0]["applications"] == ["ssl"]


def test_switch_state_scope_unused_ntp_and_secret_redaction() -> None:
    weak = _collect("cisco_switch", "weak")
    unknown = _collect("cisco_switch", "unknown")
    port = weak.facts["interfaces"][1]
    assert port["configured_shutdown"] is False
    assert port["operational_status"] == "down"
    assert port["designated_unused"] is True
    assert unknown.facts["interfaces"][1]["designated_unused"] is None
    assert weak.facts["dhcp_snooping"]["vlans"] == ["10"]
    assert weak.facts["dynamic_arp_inspection"]["vlans"] == ["10"]
    assert weak.facts["management_svis"][0]["name"] == "Vlan1"
    assert weak.facts["ntp"]["synchronized"] is True
    assert weak.facts["snmp"]["v3_users_present"] is True
    assert weak.facts["snmp"]["insecure_v1_v2c_present"] is True
    assert weak.facts["snmp"]["communities"] == ["<redacted>"]
    assert "SECRET" not in json.dumps(weak.model_dump(mode="json"))


def test_xml_safety_and_unsupported_versions() -> None:
    dangerous = b'<!DOCTYPE x [<!ENTITY e "secret">]><Response APIVersion="1905.1"/>'
    for parser in (parse_sophos_xml, parse_panos_xml):
        with pytest.raises(FixtureInputError) as unsafe:
            parser(dangerous)
        assert unsafe.value.code == "UNSAFE_XML"
        with pytest.raises(FixtureInputError) as malformed:
            parser(b"<broken")
        assert malformed.value.code == "MALFORMED_XML"
    with pytest.raises(FixtureInputError) as panos:
        parse_panos_xml(
            b'<response status="success"><result><config version="9.0"/></result></response>'
        )
    assert panos.value.code == "UNSUPPORTED_PANOS_VERSION"
    with pytest.raises(FixtureInputError) as nxos:
        parse_cisco_ios_sources(
            b"version 9.3\nhostname nx\n",
            None,
            platform="cisco_switch",
            designated_unused_ports=None,
        )
    assert nxos.value.code == "UNSUPPORTED_IOS_VERSION"


def test_individual_hashes_and_cli(capsys: pytest.CaptureFixture[str]) -> None:
    case = FIXTURES / "cisco_switch" / "secure"
    result = collect_remaining_fixture(case / "manifest.json")
    hashes = {r.source_identity: r.sha256 for r in result.evidence_refs}
    for identity, filename in (
        ("running_config", "running-config.txt"),
        ("show_output", "show-output.txt"),
    ):
        assert hashes[identity] == hashlib.sha256((case / filename).read_bytes()).hexdigest()
    manifest = FIXTURES / "cisco_router" / "secure" / "manifest.json"
    assert main(["device-collect", "--transport", "offline", "--fixture", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "cisco_router"
    assert main(["device-collect", "--transport", "live", "--fixture", str(manifest)]) == 2
    assert (
        json.loads(capsys.readouterr().out)["error"]["code"] == "LIVE_DEVICE_TRANSPORT_UNAVAILABLE"
    )


def test_missing_required_source_is_explicit() -> None:
    source = FIXTURES / "sophos_firewall" / "secure" / "manifest.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["sources"][0]["state"] = "denied"
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest_path = Path(tmp_dir) / "manifest.json"
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(DeviceEngineError) as denied:
            collect_remaining_fixture(manifest_path)
        assert denied.value.code == "REQUIRED_SOURCE_UNAVAILABLE"


def _collect(family: str, state: str):
    return collect_remaining_fixture(FIXTURES / family / state / "manifest.json")
