import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from cisguard_device.cli import main
from cisguard_device.errors import DeviceEngineError, FixtureInputError
from cisguard_device.firewalls import (
    collect_asa_ssh,
    collect_firewall_fixture,
    collect_paginated,
    map_http_failure,
    parse_firewall_capture,
    resolve_objects,
    validate_https_target,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "firewalls"
PLATFORMS = ("fortios", "cisco_asa", "cisco_ftd_fmc", "checkpoint_management")


@pytest.mark.parametrize("platform", PLATFORMS)
@pytest.mark.parametrize("state", ("secure", "weak", "unknown"))
def test_firewall_fixture_matrix_is_deterministic(platform: str, state: str) -> None:
    manifest = FIXTURES / platform / state / "manifest.json"
    first = collect_firewall_fixture(manifest)
    second = collect_firewall_fixture(manifest)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.platform == platform
    assert first.facts["ordered_rules"][0]["order"] == 1
    assert first.facts["context"]
    if state == "weak":
        assert first.facts["management"]["telnet_enabled"] is True
        assert first.facts["ordered_rules"][1]["enabled"] is False
    if state == "unknown":
        assert first.errors[0].code == "FIREWALL_SOURCE_DENIED"
        assert first.facts["deployment"]["confirmed_installed"] is None


def test_asa_and_ftd_are_distinct_and_bindings_nat_are_preserved() -> None:
    asa = _collect("cisco_asa", "secure")
    ftd = _collect("cisco_ftd_fmc", "secure")
    assert asa.platform != ftd.platform
    assert asa.facts["context"] == {"security_context": "admin"}
    assert ftd.facts["context"]["domain"] == "Global"
    assert asa.facts["bindings"][0]["direction"] == "in"
    assert ftd.facts["ordered_rules"][0]["application_or_user_constraints"]
    assert asa.facts["nat"][0]["type"] == "source"


def test_object_resolution_preserves_nested_cycle_unresolved_and_depth() -> None:
    objects = {
        "leaf": {"type": "address", "value": "192.0.2.1"},
        "nested": {"type": "group", "members": ["leaf", "missing"]},
        "a": {"type": "group", "members": ["b"]},
        "b": {"type": "group", "members": ["a"]},
    }
    result = resolve_objects(objects)
    assert result["nested"] == {
        "status": "partial",
        "values": ["192.0.2.1"],
        "unresolved": ["missing"],
    }
    assert result["a"]["status"] == "cycle"
    assert resolve_objects(objects, max_depth=0)["a"]["status"] == "depth_limit"


def test_pagination_success_duplicate_loop_and_limit() -> None:
    pages = {None: ([1], "next"), "next": ([2], None)}
    assert collect_paginated(lambda cursor: pages[cursor]) == [1, 2]
    with pytest.raises(DeviceEngineError, match="repeated") as duplicate:
        collect_paginated(lambda cursor: ([1], "next" if cursor is None else None))
    assert duplicate.value.code == "DUPLICATE_PAGE"
    with pytest.raises(DeviceEngineError) as loop:
        collect_paginated(lambda cursor: ([cursor], "same"))
    assert loop.value.code == "PAGINATION_LOOP"
    with pytest.raises(DeviceEngineError) as limit:
        collect_paginated(lambda cursor: ([cursor], str(cursor) + "x"), max_pages=2)
    assert limit.value.code == "PAGINATION_LIMIT"


def test_exact_byte_hash_and_malformed_oversized() -> None:
    case = FIXTURES / "fortios" / "secure"
    result = collect_firewall_fixture(case / "manifest.json")
    expected_hash = hashlib.sha256((case / "capture.json").read_bytes()).hexdigest()
    assert result.evidence_refs[0].sha256 == expected_hash
    with pytest.raises(FixtureInputError) as malformed:
        parse_firewall_capture(b"not json")
    assert malformed.value.code == "MALFORMED_FIREWALL_CAPTURE"
    with pytest.raises(FixtureInputError) as oversized:
        parse_firewall_capture(b"{}", max_bytes=1)
    assert oversized.value.code == "FIREWALL_CAPTURE_TOO_LARGE"


def test_cli_json_and_live_failure(capsys: pytest.CaptureFixture[str]) -> None:
    manifest = FIXTURES / "checkpoint_management" / "secure" / "manifest.json"
    assert main(["firewall-collect", "--transport", "offline", "--fixture", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "checkpoint_management"
    assert main(["firewall-collect", "--transport", "live", "--fixture", str(manifest)]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "LIVE_FIREWALL_TRANSPORT_UNAVAILABLE"


def test_tls_identity_and_http_failure_mapping(tmp_path: Path) -> None:
    assert validate_https_target("https://fw.example:8443") == "https://fw.example:8443"
    for target in ("http://fw.example", "https://user:secret@fw.example", "https://fw.example/api"):
        with pytest.raises(DeviceEngineError):
            validate_https_target(target)
    with pytest.raises(DeviceEngineError) as ca:
        validate_https_target("https://fw.example", custom_ca=tmp_path / "missing-ca.pem")
    assert ca.value.code == "CUSTOM_CA_NOT_FOUND"
    expected = {
        401: "AUTHENTICATION_FAILED",
        403: "PERMISSION_DENIED",
        408: "API_TIMEOUT",
        429: "RATE_LIMITED",
        503: "API_TRANSPORT_FAILED",
    }
    for status, code in expected.items():
        error = map_http_failure(status)
        assert error.code == code
        assert "secret" not in str(error.details)


def test_asa_ssh_requires_known_host_identity(tmp_path: Path) -> None:
    with pytest.raises(DeviceEngineError) as rejected:
        collect_asa_ssh(
            target="asa.example",
            known_hosts=tmp_path / "missing",
            secret_provider=object(),  # rejected before credentials are requested
            org_id=UUID("11111111-1111-4111-8111-111111111111"),
            asset_id=UUID("44444444-0000-4000-8000-000000000002"),
            client_factory=lambda: object(),
        )
    assert rejected.value.code == "KNOWN_HOSTS_REQUIRED"


def _collect(platform: str, state: str):
    return collect_firewall_fixture(FIXTURES / platform / state / "manifest.json")
