import hashlib
import json
import sys
from pathlib import Path

import pytest

from cisguard_device import collect_fixture, load_expected_envelope, probe_fixture
from cisguard_device.cisco_ios_fixture import CiscoIosFixtureAdapter
from cisguard_device.errors import FixtureInputError, LiveWriteBlockedError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "cisco_ios"


@pytest.mark.parametrize("case", ["secure", "weak", "unknown"])
def test_fixture_matches_golden_expected_json(case: str) -> None:
    manifest = FIXTURES / case / "manifest.json"
    assert collect_fixture(manifest) == load_expected_envelope(manifest)


def test_secure_and_weak_facts_are_configuration_only() -> None:
    secure = collect_fixture(FIXTURES / "secure" / "manifest.json")
    weak = collect_fixture(FIXTURES / "weak" / "manifest.json")
    assert [block["telnet_allowed"] for block in secure.facts["management"]["vty_blocks"]] == [
        False,
        False,
    ]
    assert [block["telnet_allowed"] for block in weak.facts["management"]["vty_blocks"]] == [
        True,
        False,
    ]
    assert secure.facts["management"]["ssh"]["key_authentication_configured"] is None
    assert secure.facts["ntp"]["configured_servers"]
    assert secure.facts["ntp"]["synchronized"] is None


def test_unknown_partial_facts_stay_unknown_and_warn() -> None:
    result = collect_fixture(FIXTURES / "unknown" / "manifest.json")
    assert result.facts["management"]["ssh"]["configured_version"] is None
    block = result.facts["management"]["vty_blocks"][0]
    assert block["transport_input"] is None
    assert block["telnet_allowed"] is None
    assert block["exec_timeout_seconds"] is None
    assert result.facts["parser"]["warnings"]


def test_sha256_is_over_exact_source_bytes() -> None:
    manifest = FIXTURES / "secure" / "manifest.json"
    source = manifest.parent / "config.txt"
    result = collect_fixture(manifest)
    assert result.evidence_refs[0].sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


def test_repeated_parsing_is_deterministic() -> None:
    manifest = FIXTURES / "weak" / "manifest.json"
    first = collect_fixture(manifest)
    second = collect_fixture(manifest)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_probe_is_explicitly_fixture_only() -> None:
    result = probe_fixture(FIXTURES / "secure" / "manifest.json")
    assert result["synthetic"] is True
    assert result["implementation_status"] == "FIXTURE_ONLY_PARTIAL"


def test_platform_mismatch_is_rejected() -> None:
    with pytest.raises(FixtureInputError, match="No Phase-1 fixture adapter") as captured:
        collect_fixture(FIXTURES / "secure" / "manifest.json", platform="cisco_ios")
    assert captured.value.code == "UNSUPPORTED_PLATFORM"


def test_missing_file_is_structured_error(tmp_path: Path) -> None:
    manifest = _copy_manifest(tmp_path, source_file="missing.txt")
    with pytest.raises(FixtureInputError) as captured:
        collect_fixture(manifest)
    assert captured.value.code == "FIXTURE_NOT_FOUND"


def test_empty_and_oversized_input_are_rejected(tmp_path: Path) -> None:
    manifest = _copy_manifest(tmp_path)
    (tmp_path / "config.txt").write_bytes(b"")
    with pytest.raises(FixtureInputError) as empty:
        collect_fixture(manifest)
    assert empty.value.code == "EMPTY_FIXTURE"
    (tmp_path / "config.txt").write_bytes(b"12345")
    with pytest.raises(FixtureInputError) as oversized:
        collect_fixture(manifest, max_bytes=4)
    assert oversized.value.code == "FIXTURE_TOO_LARGE"


def test_invalid_encoding_is_rejected(tmp_path: Path) -> None:
    manifest = _copy_manifest(tmp_path)
    (tmp_path / "config.txt").write_bytes(b"\xff\xfe")
    with pytest.raises(FixtureInputError) as captured:
        collect_fixture(manifest)
    assert captured.value.code == "INVALID_ENCODING"


def test_malformed_manifest_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{not-json", encoding="utf-8")
    with pytest.raises(FixtureInputError) as captured:
        collect_fixture(manifest)
    assert captured.value.code == "MALFORMED_MANIFEST"


def test_execute_is_blocked() -> None:
    with pytest.raises(LiveWriteBlockedError) as captured:
        CiscoIosFixtureAdapter().execute_approved_change({})
    assert captured.value.code == "LIVE_WRITE_BLOCKED"


def test_core_fixture_path_has_no_optional_dependency_imports() -> None:
    collect_fixture(FIXTURES / "secure" / "manifest.json")
    assert not {"netmiko", "scrapli", "paramiko", "httpx", "ttp", "textfsm"} & set(sys.modules)


def _copy_manifest(tmp_path: Path, *, source_file: str = "config.txt") -> Path:
    payload = json.loads((FIXTURES / "secure" / "manifest.json").read_text(encoding="utf-8"))
    payload["source_file"] = source_file
    payload["expected_file"] = "expected.json"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    return manifest
