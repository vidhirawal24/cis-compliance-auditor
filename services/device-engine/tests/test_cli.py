import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from cisguard_device.models import FactsEnvelope

FIXTURES = Path(__file__).parents[1] / "fixtures" / "cisco_ios"
WINDOWS_FIXTURES = Path(__file__).parents[1] / "fixtures" / "windows"
LINUX_FIXTURES = Path(__file__).parents[1] / "fixtures" / "linux"
OPENSCAP_FIXTURES = Path(__file__).parents[1] / "fixtures" / "openscap"


def test_cli_capabilities_reports_fixture_coverage_for_every_listed_family() -> None:
    result = _run("capabilities")
    assert result.returncode == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["device_families"]
    assert all(family["fixture_tests"] for family in payload["device_families"])
    assert all(not family["live_lab_tests"] for family in payload["device_families"])


def test_cli_self_test_produces_valid_json() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "cisguard_device", "self-test"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    parsed = FactsEnvelope.model_validate(payload)
    assert parsed.collection_method == "synthetic_fixture_serialization_only"
    assert parsed.facts["management"]["telnet_enabled"] is None


def test_cli_collect_fixture_produces_valid_json() -> None:
    result = _run("collect", "--fixture", str(FIXTURES / "secure" / "manifest.json"))
    assert result.returncode == 0
    assert result.stderr == ""
    parsed = FactsEnvelope.model_validate_json(result.stdout)
    assert parsed.collection_method == "offline_synthetic_fixture"


def test_cli_platform_error_is_json_and_nonzero() -> None:
    result = _run(
        "collect",
        "--fixture",
        str(FIXTURES / "secure" / "manifest.json"),
        "--platform",
        "not_real",
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "UNSUPPORTED_PLATFORM"
    assert "UNSUPPORTED_PLATFORM" in result.stderr


def test_cli_windows_offline_collection_and_probe() -> None:
    manifest = WINDOWS_FIXTURES / "windows11_enterprise_secure" / "manifest.json"
    probe = _run("windows-probe", "--fixture", str(manifest))
    assert probe.returncode == 0
    assert json.loads(probe.stdout)["platform"] == "windows_11_enterprise"
    collected = _run("windows-collect", "--transport", "offline", "--fixture", str(manifest))
    assert collected.returncode == 0
    envelope = FactsEnvelope.model_validate_json(collected.stdout)
    assert envelope.platform == "windows_11_enterprise"


def test_cli_windows_offline_missing_fixture_is_structured_error() -> None:
    result = _run("windows-collect", "--transport", "offline")
    assert result.returncode != 0
    assert json.loads(result.stdout)["error"]["code"] == "FIXTURE_REQUIRED"


def test_cli_linux_offline_collection_and_probe() -> None:
    manifest = LINUX_FIXTURES / "rhel9_secure" / "manifest.json"
    probe = _run("linux-probe", "--fixture", str(manifest))
    assert probe.returncode == 0
    assert json.loads(probe.stdout)["platform"] == "rhel_9"
    collected = _run("linux-collect", "--transport", "offline", "--fixture", str(manifest))
    assert collected.returncode == 0
    envelope = FactsEnvelope.model_validate_json(collected.stdout)
    assert envelope.platform == "rhel_9"


def test_cli_linux_missing_fixture_is_structured_error() -> None:
    result = _run("linux-collect", "--transport", "offline")
    assert result.returncode != 0
    assert json.loads(result.stdout)["error"]["code"] == "FIXTURE_REQUIRED"


def test_cli_scap_ingest_preserves_json_states() -> None:
    result = _run(
        "scap-ingest",
        "--input",
        str(OPENSCAP_FIXTURES / "synthetic-results.xml"),
        "--synthetic",
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert {item["result"] for item in payload["rule_results"]} >= {"pass", "unknown", "error"}


@pytest.mark.parametrize(
    ("command", "expected_code"),
    [
        ("candidates", "NOT_IMPLEMENTED"),
        ("execute", "LIVE_WRITE_BLOCKED"),
        ("verify", "NOT_IMPLEMENTED"),
    ],
)
def test_unsupported_commands_never_return_success(command: str, expected_code: str) -> None:
    result = _run(command)
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == expected_code
    assert payload["status"] in {"NOT_IMPLEMENTED", "REJECTED"}


def test_offline_import_and_evaluation_cli() -> None:
    source = Path(__file__).parents[1] / "fixtures" / "remaining" / "cisco_router" / "secure"
    imported = _run(
        "offline-import",
        "--input",
        str(source / "running-config.txt"),
        "--operational",
        str(source / "show-output.txt"),
        "--source-type",
        "cisco_ios_running_config",
        "--platform",
        "cisco_router",
        "--org-id",
        "11111111-1111-4111-8111-111111111111",
        "--asset-id",
        "22222222-2222-4222-8222-222222222222",
        "--completeness",
        "complete",
        "--capture-timestamp",
        "2026-10-29T01:00:00+00:00",
    )
    assert imported.returncode == 0
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        envelope_path = tmp / "envelope.json"
        envelope_path.write_text(imported.stdout, encoding="utf-8")
        policy_path = tmp / "policy.json"
        policy_path.write_text('{"session_timeout_seconds":300}', encoding="utf-8")

        evaluated = _run(
            "evaluate_device",
            "--envelope",
            str(envelope_path),
            "--policy",
            str(policy_path),
        )
        assert evaluated.returncode == 0
        payload = json.loads(evaluated.stdout)
        assert payload["assessment_status"] == "COMPLETED"
        assert payload["results"]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cisguard_device", *args],
        check=False,
        capture_output=True,
        text=True,
    )
