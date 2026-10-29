import hashlib
import json
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

import cisguard_device.windows as windows
from cisguard_device.errors import DeviceEngineError, FixtureInputError
from cisguard_device.windows import (
    CaptureSource,
    WindowsCapture,
    classify_windows_capture,
    collect_windows_fixture,
    collect_windows_local,
    collect_windows_winrm,
    parse_windows_capture,
    probe_windows_fixture,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "windows"
ORG_ID = UUID("11111111-1111-4111-8111-111111111111")
ASSET_ID = UUID("29999999-0000-4000-8000-000000000001")


@pytest.mark.parametrize(
    ("case", "platform", "family", "context"),
    [
        ("windows11_enterprise_secure", "windows_11_enterprise", "workstation", "domain_joined"),
        ("windows11_standalone_weak", "windows_11_standalone", "workstation", "standalone"),
        ("server2019_unknown", "windows_server_2019", "server", "domain_joined"),
    ],
)
def test_windows_classification(case: str, platform: str, family: str, context: str) -> None:
    capture = _capture(case)
    classification = classify_windows_capture(capture)
    assert classification.platform == platform
    assert classification.family == family
    assert classification.deployment_context == context
    assert classification.supported is True


def test_server_is_not_classified_by_build_number_alone() -> None:
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"]["data"].update(
        {
            "caption": "Microsoft Windows Server 2022 Standard",
            "build_number": "22631",
            "product_type": 3,
        }
    )
    result = classify_windows_capture(WindowsCapture.model_validate(payload))
    assert result.supported is False
    assert result.family == "server"


def test_unsupported_windows_version_is_explicit() -> None:
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"]["data"].update(
        {"caption": "Microsoft Windows 10 Enterprise", "build_number": "19045"}
    )
    result = classify_windows_capture(WindowsCapture.model_validate(payload))
    assert result.supported is False
    assert "Unsupported Windows workstation" in str(result.reason)


def test_windows_11_home_is_collection_only_not_enterprise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windows.os, "name", "nt")
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"]["data"].update(
        {
            "caption": "Microsoft Windows 11 Home Single Language",
            "edition_id": "CoreSingleLanguage",
            "product_type": 1,
        }
    )

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(payload).encode(), stderr=b"")

    with pytest.raises(DeviceEngineError) as rejected:
        collect_windows_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=runner)
    assert rejected.value.code == "UNSUPPORTED_WINDOWS_VERSION"
    diagnostic = collect_windows_local(
        org_id=ORG_ID,
        asset_id=ASSET_ID,
        runner=runner,
        collection_only_diagnostic=True,
    )
    assert diagnostic.platform == "windows_11_home_diagnostic"
    assert "benchmark_applicability" in diagnostic.unsupported_capabilities
    assert diagnostic.facts["os"]["value"]["edition_id"] == "CoreSingleLanguage"


def test_enterprise_edition_wins_over_workgroup_context() -> None:
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["domain_membership"]["data"]["part_of_domain"] = False
    result = classify_windows_capture(WindowsCapture.model_validate(payload))
    assert result.platform == "windows_11_enterprise"


def test_known_privilege_exit_codes_are_nonretryable_and_keep_facts_unknown() -> None:
    timestamp = _capture("windows11_enterprise_secure").captured_at
    errors = windows._source_errors(
        {
            "audit_policy": CaptureSource(
                source_identity="auditpol.exe",
                timestamp=timestamp,
                state="error",
                exit_status=1314,
                error_code="AUDITPOL_ERROR",
            ),
            "local_security_policy": CaptureSource(
                source_identity="secedit.exe",
                timestamp=timestamp,
                state="error",
                exit_status=740,
                error_code="SECEDIT_ERROR",
            ),
        }
    )
    by_code = {error.code: error for error in errors}
    assert by_code["AUDITPOL_PRIVILEGE_REQUIRED"].retryable is False
    assert by_code["AUDITPOL_PRIVILEGE_REQUIRED"].details["exit_status"] == 1314
    assert by_code["SECEDIT_ELEVATION_REQUIRED"].retryable is False
    assert "automatic elevation" in by_code["SECEDIT_ELEVATION_REQUIRED"].message
    assert (
        windows._source_fact(
            CaptureSource(
                source_identity="auditpol.exe",
                timestamp=timestamp,
                state="error",
                exit_status=1314,
            )
        )["value"]
        is None
    )


def test_unavailable_windows_identity_is_not_unsupported_version() -> None:
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"].update({"state": "denied", "data": None})
    result = classify_windows_capture(WindowsCapture.model_validate(payload))
    assert result.identity_available is False
    assert result.reason == "OS identity unavailable"


def test_local_unavailable_identity_uses_distinct_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windows.os, "name", "nt")
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"].update({"state": "denied", "data": None})

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(payload).encode(), stderr=b"")

    with pytest.raises(DeviceEngineError) as captured:
        collect_windows_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=runner)
    assert captured.value.code == "WINDOWS_IDENTITY_UNAVAILABLE"


def test_secure_weak_and_unknown_normalized_facts() -> None:
    secure = _collect("windows11_enterprise_secure")
    weak = _collect("windows11_standalone_weak")
    unknown = _collect("server2019_unknown")
    assert secure.facts["firewall_profiles"]["value"][0]["enabled"] is True
    assert weak.facts["account_policy"]["value"]["minimum_password_length"] == 6
    assert unknown.facts["audit_policy"]["collection_state"] == "denied"
    assert unknown.facts["audit_policy"]["value"] is None
    assert {error.code for error in unknown.errors} >= {"AUDITPOL_DENIED", "SECEDIT_DENIED"}


def test_local_and_domain_policy_are_distinct() -> None:
    result = _collect("windows11_enterprise_secure")
    assert result.facts["deployment"]["context"] == "domain_joined"
    assert result.facts["deployment"]["effective_domain_policy_verified"] is False
    assert result.facts["account_policy"]["value"]["scope"] == "local"


def test_missing_registry_value_is_not_disabled_or_zero() -> None:
    result = _collect("windows11_standalone_weak")
    values = result.facts["registry_settings"]["value"]
    missing = next(item for item in values if item["name"] == "NoLMHash")
    assert missing == {"path": "HKLM:...Lsa", "name": "NoLMHash", "state": "missing", "value": None}


def test_locale_uncertainty_is_retained() -> None:
    result = _collect("server2019_unknown")
    account = result.facts["account_policy"]
    assert account["value"]["parsed_values"] is None
    assert "Locale-dependent" in account["limitation"]


def test_exact_capture_byte_hash() -> None:
    case = FIXTURES / "windows11_enterprise_secure"
    result = collect_windows_fixture(case / "manifest.json")
    assert (
        result.evidence_refs[0].sha256
        == hashlib.sha256((case / "capture.json").read_bytes()).hexdigest()
    )


def test_probe_and_platform_mismatch(tmp_path: Path) -> None:
    source_case = FIXTURES / "windows11_enterprise_secure"
    probe = probe_windows_fixture(source_case / "manifest.json")
    assert probe["platform"] == "windows_11_enterprise"
    payload = json.loads((source_case / "manifest.json").read_text(encoding="utf-8"))
    payload["intended_platform"] = "windows_server_2019"
    (tmp_path / "manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "capture.json").write_bytes((source_case / "capture.json").read_bytes())
    with pytest.raises(FixtureInputError) as captured:
        collect_windows_fixture(tmp_path / "manifest.json")
    assert captured.value.code == "PLATFORM_MISMATCH"


def test_malformed_and_contradictory_capture() -> None:
    with pytest.raises(FixtureInputError) as malformed:
        parse_windows_capture(b"{bad-json")
    assert malformed.value.code == "MALFORMED_WINDOWS_CAPTURE"
    payload = _capture_payload("windows11_enterprise_secure")
    payload["sources"]["os_identity"]["data"].update(
        {"caption": "Microsoft Windows 11 Enterprise", "product_type": 3}
    )
    result = classify_windows_capture(WindowsCapture.model_validate(payload))
    assert result.supported is False


def test_local_subprocess_timeout_nonzero_and_malformed_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(windows.os, "name", "nt")

    def timeout_runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=1)

    with pytest.raises(DeviceEngineError) as timeout:
        collect_windows_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=timeout_runner)
    assert timeout.value.code == "POWERSHELL_TIMEOUT"

    def failed_runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 5, stdout=b"", stderr=b"sensitive detail")

    with pytest.raises(DeviceEngineError) as failed:
        collect_windows_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=failed_runner)
    assert failed.value.code == "POWERSHELL_FAILED"
    assert failed.value.details == {"exit_status": 5, "stderr_redacted": True}

    def malformed_runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout=b"not-json", stderr=b"")

    with pytest.raises(FixtureInputError) as malformed:
        collect_windows_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=malformed_runner)
    assert malformed.value.code == "MALFORMED_WINDOWS_CAPTURE"


def test_winrm_rejects_insecure_target_and_redacts_failure() -> None:
    provider = _SecretProvider()
    with pytest.raises(DeviceEngineError) as insecure:
        collect_windows_winrm(
            target="http://example.invalid:5985/wsman",
            secret_provider=provider,
            org_id=ORG_ID,
            asset_id=ASSET_ID,
        )
    assert insecure.value.code == "INSECURE_WINRM_TARGET"

    def failing_factory(*args: object, **kwargs: object) -> object:
        raise RuntimeError("password=should-not-escape")

    with pytest.raises(DeviceEngineError) as failed:
        collect_windows_winrm(
            target="https://example.invalid:5986/wsman",
            secret_provider=provider,
            org_id=ORG_ID,
            asset_id=ASSET_ID,
            session_factory=failing_factory,
        )
    assert failed.value.code == "WINRM_TRANSPORT_FAILED"
    assert "should-not-escape" not in failed.value.message
    assert failed.value.details == {"target_host": "example.invalid", "details_redacted": True}


class _SecretProvider:
    def get_winrm_credentials(self, target: str) -> tuple[str, str]:
        return "synthetic-user", "synthetic-secret"


def _capture(case: str) -> WindowsCapture:
    return WindowsCapture.model_validate(_capture_payload(case))


def _capture_payload(case: str) -> dict[str, object]:
    return json.loads((FIXTURES / case / "capture.json").read_text(encoding="utf-8"))


def _collect(case: str):
    return collect_windows_fixture(FIXTURES / case / "manifest.json")
