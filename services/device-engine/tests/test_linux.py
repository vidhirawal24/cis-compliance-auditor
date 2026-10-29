import hashlib
import json
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

import cisguard_device.linux as linux
from cisguard_device.errors import DeviceEngineError, FixtureInputError
from cisguard_device.linux import (
    LinuxCapture,
    classify_linux_capture,
    collect_linux_fixture,
    collect_linux_local,
    collect_linux_ssh,
    parse_linux_capture,
    probe_linux_fixture,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "linux"
ORG_ID = UUID("11111111-1111-4111-8111-111111111111")
ASSET_ID = UUID("39999999-0000-4000-8000-000000000001")
TARGET_CASES = {
    "ubuntu2004": "ubuntu_20_04_lts",
    "ubuntu2204": "ubuntu_22_04_lts",
    "rhel8": "rhel_8",
    "rhel9": "rhel_9",
}


@pytest.mark.parametrize(
    ("case", "platform"),
    [
        (f"{prefix}_{state}", platform)
        for prefix, platform in TARGET_CASES.items()
        for state in ("secure", "weak", "unknown")
    ],
)
def test_all_linux_fixtures_classify_and_replay_deterministically(case: str, platform: str) -> None:
    manifest = FIXTURES / case / "manifest.json"
    first = collect_linux_fixture(manifest)
    second = collect_linux_fixture(manifest)
    assert first.platform == platform
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert probe_linux_fixture(manifest)["platform"] == platform


def test_exact_capture_byte_hash() -> None:
    case = FIXTURES / "ubuntu2204_secure"
    result = collect_linux_fixture(case / "manifest.json")
    assert (
        result.evidence_refs[0].sha256
        == hashlib.sha256((case / "capture.json").read_bytes()).hexdigest()
    )


def test_secure_weak_unknown_and_configured_runtime_differences() -> None:
    secure = _collect("ubuntu2004_secure")
    weak = _collect("ubuntu2004_weak")
    unknown = _collect("ubuntu2004_unknown")
    assert secure.facts["ssh"]["value"]["configured"]["permit_root_login"] == "no"
    assert weak.facts["sysctl"]["value"]["configured"]["net.ipv4.ip_forward"] == "0"
    assert weak.facts["sysctl"]["value"]["runtime"]["net.ipv4.ip_forward"] == "1"
    assert unknown.facts["firewall"]["collection_state"] == "unavailable"
    assert unknown.facts["firewall"]["value"] is None


def test_sshd_match_context_and_selinux_differences_are_preserved() -> None:
    ubuntu = _collect("ubuntu2204_secure")
    rhel = _collect("rhel9_weak")
    assert ubuntu.facts["ssh"]["value"]["match_context_complete"] is False
    assert rhel.facts["selinux"]["value"] == {
        "configured": "enforcing",
        "runtime": "Disabled",
    }


def test_unsupported_derivative_version_and_identity_unavailable() -> None:
    payload = _payload("ubuntu2204_secure")
    payload["sources"]["os_identity"]["data"]["id"] = "linuxmint"
    result = classify_linux_capture(LinuxCapture.model_validate(payload))
    assert result.supported is False
    assert result.identity_available is True
    assert "Unsupported Linux distribution" in str(result.reason)
    payload["sources"]["os_identity"].update({"state": "denied", "data": None})
    unavailable = classify_linux_capture(LinuxCapture.model_validate(payload))
    assert unavailable.identity_available is False
    assert unavailable.reason == "Linux identity unavailable"


def test_unsupported_ubuntu_version_is_not_substituted() -> None:
    payload = _payload("ubuntu2204_secure")
    payload["sources"]["os_identity"]["data"]["version_id"] = "24.04"
    result = classify_linux_capture(LinuxCapture.model_validate(payload))
    assert result.supported is False
    assert result.reason == "Unsupported Ubuntu version: 24.04"


def test_malformed_capture_and_fixture_platform_mismatch(tmp_path: Path) -> None:
    with pytest.raises(FixtureInputError) as malformed:
        parse_linux_capture(b"not-json")
    assert malformed.value.code == "MALFORMED_LINUX_CAPTURE"
    source_case = FIXTURES / "ubuntu2204_secure"
    manifest = json.loads((source_case / "manifest.json").read_text(encoding="utf-8"))
    manifest["intended_platform"] = "rhel_9"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "capture.json").write_bytes((source_case / "capture.json").read_bytes())
    with pytest.raises(FixtureInputError) as mismatch:
        collect_linux_fixture(tmp_path / "manifest.json")
    assert mismatch.value.code == "PLATFORM_MISMATCH"


def test_local_subprocess_timeout_nonzero_and_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(linux.sys, "platform", "linux")

    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired("python3", 1)

    with pytest.raises(DeviceEngineError) as captured:
        collect_linux_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=timeout)
    assert captured.value.code == "LINUX_COLLECTOR_TIMEOUT"

    def failed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 3, stdout=b"", stderr=b"secret")

    with pytest.raises(DeviceEngineError) as captured:
        collect_linux_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=failed)
    assert captured.value.code == "LINUX_COLLECTOR_FAILED"
    assert captured.value.details == {"exit_status": 3, "stderr_redacted": True}

    def malformed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout=b"bad-json", stderr=b"")

    with pytest.raises(FixtureInputError) as captured:
        collect_linux_local(org_id=ORG_ID, asset_id=ASSET_ID, runner=malformed)
    assert captured.value.code == "MALFORMED_LINUX_CAPTURE"


def test_ssh_requires_known_hosts_and_redacts_transport_failure(tmp_path: Path) -> None:
    provider = _SecretProvider()
    with pytest.raises(DeviceEngineError) as missing:
        collect_linux_ssh(
            target="example.invalid",
            port=22,
            known_hosts=tmp_path / "missing",
            secret_provider=provider,
            org_id=ORG_ID,
            asset_id=ASSET_ID,
        )
    assert missing.value.code == "KNOWN_HOSTS_REQUIRED"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic host key placeholder", encoding="utf-8")
    client = _FailingSSHClient()
    with pytest.raises(DeviceEngineError) as failed:
        collect_linux_ssh(
            target="example.invalid",
            port=22,
            known_hosts=known_hosts,
            secret_provider=provider,
            org_id=ORG_ID,
            asset_id=ASSET_ID,
            client_factory=lambda: client,
        )
    assert failed.value.code == "SSH_TRANSPORT_FAILED"
    assert failed.value.details == {"target": "example.invalid", "details_redacted": True}
    assert client.policy_set is True


class _SecretProvider:
    def get_ssh_credentials(self, target: str):
        return {"username": "synthetic", "password": "synthetic", "key_filename": None}


class _FailingSSHClient:
    policy_set = False

    def load_host_keys(self, path: str) -> None:
        return None

    def set_missing_host_key_policy(self, policy: object) -> None:
        self.policy_set = True

    def connect(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError("unknown host key and secret material")

    def close(self) -> None:
        return None


def _collect(case: str):
    return collect_linux_fixture(FIXTURES / case / "manifest.json")


def _payload(case: str):
    return json.loads((FIXTURES / case / "capture.json").read_text(encoding="utf-8"))
