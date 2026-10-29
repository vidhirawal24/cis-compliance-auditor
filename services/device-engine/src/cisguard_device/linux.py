"""Linux Phase-3 native capture, normalization, and explicit transports."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import DeviceEngineError, FixtureInputError
from .models import CanonicalError, EvidenceReference, FactsEnvelope

LINUX_CAPTURE_SCHEMA = "1.0.0"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_CAPTURE_BYTES = 4_194_304
SUPPORTED_LINUX_PLATFORMS = {
    "ubuntu_20_04_lts",
    "ubuntu_22_04_lts",
    "rhel_8",
    "rhel_9",
}


class LinuxSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_identity: str
    timestamp: datetime
    state: str
    exit_status: int | None = None
    data: Any = None
    error_code: str | None = None
    limitation: str | None = None


class LinuxCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    collector_version: str
    captured_at: datetime
    sources: dict[str, LinuxSource]


class LinuxFixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    synthetic: bool
    label: str = Field(min_length=1)
    intended_platform: str
    illustrative_version: str
    case: str
    scope: str
    org_id: UUID
    asset_id: UUID
    model: str
    capture_file: str


@dataclass(frozen=True, slots=True)
class LinuxClassification:
    platform: str | None
    supported: bool
    distribution_id: str | None
    version_id: str | None
    reason: str | None = None
    identity_available: bool = True


@dataclass(frozen=True, slots=True)
class LinuxCollectedCapture:
    content: bytes
    sha256: str
    artifact_location: str
    org_id: UUID
    asset_id: UUID
    model: str


class SSHSecretProvider(Protocol):
    def get_ssh_credentials(self, target: str) -> Mapping[str, str | None]: ...


class EnvironmentSSHSecretProvider:
    """Development provider; production should inject Mandar's vault-backed provider."""

    def get_ssh_credentials(self, target: str) -> Mapping[str, str | None]:
        username = os.environ.get("CISGUARD_SSH_USERNAME")
        password = os.environ.get("CISGUARD_SSH_PASSWORD")
        key_filename = os.environ.get("CISGUARD_SSH_KEY_FILE")
        if not username or (not password and not key_filename):
            raise DeviceEngineError(
                "SSH_SECRET_UNAVAILABLE",
                "SSH credentials were not supplied by the runtime secret provider.",
            )
        return {"username": username, "password": password, "key_filename": key_filename}


def classify_linux_capture(capture: LinuxCapture) -> LinuxClassification:
    source = capture.sources.get("os_identity")
    if source is None or source.state != "success" or not isinstance(source.data, Mapping):
        return LinuxClassification(None, False, None, None, "Linux identity unavailable", False)
    distribution_id = str(source.data.get("id") or "").lower()
    version_id = str(source.data.get("version_id") or "")
    if not distribution_id or not version_id:
        return LinuxClassification(
            None,
            False,
            distribution_id or None,
            version_id or None,
            "Linux identity incomplete",
            False,
        )
    if distribution_id == "ubuntu":
        if version_id == "20.04":
            return LinuxClassification("ubuntu_20_04_lts", True, distribution_id, version_id)
        if version_id == "22.04":
            return LinuxClassification("ubuntu_22_04_lts", True, distribution_id, version_id)
        return LinuxClassification(
            None, False, distribution_id, version_id, f"Unsupported Ubuntu version: {version_id}"
        )
    if distribution_id == "rhel":
        major = version_id.split(".", 1)[0]
        if major == "8":
            return LinuxClassification("rhel_8", True, distribution_id, version_id)
        if major == "9":
            return LinuxClassification("rhel_9", True, distribution_id, version_id)
        return LinuxClassification(
            None, False, distribution_id, version_id, f"Unsupported RHEL version: {version_id}"
        )
    return LinuxClassification(
        None,
        False,
        distribution_id,
        version_id,
        f"Unsupported Linux distribution: {distribution_id}",
    )


def load_linux_fixture_manifest(path: Path) -> LinuxFixtureManifest:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = LinuxFixtureManifest.model_validate(payload)
    except FileNotFoundError as exc:
        raise FixtureInputError(
            "LINUX_MANIFEST_NOT_FOUND", "Linux fixture manifest not found."
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise FixtureInputError("MALFORMED_LINUX_MANIFEST", "Linux manifest is invalid.") from exc
    if not manifest.synthetic:
        raise FixtureInputError(
            "NON_SYNTHETIC_FIXTURE_REJECTED", "Only synthetic Linux fixtures are accepted."
        )
    if manifest.intended_platform not in SUPPORTED_LINUX_PLATFORMS:
        raise FixtureInputError("UNSUPPORTED_PLATFORM", "Linux fixture target is unsupported.")
    if manifest.case not in {"secure", "weak", "unknown"}:
        raise FixtureInputError("MALFORMED_LINUX_MANIFEST", "Linux fixture case is invalid.")
    return manifest


def probe_linux_fixture(manifest_path: Path) -> dict[str, Any]:
    manifest = load_linux_fixture_manifest(manifest_path)
    raw = _load_fixture_capture(manifest_path, manifest)
    capture = parse_linux_capture(raw.content)
    classification = classify_linux_capture(capture)
    _validate_fixture_platform(manifest.intended_platform, classification)
    return {
        "schema_version": "1.0.0",
        "synthetic": True,
        "label": manifest.label,
        "platform": classification.platform,
        "case": manifest.case,
        "illustrative_version": manifest.illustrative_version,
        "scope": manifest.scope,
        "implementation_status": "FIXTURE_TESTED_PARTIAL",
    }


def collect_linux_fixture(manifest_path: Path) -> FactsEnvelope:
    manifest = load_linux_fixture_manifest(manifest_path)
    raw = _load_fixture_capture(manifest_path, manifest)
    capture = parse_linux_capture(raw.content)
    classification = classify_linux_capture(capture)
    _validate_fixture_platform(manifest.intended_platform, classification)
    return normalize_linux_capture(raw, capture, classification, "offline_synthetic_fixture")


def collect_linux_local(
    *,
    org_id: UUID,
    asset_id: UUID,
    model: str = "local-linux-host",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> FactsEnvelope:
    if not sys.platform.startswith("linux"):
        raise DeviceEngineError(
            "LOCAL_LINUX_REQUIRED", "Local Linux collection requires a Linux host."
        )
    command = [os.environ.get("PYTHON", "python3"), str(linux_collector_script_path())]
    try:
        result = runner(
            command, shell=False, capture_output=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceEngineError(
            "LINUX_COLLECTOR_TIMEOUT", "Fixed Linux collector timed out."
        ) from exc
    stdout = result.stdout or b""
    if len(stdout) > max_output_bytes:
        raise DeviceEngineError("CAPTURE_TOO_LARGE", "Linux collector output exceeded its limit.")
    if result.returncode != 0:
        raise DeviceEngineError(
            "LINUX_COLLECTOR_FAILED",
            "Fixed Linux collector returned a nonzero exit status.",
            details={"exit_status": result.returncode, "stderr_redacted": True},
        )
    capture = parse_linux_capture(stdout)
    classification = classify_linux_capture(capture)
    _raise_for_classification(classification, capture.sources)
    raw = LinuxCollectedCapture(
        stdout,
        hashlib.sha256(stdout).hexdigest(),
        "local://linux/fixed-read-only-capture",
        org_id,
        asset_id,
        model,
    )
    return normalize_linux_capture(raw, capture, classification, "local_read_only")


def collect_linux_ssh(
    *,
    target: str,
    port: int,
    known_hosts: Path,
    secret_provider: SSHSecretProvider,
    org_id: UUID,
    asset_id: UUID,
    model: str = "remote-linux-host",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    client_factory: Callable[[], Any] | None = None,
) -> FactsEnvelope:
    if not known_hosts.is_file():
        raise DeviceEngineError(
            "KNOWN_HOSTS_REQUIRED", "SSH requires an existing known_hosts file."
        )
    credentials = secret_provider.get_ssh_credentials(target)
    if client_factory is None:
        try:
            import paramiko  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DeviceEngineError(
                "OPTIONAL_DEPENDENCY_MISSING", "SSH collection requires optional Paramiko."
            ) from exc
        client_factory = paramiko.SSHClient
        reject_policy = paramiko.RejectPolicy()
    else:
        reject_policy = object()
    client = client_factory()
    try:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(reject_policy)
        client.connect(
            target,
            port=port,
            username=credentials.get("username"),
            password=credentials.get("password"),
            key_filename=credentials.get("key_filename"),
            timeout=timeout_seconds,
            banner_timeout=timeout_seconds,
            auth_timeout=timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        script = linux_collector_script_path().read_text(encoding="utf-8")
        stdin, stdout_stream, stderr_stream = client.exec_command(
            "python3 -", timeout=timeout_seconds
        )
        stdin.write(script)
        stdin.channel.shutdown_write()
        content = stdout_stream.read(max_output_bytes + 1)
        exit_status = stdout_stream.channel.recv_exit_status()
        stderr_stream.read(4096)
    except Exception as exc:
        raise DeviceEngineError(
            "SSH_TRANSPORT_FAILED",
            "Authorized SSH collection failed; transport details were redacted.",
            details={"target": target, "details_redacted": True},
        ) from exc
    finally:
        client.close()
    if len(content) > max_output_bytes:
        raise DeviceEngineError("CAPTURE_TOO_LARGE", "SSH capture exceeded its limit.")
    if exit_status != 0:
        raise DeviceEngineError(
            "LINUX_COLLECTOR_FAILED",
            "Remote fixed collector failed.",
            details={"exit_status": exit_status, "stderr_redacted": True},
        )
    capture = parse_linux_capture(content)
    classification = classify_linux_capture(capture)
    _raise_for_classification(classification, capture.sources)
    raw = LinuxCollectedCapture(
        content,
        hashlib.sha256(content).hexdigest(),
        f"ssh://{target}/fixed-read-only-capture",
        org_id,
        asset_id,
        model,
    )
    return normalize_linux_capture(raw, capture, classification, "ssh_read_only")


def parse_linux_capture(content: bytes) -> LinuxCapture:
    if not content.strip():
        raise FixtureInputError("EMPTY_LINUX_CAPTURE", "Linux capture is empty.")
    try:
        capture = LinuxCapture.model_validate(json.loads(content.decode("utf-8", errors="strict")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise FixtureInputError(
            "MALFORMED_LINUX_CAPTURE", "Linux capture is invalid JSON."
        ) from exc
    if capture.schema_version != LINUX_CAPTURE_SCHEMA:
        raise FixtureInputError(
            "UNSUPPORTED_CAPTURE_SCHEMA", "Linux capture schema is unsupported."
        )
    return capture


def normalize_linux_capture(
    raw: LinuxCollectedCapture,
    capture: LinuxCapture,
    classification: LinuxClassification,
    collection_method: str,
) -> FactsEnvelope:
    _raise_for_classification(classification, capture.sources)
    assert classification.platform is not None
    names = (
        "os_identity",
        "ssh",
        "pam",
        "account_policy",
        "audit",
        "sysctl",
        "firewall",
        "services",
        "packages",
        "permissions",
        "selinux",
    )
    facts = {name: _source_fact(capture.sources.get(name)) for name in names}
    os_data = capture.sources["os_identity"].data
    version = (
        str(os_data.get("version_id") or "unknown") if isinstance(os_data, Mapping) else "unknown"
    )
    return FactsEnvelope(
        org_id=raw.org_id,
        asset_id=raw.asset_id,
        platform=classification.platform,
        vendor="Canonical" if classification.distribution_id == "ubuntu" else "Red Hat",
        model=raw.model,
        os_or_firmware_version=version,
        collector_version=capture.collector_version,
        collection_method=collection_method,
        collected_at=capture.captured_at,
        facts=facts,
        evidence_refs=[
            EvidenceReference(
                sha256=raw.sha256,
                source_identity="fixed:python/linux-read-only-v1",
                artifact_location=raw.artifact_location,
                timestamp=capture.captured_at,
            )
        ],
        supported_capabilities=[
            "linux_os_identity",
            "linux_ssh_config",
            "linux_pam_config",
            "linux_account_policy",
            "linux_audit",
            "linux_sysctl",
            "linux_host_firewall",
            "linux_service_state",
            "linux_package_inventory",
            "linux_path_permissions",
            "linux_selinux_state",
        ],
        unsupported_capabilities=[
            "effective_network_exposure",
            "password_strength_verification",
            "patch_compliance",
            "compliance_evaluation",
            "remediation",
            "live_write",
        ],
        errors=_source_errors(capture.sources),
    )


def linux_collector_script_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "linux_collect.py"


def _load_fixture_capture(
    manifest_path: Path, manifest: LinuxFixtureManifest
) -> LinuxCollectedCapture:
    base = manifest_path.resolve().parent
    candidate = (base / manifest.capture_file).resolve()
    if base != candidate and base not in candidate.parents:
        raise FixtureInputError(
            "INVALID_FIXTURE_PATH", "Linux capture escapes its fixture directory."
        )
    try:
        content = candidate.read_bytes()
    except FileNotFoundError as exc:
        raise FixtureInputError("LINUX_CAPTURE_NOT_FOUND", "Linux capture file not found.") from exc
    if len(content) > DEFAULT_MAX_CAPTURE_BYTES:
        raise FixtureInputError("CAPTURE_TOO_LARGE", "Linux capture exceeds its limit.")
    return LinuxCollectedCapture(
        content,
        hashlib.sha256(content).hexdigest(),
        f"fixture://linux/{base.name}/{manifest.capture_file}",
        manifest.org_id,
        manifest.asset_id,
        manifest.model,
    )


def _validate_fixture_platform(intended: str, classification: LinuxClassification) -> None:
    if not classification.identity_available:
        raise FixtureInputError(
            "LINUX_IDENTITY_UNAVAILABLE", classification.reason or "Identity unavailable."
        )
    if not classification.supported:
        raise FixtureInputError(
            "UNSUPPORTED_LINUX_VERSION", classification.reason or "Unsupported Linux."
        )
    if classification.platform != intended:
        raise FixtureInputError(
            "PLATFORM_MISMATCH",
            "Linux fixture platform mismatch.",
            details={"intended": intended, "actual": classification.platform},
        )


def _raise_for_classification(
    classification: LinuxClassification, sources: Mapping[str, LinuxSource]
) -> None:
    if not classification.identity_available:
        raise DeviceEngineError(
            "LINUX_IDENTITY_UNAVAILABLE",
            classification.reason or "Identity unavailable.",
            details={"source_states": _source_state_summary(sources)},
        )
    if not classification.supported:
        raise DeviceEngineError(
            "UNSUPPORTED_LINUX_VERSION", classification.reason or "Unsupported Linux."
        )


def _source_fact(source: LinuxSource | None) -> dict[str, Any]:
    if source is None:
        return {"collection_state": "unavailable", "value": None, "limitation": "source absent"}
    return {
        "collection_state": source.state,
        "value": source.data if source.state == "success" else None,
        "source": {
            "identity": source.source_identity,
            "timestamp": source.timestamp.isoformat().replace("+00:00", "Z"),
            "exit_status": source.exit_status,
        },
        "error_code": source.error_code,
        "limitation": source.limitation,
    }


def _source_errors(sources: Mapping[str, LinuxSource]) -> list[CanonicalError]:
    namespace = UUID("df80cfaa-e01e-4ebd-a373-d9f322694bda")
    return [
        CanonicalError(
            code=source.error_code or f"SOURCE_{source.state.upper()}",
            message=f"Linux collection source {name} was {source.state}.",
            request_id=uuid5(namespace, name),
            details={"source": name, "state": source.state},
            retryable=source.state == "error",
        )
        for name, source in sorted(sources.items())
        if source.state != "success"
    ]


def _source_state_summary(sources: Mapping[str, LinuxSource]) -> dict[str, str]:
    return {name: source.state for name, source in sorted(sources.items())}
