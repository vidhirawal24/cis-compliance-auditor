"""Windows Phase-2 capture ingestion and explicit read-only transports."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import DeviceEngineError, FixtureInputError
from .models import CanonicalError, EvidenceReference, FactsEnvelope

WINDOWS_CAPTURE_SCHEMA = "1.0.0"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_CAPTURE_BYTES = 4_194_304
SUPPORTED_WINDOWS_PLATFORMS = {
    "windows_11_enterprise",
    "windows_11_standalone",
    "windows_server_2019",
}


class CaptureSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_identity: str
    timestamp: datetime
    state: str
    exit_status: int | None = None
    data: Any = None
    error_code: str | None = None
    limitation: str | None = None


class WindowsCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    collector_version: str
    captured_at: datetime
    sources: dict[str, CaptureSource]


class WindowsFixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    synthetic: bool
    label: str = Field(min_length=1)
    intended_platform: str
    illustrative_version: str
    scope: str
    org_id: UUID
    asset_id: UUID
    model: str
    capture_file: str


@dataclass(frozen=True, slots=True)
class WindowsClassification:
    platform: str | None
    supported: bool
    family: str
    deployment_context: str | None
    reason: str | None = None
    identity_available: bool = True
    benchmark_applicable: bool = True


@dataclass(frozen=True, slots=True)
class WindowsCollectedCapture:
    content: bytes
    sha256: str
    artifact_location: str
    org_id: UUID
    asset_id: UUID
    model: str


class SecretProvider(Protocol):
    def get_winrm_credentials(self, target: str) -> tuple[str, str]: ...


class EnvironmentWinRMSecretProvider:
    """Development-only runtime provider; production should use Mandar's vault client."""

    def get_winrm_credentials(self, target: str) -> tuple[str, str]:
        username = os.environ.get("CISGUARD_WINRM_USERNAME")
        password = os.environ.get("CISGUARD_WINRM_PASSWORD")
        if not username or not password:
            raise DeviceEngineError(
                "WINRM_SECRET_UNAVAILABLE",
                "WinRM credentials were not supplied by the runtime secret provider.",
            )
        return username, password


def classify_windows_capture(capture: WindowsCapture) -> WindowsClassification:
    os_source = capture.sources.get("os_identity")
    if os_source is None or os_source.state != "success" or not isinstance(os_source.data, Mapping):
        return WindowsClassification(None, False, "unknown", None, "OS identity unavailable", False)
    data = os_source.data
    caption = str(data.get("caption") or "")
    version = str(data.get("version") or "")
    build = str(data.get("build_number") or "")
    product_type = _integer_or_none(data.get("product_type"))
    edition = str(data.get("edition_id") or "")
    domain_source = capture.sources.get("domain_membership")
    part_of_domain = None
    if (
        domain_source
        and domain_source.state == "success"
        and isinstance(domain_source.data, Mapping)
    ):
        value = domain_source.data.get("part_of_domain")
        if isinstance(value, bool):
            part_of_domain = value
    deployment = (
        "domain_joined"
        if part_of_domain is True
        else "standalone"
        if part_of_domain is False
        else None
    )

    if product_type in {2, 3}:
        if "Windows Server 2019" in caption and version.startswith("10.0"):
            return WindowsClassification("windows_server_2019", True, "server", deployment)
        return WindowsClassification(
            None,
            False,
            "server",
            deployment,
            f"Unsupported Windows Server metadata: caption={caption!r}, build={build!r}",
        )
    if product_type == 1:
        if "Windows 11" not in caption or not version.startswith("10.0"):
            return WindowsClassification(
                None,
                False,
                "workstation",
                deployment,
                f"Unsupported Windows workstation metadata: caption={caption!r}, build={build!r}",
            )
        if "home" in caption.lower() or "core" in edition.lower():
            return WindowsClassification(
                None,
                False,
                "workstation",
                deployment,
                f"Unsupported Windows 11 Home edition/context: edition={edition!r}",
            )
        if edition.lower().startswith("enterprise"):
            return WindowsClassification("windows_11_enterprise", True, "workstation", deployment)
        if part_of_domain is False:
            return WindowsClassification("windows_11_standalone", True, "workstation", deployment)
        return WindowsClassification(
            None,
            False,
            "workstation",
            deployment,
            f"Unsupported Windows 11 edition/context: edition={edition!r}",
        )
    return WindowsClassification(
        None, False, "unknown", deployment, "Missing or invalid ProductType"
    )


def load_windows_fixture_manifest(path: Path) -> WindowsFixtureManifest:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureInputError(
            "WINDOWS_MANIFEST_NOT_FOUND", "Windows fixture manifest not found."
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureInputError(
            "MALFORMED_WINDOWS_MANIFEST", "Windows manifest is not valid UTF-8 JSON."
        ) from exc
    try:
        manifest = WindowsFixtureManifest.model_validate(payload)
    except ValidationError as exc:
        raise FixtureInputError(
            "MALFORMED_WINDOWS_MANIFEST",
            "Windows manifest failed schema validation.",
            details={"error_count": exc.error_count()},
        ) from exc
    if not manifest.synthetic:
        raise FixtureInputError(
            "NON_SYNTHETIC_FIXTURE_REJECTED", "Only synthetic Windows fixtures are accepted."
        )
    if manifest.intended_platform not in SUPPORTED_WINDOWS_PLATFORMS:
        raise FixtureInputError(
            "UNSUPPORTED_PLATFORM",
            "Windows fixture declares an unsupported target platform.",
            details={"platform": manifest.intended_platform},
        )
    return manifest


def probe_windows_fixture(manifest_path: Path) -> dict[str, Any]:
    manifest = load_windows_fixture_manifest(manifest_path)
    raw = _load_offline_capture(manifest_path, manifest)
    capture = parse_windows_capture(raw.content)
    classification = classify_windows_capture(capture)
    _validate_fixture_platform(manifest.intended_platform, classification)
    return {
        "schema_version": "1.0.0",
        "synthetic": True,
        "label": manifest.label,
        "platform": classification.platform,
        "family": classification.family,
        "deployment_context": classification.deployment_context,
        "illustrative_version": manifest.illustrative_version,
        "scope": manifest.scope,
        "implementation_status": "FIXTURE_TESTED_PARTIAL",
    }


def collect_windows_fixture(manifest_path: Path) -> FactsEnvelope:
    manifest = load_windows_fixture_manifest(manifest_path)
    raw = _load_offline_capture(manifest_path, manifest)
    capture = parse_windows_capture(raw.content)
    classification = classify_windows_capture(capture)
    _validate_fixture_platform(manifest.intended_platform, classification)
    return normalize_windows_capture(
        raw, capture, classification, collection_method="offline_synthetic_fixture"
    )


def collect_windows_local(
    *,
    org_id: UUID,
    asset_id: UUID,
    model: str = "local-windows-host",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    collection_only_diagnostic: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> FactsEnvelope:
    if os.name != "nt":
        raise DeviceEngineError(
            "LOCAL_WINDOWS_REQUIRED", "Local collection requires a Windows host."
        )
    script_path = windows_collector_script_path()
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
    ]
    try:
        result = runner(
            command,
            shell=False,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceEngineError(
            "POWERSHELL_TIMEOUT",
            "Fixed Windows collector exceeded its timeout.",
            details={"timeout_seconds": timeout_seconds},
        ) from exc
    stdout = result.stdout or b""
    if len(stdout) > max_output_bytes:
        raise DeviceEngineError(
            "CAPTURE_TOO_LARGE",
            "PowerShell collector output exceeded the configured limit.",
            details={"max_output_bytes": max_output_bytes},
        )
    if result.returncode != 0:
        raise DeviceEngineError(
            "POWERSHELL_FAILED",
            "Fixed Windows collector returned a nonzero exit status.",
            details={"exit_status": result.returncode, "stderr_redacted": True},
        )
    capture = parse_windows_capture(stdout)
    classification = classify_windows_capture(capture)
    if collection_only_diagnostic:
        classification = _home_collection_only_classification(capture, classification)
    if not classification.supported:
        code = (
            "WINDOWS_IDENTITY_UNAVAILABLE"
            if not classification.identity_available
            else "UNSUPPORTED_WINDOWS_VERSION"
        )
        raise DeviceEngineError(
            code,
            classification.reason or "Windows version is unsupported.",
            details={"source_states": _source_state_summary(capture.sources)},
        )
    raw = WindowsCollectedCapture(
        content=stdout,
        sha256=hashlib.sha256(stdout).hexdigest(),
        artifact_location="local://windows/fixed-read-only-capture",
        org_id=org_id,
        asset_id=asset_id,
        model=model,
    )
    return normalize_windows_capture(
        raw, capture, classification, collection_method="local_read_only"
    )


def collect_windows_winrm(
    *,
    target: str,
    secret_provider: SecretProvider,
    org_id: UUID,
    asset_id: UUID,
    model: str = "remote-windows-host",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
    session_factory: Callable[..., Any] | None = None,
) -> FactsEnvelope:
    parsed_target = urlparse(target)
    if parsed_target.scheme.lower() != "https" or not parsed_target.hostname:
        raise DeviceEngineError(
            "INSECURE_WINRM_TARGET",
            "WinRM target must be an explicit HTTPS URL with certificate validation.",
        )
    username, password = secret_provider.get_winrm_credentials(target)
    if session_factory is None:
        try:
            import winrm  # type: ignore[import-not-found]
        except ImportError as exc:
            raise DeviceEngineError(
                "OPTIONAL_DEPENDENCY_MISSING",
                "Remote WinRM requires the optional pywinrm dependency.",
            ) from exc
        session_factory = winrm.Session
    script = windows_collector_script_path().read_text(encoding="utf-8")
    try:
        session = session_factory(
            target,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="validate",
            read_timeout_sec=timeout_seconds,
            operation_timeout_sec=max(1, timeout_seconds - 5),
        )
        result = session.run_ps(script)
    except Exception as exc:
        raise DeviceEngineError(
            "WINRM_TRANSPORT_FAILED",
            "Authorized WinRM collection failed; transport details were redacted.",
            details={"target_host": parsed_target.hostname, "details_redacted": True},
        ) from exc
    stdout = bytes(result.std_out or b"")
    if len(stdout) > max_output_bytes:
        raise DeviceEngineError("CAPTURE_TOO_LARGE", "WinRM capture exceeded the configured limit.")
    if int(result.status_code) != 0:
        raise DeviceEngineError(
            "POWERSHELL_FAILED",
            "Remote fixed collector returned a nonzero exit status.",
            details={"exit_status": int(result.status_code), "stderr_redacted": True},
        )
    capture = parse_windows_capture(stdout)
    classification = classify_windows_capture(capture)
    if not classification.supported:
        code = (
            "WINDOWS_IDENTITY_UNAVAILABLE"
            if not classification.identity_available
            else "UNSUPPORTED_WINDOWS_VERSION"
        )
        raise DeviceEngineError(
            code, classification.reason or "Unsupported remote Windows version."
        )
    raw = WindowsCollectedCapture(
        content=stdout,
        sha256=hashlib.sha256(stdout).hexdigest(),
        artifact_location=f"winrm://{parsed_target.hostname}/fixed-read-only-capture",
        org_id=org_id,
        asset_id=asset_id,
        model=model,
    )
    return normalize_windows_capture(
        raw, capture, classification, collection_method="winrm_read_only"
    )


def parse_windows_capture(content: bytes) -> WindowsCapture:
    if not content.strip():
        raise FixtureInputError("EMPTY_WINDOWS_CAPTURE", "Windows capture is empty.")
    try:
        payload = json.loads(content.decode("utf-8-sig", errors="strict"))
        capture = WindowsCapture.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise FixtureInputError(
            "MALFORMED_WINDOWS_CAPTURE", "Windows capture is not valid schema-compliant JSON."
        ) from exc
    if capture.schema_version != WINDOWS_CAPTURE_SCHEMA:
        raise FixtureInputError(
            "UNSUPPORTED_CAPTURE_SCHEMA", "Windows capture schema version is unsupported."
        )
    return capture


def normalize_windows_capture(
    raw: WindowsCollectedCapture,
    capture: WindowsCapture,
    classification: WindowsClassification,
    *,
    collection_method: str,
) -> FactsEnvelope:
    if not classification.supported or classification.platform is None:
        code = (
            "WINDOWS_IDENTITY_UNAVAILABLE"
            if not classification.identity_available
            else "UNSUPPORTED_WINDOWS_VERSION"
        )
        raise DeviceEngineError(code, classification.reason or "Unsupported Windows capture.")
    sources = capture.sources
    facts = {
        "os": _source_fact(sources.get("os_identity")),
        "deployment": {
            "context": classification.deployment_context,
            "domain_membership": _source_fact(sources.get("domain_membership")),
            "effective_domain_policy_verified": False,
        },
        "account_policy": _source_fact(sources.get("account_policy")),
        "local_security_policy": _source_fact(sources.get("local_security_policy")),
        "audit_policy": _source_fact(sources.get("audit_policy")),
        "firewall_profiles": _source_fact(sources.get("firewall_profiles")),
        "services": _source_fact(sources.get("services")),
        "registry_settings": _source_fact(sources.get("registry_settings")),
        "permissions": _source_fact(sources.get("permissions")),
    }
    errors = _source_errors(sources)
    os_data = sources["os_identity"].data if "os_identity" in sources else {}
    version = "unknown"
    if isinstance(os_data, Mapping):
        os_version = os_data.get("version") or "unknown"
        build_number = os_data.get("build_number") or "unknown"
        version = f"{os_version} build {build_number}"
    return FactsEnvelope(
        org_id=raw.org_id,
        asset_id=raw.asset_id,
        platform=classification.platform,
        vendor="Microsoft",
        model=raw.model,
        os_or_firmware_version=version,
        collector_version=capture.collector_version,
        collection_method=collection_method,
        collected_at=capture.captured_at,
        facts=facts,
        evidence_refs=[
            EvidenceReference(
                sha256=raw.sha256,
                source_identity="fixed:powershell/windows-read-only-v1",
                artifact_location=raw.artifact_location,
                timestamp=capture.captured_at,
            )
        ],
        supported_capabilities=[
            "windows_os_identity",
            "windows_domain_context",
            "windows_account_policy",
            "windows_local_security_policy",
            "windows_audit_policy",
            "windows_firewall_profiles",
            "windows_service_state",
            "windows_registry_settings",
            "windows_path_permissions",
        ],
        unsupported_capabilities=[
            "effective_domain_policy",
            "compliance_evaluation",
            "remediation",
            "live_write",
            *([] if classification.benchmark_applicable else ["benchmark_applicability"]),
        ],
        errors=errors,
    )


def windows_collector_script_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "windows_collect.ps1"


def _home_collection_only_classification(
    capture: WindowsCapture, classification: WindowsClassification
) -> WindowsClassification:
    """Permit fact diagnostics for Home without expanding benchmark support."""
    identity = capture.sources.get("os_identity")
    data = identity.data if identity and isinstance(identity.data, Mapping) else {}
    caption = str(data.get("caption") or "")
    edition = str(data.get("edition_id") or "")
    product_type = _integer_or_none(data.get("product_type"))
    if (
        not classification.supported
        and product_type == 1
        and "Windows 11" in caption
        and ("home" in caption.lower() or "core" in edition.lower())
    ):
        return WindowsClassification(
            "windows_11_home_diagnostic",
            True,
            "workstation",
            classification.deployment_context,
            "Collection-only diagnostic; Windows 11 Home is outside supported benchmark scope.",
            True,
            False,
        )
    return classification


def _load_offline_capture(
    manifest_path: Path, manifest: WindowsFixtureManifest
) -> WindowsCollectedCapture:
    base = manifest_path.resolve().parent
    candidate = (base / manifest.capture_file).resolve()
    if base != candidate and base not in candidate.parents:
        raise FixtureInputError(
            "INVALID_FIXTURE_PATH", "Windows capture path escapes its fixture directory."
        )
    try:
        content = candidate.read_bytes()
    except FileNotFoundError as exc:
        raise FixtureInputError(
            "WINDOWS_CAPTURE_NOT_FOUND", "Windows capture file not found."
        ) from exc
    if len(content) > DEFAULT_MAX_CAPTURE_BYTES:
        raise FixtureInputError(
            "CAPTURE_TOO_LARGE", "Windows capture exceeds the configured limit."
        )
    return WindowsCollectedCapture(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        artifact_location=f"fixture://windows/{base.name}/{manifest.capture_file}",
        org_id=manifest.org_id,
        asset_id=manifest.asset_id,
        model=manifest.model,
    )


def _validate_fixture_platform(
    intended_platform: str, classification: WindowsClassification
) -> None:
    if not classification.supported:
        code = (
            "WINDOWS_IDENTITY_UNAVAILABLE"
            if not classification.identity_available
            else "UNSUPPORTED_WINDOWS_VERSION"
        )
        raise FixtureInputError(
            code,
            classification.reason or "Fixture Windows version is unsupported.",
        )
    if classification.platform != intended_platform:
        raise FixtureInputError(
            "PLATFORM_MISMATCH",
            "Fixture classification does not match its intended platform.",
            details={"intended": intended_platform, "actual": classification.platform},
        )


def _source_fact(source: CaptureSource | None) -> dict[str, Any]:
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


def _source_errors(sources: Mapping[str, CaptureSource]) -> list[CanonicalError]:
    errors: list[CanonicalError] = []
    namespace = UUID("c25624be-3337-4ec5-9071-00c4f34b19db")
    from uuid import uuid5

    for name, source in sorted(sources.items()):
        if source.state == "success":
            continue
        code, message, retryable = _source_error_semantics(name, source)
        errors.append(
            CanonicalError(
                code=code,
                message=message,
                request_id=uuid5(namespace, name),
                details={
                    "source": name,
                    "state": source.state,
                    "exit_status": source.exit_status,
                },
                retryable=retryable,
            )
        )
    return errors


def _source_error_semantics(source_name: str, source: CaptureSource) -> tuple[str, str, bool]:
    """Map known privilege failures without exposing command stderr."""
    if source_name == "audit_policy" and source.exit_status == 1314:
        return (
            "AUDITPOL_PRIVILEGE_REQUIRED",
            "auditpol requires privileges unavailable to this non-elevated context; "
            "rerun only in an authorized context.",
            False,
        )
    if source_name == "local_security_policy" and source.exit_status == 740:
        return (
            "SECEDIT_ELEVATION_REQUIRED",
            "secedit requires elevation; no automatic elevation was attempted.",
            False,
        )
    return (
        source.error_code or f"SOURCE_{source.state.upper()}",
        f"Windows collection source {source_name} was {source.state}.",
        source.state == "error",
    )


def _source_state_summary(sources: Mapping[str, CaptureSource]) -> dict[str, str]:
    return {name: source.state for name, source in sorted(sources.items())}


def _integer_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
