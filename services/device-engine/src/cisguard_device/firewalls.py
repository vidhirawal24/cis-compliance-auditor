"""Phase-4 firewall capture replay and bounded read-only transport primitives."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .errors import DeviceEngineError, FixtureInputError
from .models import CanonicalError, EvidenceReference, FactsEnvelope

PLATFORMS = {
    "fortios": "Fortinet",
    "cisco_asa": "Cisco",
    "cisco_ftd_fmc": "Cisco",
    "checkpoint_management": "Check Point",
}
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_OBJECT_DEPTH = 16
MAX_PAGES = 100
ASA_SHOW_COMMANDS = (
    "show version",
    "show mode",
    "show context",
    "show interface ip brief",
    "show running-config access-list",
    "show running-config access-group",
    "show running-config object",
    "show running-config object-group",
    "show running-config nat",
    "show running-config http",
    "show running-config telnet",
    "show running-config ssh",
    "show running-config logging",
    "show running-config ntp",
    "show running-config snmp-server",
)


class FirewallManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    synthetic: bool
    label: str
    platform: str
    illustrative_version: str
    model: str
    org_id: UUID
    asset_id: UUID
    collected_at: datetime
    capture_file: str = "capture.json"
    collection_completeness: str
    policy_state: str
    expected_supported_capabilities: list[str]
    expected_unsupported_capabilities: list[str]


class FirewallCapture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0.0"
    platform: str
    context: dict[str, Any]
    sources: list[dict[str, Any]]
    facts: dict[str, Any]


class FirewallSecretProvider(Protocol):
    def get_ssh_credentials(self, target: str) -> Mapping[str, str | None]: ...


def validate_https_target(target: str, *, custom_ca: Path | None = None) -> str:
    """Validate an API origin before credentials are obtained or forwarded."""
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DeviceEngineError(
            "TLS_IDENTITY_REQUIRED", "Firewall API target must be an HTTPS origin."
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise DeviceEngineError(
            "API_ORIGIN_REQUIRED", "Target must not contain an API path or query."
        )
    if custom_ca is not None and not custom_ca.is_file():
        raise DeviceEngineError("CUSTOM_CA_NOT_FOUND", "Configured custom CA file does not exist.")
    return f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")


def map_http_failure(status_code: int) -> DeviceEngineError:
    """Map transport status without retaining headers or sensitive bodies."""
    if status_code == 401:
        return DeviceEngineError("AUTHENTICATION_FAILED", "Firewall API authentication failed.")
    if status_code == 403:
        return DeviceEngineError("PERMISSION_DENIED", "Firewall API capability is unavailable.")
    if status_code == 408:
        return DeviceEngineError("API_TIMEOUT", "Firewall API timed out.", retryable=True)
    if status_code == 429:
        return DeviceEngineError("RATE_LIMITED", "Firewall API rate limit reached.", retryable=True)
    return DeviceEngineError(
        "API_TRANSPORT_FAILED",
        "Firewall API request failed.",
        details={"status_code": status_code},
        retryable=status_code >= 500,
    )


def parse_firewall_capture(
    content: bytes, *, max_bytes: int = MAX_CAPTURE_BYTES
) -> FirewallCapture:
    if len(content) > max_bytes:
        raise FixtureInputError("FIREWALL_CAPTURE_TOO_LARGE", "Firewall capture exceeds limit.")
    try:
        payload = json.loads(content.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise FixtureInputError("INVALID_ENCODING", "Firewall capture must be UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise FixtureInputError(
            "MALFORMED_FIREWALL_CAPTURE", "Firewall capture is not JSON."
        ) from exc
    capture = FirewallCapture.model_validate(payload)
    if capture.platform not in PLATFORMS:
        raise FixtureInputError("UNSUPPORTED_FIREWALL_PLATFORM", "Unknown firewall platform.")
    return capture


def collect_firewall_fixture(
    manifest_path: Path, *, max_bytes: int = MAX_CAPTURE_BYTES
) -> FactsEnvelope:
    manifest = _load_manifest(manifest_path)
    capture_path = _contained(manifest_path, manifest.capture_file)
    try:
        raw = capture_path.read_bytes()
    except FileNotFoundError as exc:
        raise FixtureInputError("FIREWALL_CAPTURE_NOT_FOUND", "Capture does not exist.") from exc
    capture = parse_firewall_capture(raw, max_bytes=max_bytes)
    if capture.platform != manifest.platform:
        raise FixtureInputError("PLATFORM_MISMATCH", "Manifest and capture platforms differ.")
    facts = json.loads(json.dumps(capture.facts, sort_keys=True))
    facts["context"] = capture.context
    facts["collection"] = {
        "completeness": manifest.collection_completeness,
        "policy_state": manifest.policy_state,
        "synthetic": True,
    }
    facts["object_resolution"] = resolve_objects(capture.facts.get("objects", {}))
    errors = _source_errors(capture.sources, manifest.asset_id)
    refs = [
        EvidenceReference(
            sha256=hashlib.sha256(raw).hexdigest(),
            source_identity="manifest:"
            + ",".join(str(s.get("identity", "unknown")) for s in capture.sources),
            artifact_location=str(capture_path),
            timestamp=manifest.collected_at,
        )
    ]
    return FactsEnvelope(
        org_id=manifest.org_id,
        asset_id=manifest.asset_id,
        platform=manifest.platform,
        vendor=PLATFORMS[manifest.platform],
        model=manifest.model,
        os_or_firmware_version=manifest.illustrative_version,
        collector_version="0.1.0",
        collection_method="offline_synthetic_firewall_capture",
        collected_at=manifest.collected_at,
        facts=facts,
        evidence_refs=refs,
        supported_capabilities=manifest.expected_supported_capabilities,
        unsupported_capabilities=manifest.expected_unsupported_capabilities,
        errors=errors,
    )


def probe_firewall_fixture(manifest_path: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    return {
        "schema_version": "1.0.0",
        "synthetic": True,
        "label": manifest.label,
        "platform": manifest.platform,
        "illustrative_version": manifest.illustrative_version,
        "transport_status": "OFFLINE_FIXTURE_TESTED_LIVE_NOT_CLAIMED",
    }


def resolve_objects(
    objects: Mapping[str, Any], *, max_depth: int = MAX_OBJECT_DEPTH
) -> dict[str, Any]:
    """Resolve nested groups while preserving cycles, missing members, and unsupported objects."""
    result: dict[str, Any] = {}

    def visit(name: str, trail: tuple[str, ...], depth: int) -> dict[str, Any]:
        if depth > max_depth:
            return {"status": "depth_limit", "values": [], "unresolved": [name]}
        if name in trail:
            return {"status": "cycle", "values": [], "unresolved": [*trail, name]}
        obj = objects.get(name)
        if obj is None:
            return {"status": "unresolved", "values": [], "unresolved": [name]}
        if not isinstance(obj, dict) or obj.get("type") not in {"group", "address", "service"}:
            return {"status": "unsupported", "values": [], "unresolved": [name]}
        if obj.get("type") != "group":
            value = obj.get("value")
            return {
                "status": "resolved" if value is not None else "unresolved",
                "values": [] if value is None else [value],
                "unresolved": [] if value is not None else [name],
            }
        values: list[Any] = []
        unresolved: list[str] = []
        statuses: list[str] = []
        for member in obj.get("members", []):
            child = visit(str(member), (*trail, name), depth + 1)
            values.extend(child["values"])
            unresolved.extend(child["unresolved"])
            statuses.append(child["status"])
        return {
            "status": "resolved"
            if statuses and all(s == "resolved" for s in statuses)
            else (statuses[0] if len(set(statuses)) == 1 else "partial"),
            "values": values,
            "unresolved": unresolved,
        }

    for object_name in sorted(objects):
        result[object_name] = visit(object_name, (), 0)
    return result


def collect_paginated(
    fetch_page: Callable[[str | None], tuple[list[Any], str | None]], *, max_pages: int = MAX_PAGES
) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str | None] = set()
    seen_pages: set[str] = set()
    for _ in range(max_pages):
        if cursor in seen_cursors:
            raise DeviceEngineError("PAGINATION_LOOP", "Pagination cursor repeated.")
        seen_cursors.add(cursor)
        page, next_cursor = fetch_page(cursor)
        signature = hashlib.sha256(json.dumps(page, sort_keys=True).encode()).hexdigest()
        if signature in seen_pages:
            raise DeviceEngineError("DUPLICATE_PAGE", "Pagination response repeated.")
        seen_pages.add(signature)
        items.extend(page)
        if next_cursor is None:
            return items
        cursor = next_cursor
    raise DeviceEngineError("PAGINATION_LIMIT", "Pagination exceeded its page limit.")


def collect_asa_ssh(
    *,
    target: str,
    known_hosts: Path,
    secret_provider: FirewallSecretProvider,
    org_id: UUID,
    asset_id: UUID,
    client_factory: Callable[[], Any],
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    """Run only the fixed Phase-4 ASA show-command allowlist."""
    if not known_hosts.is_file():
        raise DeviceEngineError("KNOWN_HOSTS_REQUIRED", "ASA SSH requires a known_hosts file.")
    try:
        import paramiko
    except ImportError as exc:
        raise DeviceEngineError(
            "OPTIONAL_DEPENDENCY_MISSING", "ASA SSH collection requires optional Paramiko."
        ) from exc
    client = client_factory()
    try:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        credentials = secret_provider.get_ssh_credentials(target)
        client.connect(
            target,
            username=credentials.get("username"),
            password=credentials.get("password"),
            key_filename=credentials.get("key_filename"),
            timeout=timeout_seconds,
            allow_agent=False,
            look_for_keys=False,
        )
        responses = {}
        for command in ASA_SHOW_COMMANDS:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout_seconds)
            responses[command] = stdout.read(1024 * 1024 + 1).decode("utf-8", errors="replace")
            if len(responses[command].encode()) > 1024 * 1024:
                raise DeviceEngineError(
                    "RESPONSE_TOO_LARGE", "ASA command response exceeded limit."
                )
        return {"org_id": str(org_id), "asset_id": str(asset_id), "commands": responses}
    except DeviceEngineError:
        raise
    except Exception as exc:
        raise DeviceEngineError(
            "SSH_TRANSPORT_FAILED",
            "ASA SSH collection failed.",
            details={"target": target, "details_redacted": True},
        ) from exc
    finally:
        client.close()


def _load_manifest(path: Path) -> FirewallManifest:
    try:
        manifest = FirewallManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureInputError("FIREWALL_MANIFEST_NOT_FOUND", "Manifest does not exist.") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise FixtureInputError("MALFORMED_FIREWALL_MANIFEST", "Manifest is invalid.") from exc
    if not manifest.synthetic:
        raise FixtureInputError("NON_SYNTHETIC_FIXTURE_REJECTED", "Fixture must be synthetic.")
    if manifest.platform not in PLATFORMS:
        raise FixtureInputError("UNSUPPORTED_FIREWALL_PLATFORM", "Unknown firewall platform.")
    return manifest


def _contained(manifest: Path, relative: str) -> Path:
    if Path(relative).is_absolute():
        raise FixtureInputError("INVALID_FIXTURE_PATH", "Capture path must be relative.")
    base = manifest.resolve().parent
    candidate = (base / relative).resolve()
    if base != candidate and base not in candidate.parents:
        raise FixtureInputError("INVALID_FIXTURE_PATH", "Capture path escapes fixture directory.")
    return candidate


def _source_errors(sources: list[dict[str, Any]], asset_id: UUID) -> list[CanonicalError]:
    errors = []
    for source in sources:
        state = source.get("state")
        if state in {"denied", "error", "timeout", "rate_limited", "unavailable"}:
            errors.append(
                CanonicalError(
                    code=f"FIREWALL_SOURCE_{str(state).upper()}",
                    message=f"Source {source.get('identity', 'unknown')} was unavailable.",
                    request_id=asset_id,
                    details={"source_identity": source.get("identity")},
                    retryable=state in {"timeout", "rate_limited"},
                )
            )
    return errors
