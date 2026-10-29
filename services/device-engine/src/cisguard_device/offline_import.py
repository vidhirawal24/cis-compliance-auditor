"""Safe offline import of sanitized device configuration files.

Feature E10: Offline import path for actual sanitized files supported by
existing parsers. Provides explicit source_type identification, provenance
marking, and deterministic FactsEnvelope production.

SECURITY NOTES:
- Raw configuration may contain secrets. Never print raw content in normal
  CLI output or logs.
- Content is read-only; the source file is never modified.
- No content is executed. No eval(), no shell invocation.
- Size limits are applied before parsing.
- Archive support is NOT implemented in this phase.

EVIDENCE PROVENANCE:
- Imported evidence is marked as offline, distinguishing synthetic fixtures,
  user-supplied captures, and live collection (none supported for import).
- capture_timestamp is user-supplied and preserved separately from import time.
- Import time is never used as proof of collection time.
- If capture_timestamp is unknown, source-time uncertainty is explicit. The
  compatible envelope timestamp is labelled import time, never a sentinel capture time.

ENCRYPTED STORAGE:
- This module handles plaintext file reading only.
- Mandar's platform is responsible for encrypted private storage and access
  control. This module must not be used on unencrypted production configs
  without appropriate local handling controls.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from pydantic import Field, field_validator

from .errors import DeviceEngineError, FixtureInputError
from .models import CanonicalError, EvidenceReference, FactsEnvelope, StrictModel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_BYTES_DEFAULT = 4 * 1024 * 1024  # 4 MiB
_IMPORT_REQUEST_NAMESPACE = UUID("a3f2c1b4-8e5d-4f6a-9b0c-d1e2f3a4b5c6")

# Supported source types
SUPPORTED_SOURCE_TYPES: tuple[str, ...] = (
    "cisco_ios_running_config",
    "sophos_firewall_api_xml",
    "palo_alto_panos_xml",
    "windows_json_capture",
    "linux_json_capture",
    "firewall_capture_json",
)

# Source type → allowed platforms
SOURCE_TYPE_PLATFORMS: dict[str, frozenset[str]] = {
    "cisco_ios_running_config": frozenset({"cisco_router", "cisco_switch"}),
    "sophos_firewall_api_xml": frozenset({"sophos_firewall"}),
    "palo_alto_panos_xml": frozenset({"palo_alto_panos"}),
    "windows_json_capture": frozenset(
        {"windows_11_enterprise", "windows_11_standalone", "windows_server_2019"}
    ),
    "linux_json_capture": frozenset({"ubuntu_20_04_lts", "ubuntu_22_04_lts", "rhel_8", "rhel_9"}),
    "firewall_capture_json": frozenset(
        {"fortios", "fortinet_fortios", "cisco_asa", "cisco_ftd_fmc", "checkpoint_management"}
    ),
}

# Source type → vendor mapping
_SOURCE_TYPE_VENDOR: dict[str, str] = {
    "cisco_ios_running_config": "Cisco",
    "sophos_firewall_api_xml": "Sophos",
    "palo_alto_panos_xml": "Palo Alto Networks",
    "windows_json_capture": "Microsoft",
    "linux_json_capture": "Linux",
    "firewall_capture_json": "Multi-vendor",
}

# Source type description for collection_method field
_SOURCE_TYPE_SCHEMA: dict[str, str] = {
    "cisco_ios_running_config": "Cisco IOS/IOS-XE running configuration text",
    "sophos_firewall_api_xml": "Sophos Firewall API XML 1905.2",
    "palo_alto_panos_xml": "PAN-OS 10.2/11.0 XML response",
    "windows_json_capture": "Phase-2 Windows JSON capture format",
    "linux_json_capture": "Phase-3 Linux JSON capture format",
    "firewall_capture_json": "Phase-4 internal firewall capture schema (NOT a raw vendor export)",
}


# ---------------------------------------------------------------------------
# Evidence provenance enum
# ---------------------------------------------------------------------------


class EvidenceProvenance(StrEnum):
    """Marks the origin of imported evidence."""

    SYNTHETIC_FIXTURE = "synthetic_fixture"
    """Programmatically generated test fixture with no device origin."""

    USER_SUPPLIED_CAPTURE = "user_supplied_capture"
    """Sanitized file supplied by the user from an offline device capture."""

    LIVE_COLLECTION = "live_collection"
    """Evidence collected live from a device (not supported for import)."""


# ---------------------------------------------------------------------------
# Import metadata model
# ---------------------------------------------------------------------------


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


class OfflineImportMetadata(StrictModel):
    """Typed metadata required to safely import an offline device file.

    Does NOT accept executable expressions, shell commands, or eval()-able
    content in any field.
    """

    source_type: str = Field(
        description=f"Source type identifier. Must be one of: {SUPPORTED_SOURCE_TYPES}"
    )
    platform: str = Field(
        description="Explicit platform identifier. Must be compatible with source_type."
    )
    org_id: UUID
    asset_id: UUID
    capture_timestamp: datetime | None = Field(
        default=None,
        description=(
            "User-supplied UTC timestamp of when the capture was taken. "
            "None means unknown; import time is NEVER substituted as collection time."
        ),
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.USER_SUPPLIED_CAPTURE,
        description="Evidence provenance marker.",
    )
    completeness: str = Field(
        description="Completeness of the captured data: 'complete', 'partial', or 'unknown'.",
    )

    # Optional: for Cisco IOS, a separate operational output file path.
    # This is handled by import_offline_file() as a separate parameter.

    @field_validator("capture_timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime | None) -> datetime | None:
        if v is not None:
            return _require_utc(v)
        return v

    @field_validator("source_type")
    @classmethod
    def _validate_source_type(cls, v: str) -> str:
        if v not in SUPPORTED_SOURCE_TYPES:
            raise ValueError(
                f"Unsupported source_type '{v}'. Supported types: {SUPPORTED_SOURCE_TYPES}"
            )
        return v

    @field_validator("provenance")
    @classmethod
    def _validate_provenance(cls, value: EvidenceProvenance) -> EvidenceProvenance:
        if value == EvidenceProvenance.LIVE_COLLECTION:
            raise ValueError("Offline import cannot be marked as live_collection")
        return value

    @field_validator("completeness")
    @classmethod
    def _validate_completeness(cls, v: str) -> str:
        if v not in {"complete", "partial", "unknown"}:
            raise ValueError("completeness must be 'complete', 'partial', or 'unknown'.")
        return v


# ---------------------------------------------------------------------------
# Public import function
# ---------------------------------------------------------------------------


def import_offline_file(
    path: Path,
    metadata: OfflineImportMetadata,
    *,
    max_bytes: int = _MAX_BYTES_DEFAULT,
    operational_path: Path | None = None,
    imported_at: datetime | None = None,
) -> FactsEnvelope:
    """Safely import a sanitized offline device configuration file.

    Args:
        path:             Path to the primary configuration/capture file.
                          The file is read-only; it is never modified or executed.
        metadata:         Typed import metadata. Platform and source_type must match.
        max_bytes:        Maximum file size in bytes (default 4 MiB).
        operational_path: Optional secondary file for Cisco IOS operational output
                          (e.g. 'show version', 'show ntp status'). Only used for
                          cisco_ios_running_config source_type.

    Returns:
        FactsEnvelope with collection_method indicating offline import provenance.

    Raises:
        FixtureInputError:   Invalid format, size, platform mismatch, or unsafe content.
        DeviceEngineError:   File read failure or unsupported operation.

    Notes:
        - Raw configuration is never printed in normal output or logs.
        - Capture timestamp is preserved as-is; import time is NOT used as
          proof of collection time.
        - If capture_timestamp is None, collected_at represents import time and
          facts explicitly record that source capture time is unknown.
    """
    if max_bytes < 1:
        raise FixtureInputError("INVALID_SIZE_LIMIT", "max_bytes must be a positive integer.")

    # Validate platform/source_type compatibility
    allowed_platforms = SOURCE_TYPE_PLATFORMS.get(metadata.source_type, frozenset())
    if metadata.platform not in allowed_platforms:
        raise FixtureInputError(
            "PLATFORM_SOURCE_TYPE_MISMATCH",
            f"Platform '{metadata.platform}' is not compatible with source_type "
            f"'{metadata.source_type}'. "
            f"Allowed platforms: {sorted(allowed_platforms)}",
        )

    # Read primary file
    content = _read_file_safely(path, max_bytes)

    # Read optional operational file (Cisco IOS only)
    operational_content: bytes | None = None
    if operational_path is not None:
        if metadata.source_type != "cisco_ios_running_config":
            raise FixtureInputError(
                "OPERATIONAL_FILE_NOT_APPLICABLE",
                "operational_path is only supported for cisco_ios_running_config source_type.",
            )
        operational_content = _read_file_safely(operational_path, max_bytes)
        if len(content) + len(operational_content) > max_bytes:
            raise FixtureInputError(
                "FILES_TOO_LARGE", "Combined primary and operational files exceed the size limit."
            )

    # Build evidence references
    errors: list[CanonicalError] = []
    evidence_refs: list[EvidenceReference] = []

    # FactsEnvelope requires collected_at. When source time is unknown, use a
    # separately labelled import time rather than a plausible-looking sentinel.
    import_time = imported_at or datetime.now(UTC)
    _require_utc(import_time)
    collected_at: datetime
    if metadata.capture_timestamp is not None:
        collected_at = metadata.capture_timestamp
    else:
        collected_at = import_time
        errors.append(
            CanonicalError(
                code="CAPTURE_TIMESTAMP_UNKNOWN",
                message=(
                    "Capture timestamp was not supplied; envelope collected_at is import time, "
                    "not evidence of source collection time."
                ),
                request_id=uuid5(_IMPORT_REQUEST_NAMESPACE, f"{metadata.asset_id}:unknown_ts"),
                details={
                    "source_capture_timestamp": None,
                    "imported_at": import_time.isoformat(),
                    "guidance": "Supply capture_timestamp for accurate provenance.",
                },
                retryable=False,
            )
        )

    # Build evidence reference for primary file
    content_hash = hashlib.sha256(content).hexdigest()
    evidence_refs.append(
        EvidenceReference(
            sha256=content_hash,
            source_identity=f"offline_import:{metadata.source_type}:{path.name}",
            artifact_location=str(path.resolve()),
            timestamp=collected_at,
        )
    )

    if operational_content is not None and operational_path is not None:
        op_hash = hashlib.sha256(operational_content).hexdigest()
        evidence_refs.append(
            EvidenceReference(
                sha256=op_hash,
                source_identity=f"offline_import:operational_output:{operational_path.name}",
                artifact_location=str(operational_path.resolve()),
                timestamp=collected_at,
            )
        )

    # Parse content using the appropriate existing parser
    parsed_facts, parser_errors = _dispatch_parse(
        metadata.source_type,
        metadata.platform,
        content,
        operational_content,
        org_id=metadata.org_id,
        asset_id=metadata.asset_id,
        artifact_location=f"offline_import:{metadata.source_type}:{path.name}",
    )
    errors.extend(parser_errors)
    facts = _redact_sensitive(parsed_facts)

    # Add import metadata to facts (no raw content)
    facts["import"] = {
        "source_type": metadata.source_type,
        "source_type_description": _SOURCE_TYPE_SCHEMA[metadata.source_type],
        "platform": metadata.platform,
        "provenance": str(metadata.provenance),
        "completeness": metadata.completeness,
        "capture_timestamp_known": metadata.capture_timestamp is not None,
        "source_capture_timestamp": (
            metadata.capture_timestamp.isoformat() if metadata.capture_timestamp else None
        ),
        "imported_at": import_time.isoformat(),
        "import_schema_note": (
            "This is an offline import. It does not prove current running or deployed state. "
            "Capture time is distinct from import time."
        ),
    }
    if isinstance(facts.get("snmp"), dict):
        facts["snmp"].setdefault("configuration_complete", metadata.completeness == "complete")

    # Determine collection_method
    collection_method = (
        "offline_synthetic_fixture"
        if metadata.provenance == EvidenceProvenance.SYNTHETIC_FIXTURE
        else "offline_user_supplied_capture"
    )

    return FactsEnvelope(
        org_id=metadata.org_id,
        asset_id=metadata.asset_id,
        platform=metadata.platform,
        vendor=_SOURCE_TYPE_VENDOR.get(metadata.source_type, "unknown"),
        model=f"offline-import:{metadata.source_type}",
        os_or_firmware_version="unknown",
        collector_version="0.1.0",
        collection_method=collection_method,
        collected_at=collected_at,
        facts=facts,
        evidence_refs=evidence_refs,
        supported_capabilities=[
            "offline_import",
            "deterministic_parse",
            f"source_type:{metadata.source_type}",
        ],
        unsupported_capabilities=[
            "live_collection",
            "simulation",
            "remediation",
            "current_state_proof",
        ],
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------


def _dispatch_parse(
    source_type: str,
    platform: str,
    content: bytes,
    operational_content: bytes | None,
    *,
    org_id: UUID,
    asset_id: UUID,
    artifact_location: str,
) -> tuple[dict[str, Any], list[CanonicalError]]:
    """Dispatch to the appropriate existing parser based on source_type.

    This function NEVER executes content. All parsers are pure-parse functions.
    """
    if source_type == "cisco_ios_running_config":
        from .remaining_devices import parse_cisco_ios_sources

        return (
            parse_cisco_ios_sources(
                content,
                operational_content,
                platform=platform,
                designated_unused_ports=None,
            ),
            [],
        )

    if source_type == "sophos_firewall_api_xml":
        from .remaining_devices import parse_sophos_xml

        return parse_sophos_xml(content), []

    if source_type == "palo_alto_panos_xml":
        from .remaining_devices import parse_panos_xml

        return parse_panos_xml(content), []

    if source_type == "windows_json_capture":
        from .windows import (
            WindowsCollectedCapture,
            classify_windows_capture,
            normalize_windows_capture,
            parse_windows_capture,
        )

        capture = parse_windows_capture(content)
        classification = classify_windows_capture(capture)
        if classification.platform != platform:
            raise FixtureInputError(
                "PLATFORM_SOURCE_TYPE_MISMATCH",
                "Windows capture identity does not match the explicit platform metadata.",
            )
        normalized = normalize_windows_capture(
            WindowsCollectedCapture(
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                artifact_location=artifact_location,
                org_id=org_id,
                asset_id=asset_id,
                model="offline-import",
            ),
            capture,
            classification,
            collection_method="offline_user_supplied_capture",
        )
        return normalized.facts, normalized.errors

    if source_type == "linux_json_capture":
        from .linux import (
            LinuxCollectedCapture,
            classify_linux_capture,
            normalize_linux_capture,
            parse_linux_capture,
        )

        capture = parse_linux_capture(content)
        classification = classify_linux_capture(capture)
        if classification.platform != platform:
            raise FixtureInputError(
                "PLATFORM_SOURCE_TYPE_MISMATCH",
                "Linux capture identity does not match the explicit platform metadata.",
            )
        normalized = normalize_linux_capture(
            LinuxCollectedCapture(
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                artifact_location=artifact_location,
                org_id=org_id,
                asset_id=asset_id,
                model="offline-import",
            ),
            capture,
            classification,
            "offline_user_supplied_capture",
        )
        return normalized.facts, normalized.errors

    if source_type == "firewall_capture_json":
        from .firewalls import parse_firewall_capture

        capture = parse_firewall_capture(content)
        expected_capture_platform = {
            "fortinet_fortios": "fortios",
            "fortios": "fortios",
            "cisco_asa": "cisco_asa",
            "cisco_ftd_fmc": "cisco_ftd_fmc",
            "checkpoint_management": "checkpoint_management",
        }[platform]
        if capture.platform != expected_capture_platform:
            raise FixtureInputError(
                "PLATFORM_SOURCE_TYPE_MISMATCH",
                "Internal firewall capture platform does not match the explicit platform metadata.",
            )
        return {
            "firewall_capture": capture.model_dump(mode="json"),
            "parser": {
                "source_type": source_type,
                "schema_note": (
                    "Phase-4 internal capture schema. "
                    "This is NOT a raw vendor export. "
                    "It was produced by cisguard_device firewall collection."
                ),
            },
        }, []

    # Should never reach here due to metadata validation
    raise DeviceEngineError(
        "UNSUPPORTED_SOURCE_TYPE",
        f"No parser available for source_type '{source_type}'.",
    )


# ---------------------------------------------------------------------------
# File reading helper
# ---------------------------------------------------------------------------


def _read_file_safely(path: Path, max_bytes: int) -> bytes:
    """Read a file with size limit. Never executes content."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FixtureInputError(
            "FILE_READ_ERROR",
            f"Cannot access file '{path.name}': {exc.strerror}",
        ) from exc

    if size > max_bytes:
        raise FixtureInputError(
            "FILE_TOO_LARGE",
            f"File '{path.name}' is {size} bytes, exceeding limit of {max_bytes} bytes.",
            details={"file_size": size, "limit": max_bytes},
        )

    try:
        content = path.read_bytes()
    except OSError as exc:
        raise FixtureInputError(
            "FILE_READ_ERROR",
            f"Failed to read '{path.name}': {exc.strerror}",
        ) from exc

    if len(content) > max_bytes:
        raise FixtureInputError(
            "FILE_TOO_LARGE",
            f"File content is {len(content)} bytes, exceeding limit of {max_bytes} bytes.",
        )

    return content


def _redact_sensitive(value: Any) -> Any:
    """Remove secret-like normalized values without retaining raw capture material."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            secret_key = (
                any(
                    marker in normalized_key
                    for marker in (
                        "password",
                        "passwd",
                        "secret",
                        "token",
                        "credential",
                        "private_key",
                    )
                )
                or (
                    "community" in normalized_key
                    and not normalized_key.endswith(("_count", "_present", "_known"))
                )
                or normalized_key in {"raw_config", "running_config", "configuration_text"}
            )
            if secret_key:
                redacted[key] = (
                    ["<redacted>" for _ in item]
                    if isinstance(item, list)
                    else "<redacted>"
                    if item is not None
                    else None
                )
            else:
                redacted[key] = _redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    return value
