"""Bounded Cisco IOS synthetic-fixture parser; not a live Cisco adapter."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .adapters import Adapter, CollectedArtifact, FixtureInput, ParsedConfiguration
from .errors import FixtureInputError, LiveWriteBlockedError
from .models import EvidenceReference, FactsEnvelope

DEFAULT_MAX_FIXTURE_BYTES = 1_048_576
PLATFORM = "cisco_ios_fixture"
SUPPORTED_CAPABILITIES = (
    "fixture_replay",
    "cisco_ios_config_parse",
    "management_vty_transport_config",
    "ssh_version_config",
    "session_timeout_config",
    "remote_syslog_config",
    "ntp_server_config",
)
UNSUPPORTED_CAPABILITIES = (
    "live_collection",
    "operational_reachability",
    "effective_exposure",
    "ssh_key_authentication_state",
    "ntp_synchronization_state",
    "compliance_evaluation",
    "remediation",
)
_VTY_START = re.compile(r"^line vty\s+(\d+)\s+(\d+)\s*$", re.IGNORECASE)


class CiscoIosFixtureAdapter(Adapter):
    platform = PLATFORM

    def __init__(self, *, max_bytes: int = DEFAULT_MAX_FIXTURE_BYTES) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes

    def probe_version(self, source: FixtureInput) -> str | None:
        self._validate_platform(source)
        return source.version or None

    def collect(self, source: FixtureInput, *, read_only: bool = True) -> CollectedArtifact:
        self._validate_platform(source)
        if not read_only:
            raise LiveWriteBlockedError(
                "LIVE_WRITE_BLOCKED",
                "Fixture collection is read-only and Phase 1 has no write path.",
            )
        try:
            size = source.path.stat().st_size
        except FileNotFoundError as exc:
            raise FixtureInputError(
                "FIXTURE_NOT_FOUND",
                "Fixture file does not exist.",
                details={"path": str(source.path)},
            ) from exc
        if size > self.max_bytes:
            raise FixtureInputError(
                "FIXTURE_TOO_LARGE",
                "Fixture exceeds the configured input limit.",
                details={"size": size, "max_bytes": self.max_bytes},
            )
        try:
            content = source.path.read_bytes()
        except OSError as exc:
            raise FixtureInputError(
                "FIXTURE_READ_ERROR",
                "Fixture could not be read.",
                details={"path": str(source.path)},
            ) from exc
        if not content.strip():
            raise FixtureInputError("EMPTY_FIXTURE", "Fixture contains no configuration content.")
        return CollectedArtifact(
            source=source,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )

    def parse(self, raw: CollectedArtifact) -> ParsedConfiguration:
        self._validate_platform(raw.source)
        try:
            text = raw.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FixtureInputError(
                "INVALID_ENCODING", "Fixture must be valid UTF-8.", details={"offset": exc.start}
            ) from exc
        lines = text.splitlines()
        warnings: list[str] = []
        vty_blocks: list[dict[str, Any]] = []
        remote_syslog: list[dict[str, Any]] = []
        ntp_servers: list[dict[str, Any]] = []
        ssh_version: int | None = None
        ssh_version_source: dict[str, Any] | None = None

        index = 0
        while index < len(lines):
            stripped = lines[index].strip()
            line_number = index + 1
            match = _VTY_START.fullmatch(stripped)
            if match:
                block, index = self._parse_vty(lines, index, match)
                vty_blocks.append(block)
                continue
            if stripped.lower().startswith("line vty"):
                warnings.append(f"unsupported VTY declaration at line {line_number}")
            ssh_match = re.fullmatch(r"ip ssh version\s+(\d+)", stripped, re.IGNORECASE)
            if ssh_match:
                value = int(ssh_match.group(1))
                if ssh_version is not None and ssh_version != value:
                    warnings.append(f"contradictory SSH versions include line {line_number}")
                    ssh_version = None
                    ssh_version_source = None
                elif not any("contradictory SSH versions" in item for item in warnings):
                    ssh_version = value
                    ssh_version_source = {"line": line_number, "text_identity": "ip ssh version"}
            log_match = re.fullmatch(r"logging host\s+(\S+)", stripped, re.IGNORECASE)
            if log_match:
                remote_syslog.append(
                    {"destination": log_match.group(1), "source": {"line": line_number}}
                )
            ntp_match = re.fullmatch(r"ntp server\s+(\S+)(?:\s+.*)?", stripped, re.IGNORECASE)
            if ntp_match:
                ntp_servers.append({"server": ntp_match.group(1), "source": {"line": line_number}})
            index += 1

        if not vty_blocks:
            warnings.append("no supported VTY blocks found")
        facts: dict[str, Any] = {
            "management": {
                "vty_blocks": vty_blocks,
                "ssh": {
                    "configured_version": ssh_version,
                    "key_authentication_configured": None,
                    "source": ssh_version_source,
                },
            },
            "logging": {
                "remote_destinations": remote_syslog,
                "operational_reachability": None,
            },
            "ntp": {"configured_servers": ntp_servers, "synchronized": None},
            "parser": {"warnings": warnings},
        }
        return ParsedConfiguration(platform=self.platform, facts=facts, warnings=tuple(warnings))

    def normalize(self, raw: CollectedArtifact, parsed: ParsedConfiguration) -> FactsEnvelope:
        if parsed.platform != self.platform:
            raise FixtureInputError(
                "PLATFORM_MISMATCH",
                "Parsed configuration platform does not match adapter.",
                details={"expected": self.platform, "actual": parsed.platform},
            )
        return FactsEnvelope(
            org_id=raw.source.org_id,
            asset_id=raw.source.asset_id,
            platform=self.platform,
            vendor="Cisco",
            model=raw.source.model,
            os_or_firmware_version=raw.source.version,
            collector_version="0.2.0",
            collection_method="offline_synthetic_fixture",
            collected_at=raw.source.collected_at,
            facts=dict(parsed.facts),
            evidence_refs=[
                EvidenceReference(
                    sha256=raw.sha256,
                    source_identity="offline_fixture:cisco_ios_running_config",
                    artifact_location=(
                        f"fixture://cisco_ios/{raw.source.path.parent.name}/{raw.source.path.name}"
                    ),
                    timestamp=raw.source.collected_at,
                )
            ],
            supported_capabilities=list(SUPPORTED_CAPABILITIES),
            unsupported_capabilities=list(UNSUPPORTED_CAPABILITIES),
            errors=[],
        )

    def supported_controls(self) -> Sequence[str]:
        return ()

    def remediation_capabilities(self) -> Sequence[str]:
        return ()

    def execute_approved_change(self, change: Mapping[str, Any]) -> None:
        raise LiveWriteBlockedError(
            "LIVE_WRITE_BLOCKED",
            "Execution is unavailable in Phase 1, including approved changes.",
        )

    @staticmethod
    def _parse_vty(
        lines: list[str], start: int, match: re.Match[str]
    ) -> tuple[dict[str, Any], int]:
        transports: list[str] | None = None
        timeout_seconds: int | None = None
        warnings: list[str] = []
        index = start + 1
        last_line = start + 1
        while index < len(lines):
            raw_line = lines[index]
            stripped = raw_line.strip()
            if stripped and not raw_line[:1].isspace():
                break
            last_line = index + 1
            recognized = not stripped
            transport_match = re.fullmatch(r"transport input(?:\s+(.*))?", stripped, re.IGNORECASE)
            if transport_match:
                recognized = True
                tokens = (transport_match.group(1) or "").lower().split()
                transports = tokens or None
                if any(token not in {"ssh", "telnet", "none", "all"} for token in tokens):
                    warnings.append(f"unsupported transport token at line {index + 1}")
            timeout_match = re.fullmatch(r"exec-timeout\s+(\d+)\s+(\d+)", stripped, re.IGNORECASE)
            if timeout_match:
                recognized = True
                timeout_seconds = int(timeout_match.group(1)) * 60 + int(timeout_match.group(2))
            if not recognized:
                warnings.append(f"unsupported VTY syntax at line {index + 1}")
            index += 1
        telnet_allowed: bool | None
        if transports is None:
            telnet_allowed = None
        else:
            telnet_allowed = "telnet" in transports or "all" in transports
        return (
            {
                "range": {"first": int(match.group(1)), "last": int(match.group(2))},
                "transport_input": transports,
                "telnet_allowed": telnet_allowed,
                "exec_timeout_seconds": timeout_seconds,
                "source": {"start_line": start + 1, "end_line": last_line},
                "warnings": warnings,
            },
            index,
        )

    @staticmethod
    def _validate_platform(source: FixtureInput) -> None:
        if source.platform != PLATFORM:
            raise FixtureInputError(
                "PLATFORM_MISMATCH",
                "Fixture platform does not match the Cisco IOS fixture adapter.",
                details={"expected": PLATFORM, "actual": source.platform},
            )


def default_fixture_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures" / "cisco_ios"
