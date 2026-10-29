"""Stable importable functions for deterministic offline fixture replay."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .adapters import FixtureInput
from .cisco_ios_fixture import PLATFORM, CiscoIosFixtureAdapter
from .errors import FixtureInputError
from .models import FactsEnvelope


class FixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    synthetic: bool
    label: str = Field(min_length=1)
    platform: str
    illustrative_version: str
    model: str
    scope: str
    org_id: UUID
    asset_id: UUID
    collected_at: datetime
    source_file: str
    expected_file: str
    expected_supported_capabilities: list[str]
    expected_unsupported_capabilities: list[str]


def load_manifest(path: Path) -> FixtureManifest:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureInputError(
            "FIXTURE_MANIFEST_NOT_FOUND",
            "Fixture manifest does not exist.",
            details={"path": str(path)},
        ) from exc
    except UnicodeDecodeError as exc:
        raise FixtureInputError(
            "INVALID_ENCODING", "Fixture manifest must be valid UTF-8."
        ) from exc
    except json.JSONDecodeError as exc:
        raise FixtureInputError(
            "MALFORMED_MANIFEST",
            "Fixture manifest is not valid JSON.",
            details={"line": exc.lineno, "column": exc.colno},
        ) from exc
    manifest = FixtureManifest.model_validate(payload)
    if not manifest.synthetic:
        raise FixtureInputError(
            "NON_SYNTHETIC_FIXTURE_REJECTED",
            "Phase 1 accepts only manifests explicitly labelled synthetic.",
        )
    return manifest


def probe_fixture(manifest_path: Path, *, platform: str | None = None) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    requested_platform = platform or manifest.platform
    source = _source(manifest_path, manifest, requested_platform)
    adapter = _adapter(requested_platform)
    version = adapter.probe_version(source)
    return {
        "schema_version": "1.0.0",
        "collection_method": "offline_synthetic_fixture",
        "synthetic": True,
        "label": manifest.label,
        "platform": requested_platform,
        "illustrative_version": version,
        "scope": manifest.scope,
        "implementation_status": "FIXTURE_ONLY_PARTIAL",
    }


def collect_fixture(
    manifest_path: Path,
    *,
    platform: str | None = None,
    max_bytes: int | None = None,
) -> FactsEnvelope:
    manifest = load_manifest(manifest_path)
    requested_platform = platform or manifest.platform
    source = _source(manifest_path, manifest, requested_platform)
    adapter = _adapter(requested_platform, max_bytes=max_bytes)
    raw = adapter.collect(source, read_only=True)
    parsed = adapter.parse(raw)
    envelope = adapter.normalize(raw, parsed)
    if envelope.supported_capabilities != manifest.expected_supported_capabilities:
        raise FixtureInputError(
            "FIXTURE_EXPECTATION_MISMATCH",
            "Manifest supported capabilities differ from adapter output.",
        )
    if envelope.unsupported_capabilities != manifest.expected_unsupported_capabilities:
        raise FixtureInputError(
            "FIXTURE_EXPECTATION_MISMATCH",
            "Manifest unsupported capabilities differ from adapter output.",
        )
    return envelope


def load_expected_envelope(manifest_path: Path) -> FactsEnvelope:
    manifest = load_manifest(manifest_path)
    expected_path = _within_manifest_dir(manifest_path, manifest.expected_file)
    try:
        return FactsEnvelope.model_validate_json(expected_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureInputError(
            "EXPECTED_FIXTURE_NOT_FOUND", "Expected normalized JSON does not exist."
        ) from exc


def _source(manifest_path: Path, manifest: FixtureManifest, platform: str) -> FixtureInput:
    source_path = _within_manifest_dir(manifest_path, manifest.source_file)
    return FixtureInput(
        path=source_path,
        platform=platform,
        org_id=manifest.org_id,
        asset_id=manifest.asset_id,
        collected_at=manifest.collected_at,
        model=manifest.model,
        version=manifest.illustrative_version,
    )


def _adapter(platform: str, *, max_bytes: int | None = None) -> CiscoIosFixtureAdapter:
    if platform != PLATFORM:
        raise FixtureInputError(
            "UNSUPPORTED_PLATFORM",
            "No Phase-1 fixture adapter exists for the requested platform.",
            details={"platform": platform},
        )
    if max_bytes is None:
        return CiscoIosFixtureAdapter()
    return CiscoIosFixtureAdapter(max_bytes=max_bytes)


def _within_manifest_dir(manifest_path: Path, relative_name: str) -> Path:
    if Path(relative_name).is_absolute():
        raise FixtureInputError("INVALID_FIXTURE_PATH", "Fixture paths must be relative.")
    base = manifest_path.resolve().parent
    candidate = (base / relative_name).resolve()
    if base != candidate and base not in candidate.parents:
        raise FixtureInputError(
            "INVALID_FIXTURE_PATH", "Fixture path escapes its manifest directory."
        )
    return candidate
