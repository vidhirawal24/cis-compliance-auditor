"""Typed adapter boundary and explicit platform registry."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from .models import FactsEnvelope


@dataclass(frozen=True, slots=True)
class FixtureInput:
    path: Path
    platform: str
    org_id: UUID
    asset_id: UUID
    collected_at: datetime
    model: str
    version: str


@dataclass(frozen=True, slots=True)
class CollectedArtifact:
    source: FixtureInput
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ParsedConfiguration:
    platform: str
    facts: Mapping[str, Any]
    warnings: tuple[str, ...]


@runtime_checkable
class Adapter(Protocol):
    """Synchronous provisional SDK boundary; live transport is not implemented."""

    platform: str

    def probe_version(self, source: FixtureInput) -> str | None: ...

    def collect(self, source: FixtureInput, *, read_only: bool = True) -> CollectedArtifact: ...

    def parse(self, raw: CollectedArtifact) -> ParsedConfiguration: ...

    def normalize(self, raw: CollectedArtifact, parsed: ParsedConfiguration) -> FactsEnvelope: ...

    def supported_controls(self) -> Sequence[str]: ...

    def remediation_capabilities(self) -> Sequence[str]: ...


@runtime_checkable
class ExecutableAdapter(Adapter, Protocol):
    """Optional future extension; Phase 1 implementations reject all execution."""

    def execute_approved_change(self, change: Mapping[str, Any]) -> None: ...


class UnsupportedPlatformError(LookupError):
    def __init__(self, platform: str) -> None:
        self.platform = platform
        super().__init__(f"No implemented adapter is registered for platform: {platform}")


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, Adapter] = {}

    def register(self, adapter: Adapter) -> None:
        if adapter.platform in self._adapters:
            raise ValueError(f"Adapter already registered for platform: {adapter.platform}")
        self._adapters[adapter.platform] = adapter

    def get(self, platform: str) -> Adapter:
        try:
            return self._adapters[platform]
        except KeyError as exc:
            raise UnsupportedPlatformError(platform) from exc

    def registered_platforms(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
