"""PROVISIONAL v1 compatibility models pending packages/contracts/v1 publication."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssessmentStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"
    NOT_ASSESSED = "NOT_ASSESSED"


class SimulationVerdict(StrEnum):
    SAFE_IN_MODEL = "SAFE_IN_MODEL"
    VIOLATES_CONTRACT = "VIOLATES_CONTRACT"
    UNSUPPORTED = "UNSUPPORTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use UTC offset +00:00")
    return value


class CanonicalError(StrictModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    request_id: UUID
    details: dict[str, Any] | None = None
    retryable: bool


class EvidenceReference(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: str = Field(
        min_length=1,
        description="Identity of the source command or API operation; never secret material.",
    )
    artifact_location: str = Field(
        min_length=1,
        description="Fixture path or production storage reference; encryption is not implied.",
    )
    timestamp: datetime

    _timestamp_is_utc = field_validator("timestamp")(_require_utc)


class FactsEnvelope(StrictModel):
    """PROVISIONAL normalized collector output; facts may explicitly contain null."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    org_id: UUID
    asset_id: UUID
    platform: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    model: str = Field(min_length=1)
    os_or_firmware_version: str = Field(min_length=1)
    collector_version: str = Field(min_length=1)
    collection_method: str = Field(min_length=1)
    collected_at: datetime
    facts: dict[str, Any]
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)
    supported_capabilities: list[str] = Field(default_factory=list)
    unsupported_capabilities: list[str] = Field(default_factory=list)
    errors: list[CanonicalError] = Field(default_factory=list)

    _collected_at_is_utc = field_validator("collected_at")(_require_utc)


class OperationStatus(StrEnum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UNSUPPORTED = "UNSUPPORTED"
    REJECTED = "REJECTED"


class UnsupportedOperationResult(StrictModel):
    """Typed negative boundary for intentionally unavailable Phase-1 operations."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    operation: str = Field(min_length=1)
    status: OperationStatus
    error: CanonicalError
