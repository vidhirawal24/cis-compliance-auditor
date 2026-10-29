"""Offline/synthetic Phase-10 verification and drift primitives; no transport is built in."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .execution import GateResult
from .models import FactsEnvelope


class VerificationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_ASSESSED = "NOT_ASSESSED"


class FactDifference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    classification: str
    before: Any = None
    after: Any = None
    runtime_observation: bool = False
    limitation: str | None = None


class DriftEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    classification: str
    expected: bool
    baseline_hashes: list[str]
    current_hashes: list[str]
    observed_at: datetime
    provenance: str


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    org_id: str
    asset_id: str
    change_id: str
    candidate_hash: str
    template_id: str
    template_version: str
    policy_version: str
    baseline: FactsEnvelope
    required_check_ids: list[str] = Field(min_length=1)
    service_contract_ids: list[str] = Field(min_length=1)
    max_age_seconds: int = Field(default=900, gt=0)


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_control_status: VerificationStatus
    service_contract_status: VerificationStatus
    status: VerificationStatus
    control_outcomes: dict[str, VerificationStatus]
    service_outcomes: dict[str, VerificationStatus]
    fresh_provenance: str
    limitations: list[str]


class TrustedOutcomes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    org_id: str
    asset_id: str
    change_id: str
    evidence_hashes: list[str]
    control_outcomes: dict[str, VerificationStatus]
    service_outcomes: dict[str, VerificationStatus]
    observed_at: datetime
    vantage: str
    provenance: str


class RecollectionProvider(Protocol):
    def collect(self, request: VerificationRequest) -> FactsEnvelope: ...


class OutcomeProvider(Protocol):
    def evaluate(self, request: VerificationRequest, fresh: FactsEnvelope) -> TrustedOutcomes: ...


def verify_post_fix(
    request: VerificationRequest,
    provider: RecollectionProvider | None,
    control_outcomes: dict[str, VerificationStatus] | None = None,
    service_outcomes: dict[str, VerificationStatus] | None = None,
    outcome_provider: OutcomeProvider | None = None,
) -> VerificationResult:
    if provider is None:
        return _result(
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            {},
            {},
            "none",
            ["Trusted recollection provider is required."],
        )
    fresh = provider.collect(request)
    now = datetime.now(UTC)
    if (
        str(fresh.org_id) != request.org_id
        or str(fresh.asset_id) != request.asset_id
        or fresh.vendor != request.baseline.vendor
    ):
        return _result(
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            {},
            {},
            fresh.collection_method,
            ["Fresh identity or vendor mismatch."],
        )
    if (
        fresh.collected_at <= request.baseline.collected_at
        or (now - fresh.collected_at).total_seconds() > request.max_age_seconds
    ):
        return _result(
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            {},
            {},
            fresh.collection_method,
            ["Fresh evidence is stale or reused baseline."],
        )
    if outcome_provider is None:
        return _result(
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            control_outcomes or {},
            service_outcomes or {},
            fresh.collection_method,
            ["Caller-supplied outcomes are untrusted compatibility input."],
        )
    trusted = outcome_provider.evaluate(request, fresh)
    evidence_hashes = sorted(ref.sha256 for ref in fresh.evidence_refs)
    if (
        trusted.org_id != request.org_id
        or trusted.asset_id != request.asset_id
        or trusted.change_id != request.change_id
        or sorted(trusted.evidence_hashes) != evidence_hashes
    ):
        return _result(
            VerificationStatus.UNKNOWN,
            VerificationStatus.UNKNOWN,
            {},
            {},
            fresh.collection_method,
            ["Trusted outcome binding mismatch."],
        )
    config = _required_status(request.required_check_ids, trusted.control_outcomes)
    service = _required_status(request.service_contract_ids, trusted.service_outcomes)
    return _result(
        config,
        service,
        trusted.control_outcomes,
        trusted.service_outcomes,
        trusted.provenance,
        ["Synthetic provenance is not live verification."]
        if "synthetic" in fresh.collection_method
        else [],
    )


def compare_normalized_facts(
    baseline: FactsEnvelope, current: FactsEnvelope
) -> list[FactDifference]:
    """Deterministic conservative comparison; missing partial facts are uncertainty, not removal."""
    differences: list[FactDifference] = []
    _compare("facts", baseline.facts, current.facts, differences, bool(current.errors))
    return differences


def drift_events(
    baseline: FactsEnvelope, current: FactsEnvelope, *, expected_paths: set[str] | None = None
) -> list[DriftEvent]:
    expected_paths = expected_paths or set()
    old = sorted(ref.sha256 for ref in baseline.evidence_refs)
    new = sorted(ref.sha256 for ref in current.evidence_refs)
    return [
        DriftEvent(
            path=d.path,
            classification=d.classification,
            expected=d.path in expected_paths,
            baseline_hashes=old,
            current_hashes=new,
            observed_at=current.collected_at,
            provenance=current.collection_method,
        )
        for d in compare_normalized_facts(baseline, current)
        if d.limitation is None
    ]


def phase9_verifier_adapter(result: VerificationResult) -> GateResult:
    """Adapt independent verification; unknown and failed results block rollout."""
    synthetic = "synthetic" in result.fresh_provenance.lower()
    allowed = result.status == VerificationStatus.PASS and not synthetic
    code = "VERIFICATION_SYNTHETIC_NOT_PRODUCTION" if synthetic else f"VERIFICATION_{result.status}"
    return GateResult(allowed=allowed, code=code, reason="Independent verification result.")


def _compare(path: str, old: Any, new: Any, out: list[FactDifference], partial: bool) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            child = f"{path}.{key}"
            if key not in new and partial:
                out.append(
                    FactDifference(
                        path=child,
                        classification="unknown",
                        before=old[key],
                        limitation="Partial capture cannot prove removal.",
                    )
                )
            elif key not in old:
                out.append(FactDifference(path=child, classification="added", after=new[key]))
            elif key not in new:
                out.append(FactDifference(path=child, classification="removed", before=old[key]))
            else:
                _compare(child, old[key], new[key], out, partial)
    elif old != new:
        out.append(
            FactDifference(
                path=path,
                classification="changed",
                before=_redact(old),
                after=_redact(new),
                runtime_observation="runtime" in path,
            )
        )


def _required_status(
    required: list[str], outcomes: dict[str, VerificationStatus]
) -> VerificationStatus:
    values = [outcomes.get(key, VerificationStatus.UNKNOWN) for key in required]
    if any(value == VerificationStatus.FAIL for value in values):
        return VerificationStatus.FAIL
    return (
        VerificationStatus.PASS
        if values and all(value == VerificationStatus.PASS for value in values)
        else VerificationStatus.UNKNOWN
    )


def _result(config, service, controls, services, provenance, limitations):
    overall = (
        VerificationStatus.PASS
        if config == service == VerificationStatus.PASS
        else VerificationStatus.FAIL
        if VerificationStatus.FAIL in {config, service}
        else VerificationStatus.UNKNOWN
    )
    return VerificationResult(
        config_control_status=config,
        service_contract_status=service,
        status=overall,
        control_outcomes=controls,
        service_outcomes=services,
        fresh_provenance=provenance,
        limitations=limitations,
    )


def _redact(value: Any) -> Any:
    if isinstance(value, str) and any(
        word in value.lower() for word in ("password", "secret", "token")
    ):
        return "[REDACTED]"
    return value
