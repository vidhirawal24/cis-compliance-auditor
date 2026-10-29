"""Fail-closed Phase-9 execution coordination; no production transport is provided."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .models import FactsEnvelope
from .remediation import RemediationCandidate, RemediationTemplate
from .simulation import SimulationResult


class ExecutionState(StrEnum):
    DRAFT = "DRAFT"
    SIMULATED = "SIMULATED"
    PRECHECKED = "PRECHECKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    NEEDS_MANUAL_RECOVERY = "NEEDS_MANUAL_RECOVERY"


class ExecutionRequest(BaseModel):
    """Provisional local request until Mandar publishes ActionEnvelope."""

    model_config = ConfigDict(extra="forbid")
    request_id: str
    action_id: str
    plan_id: str
    org_id: str
    asset_id: str
    candidate: RemediationCandidate
    current_evidence_hashes: list[str]
    simulation: SimulationResult
    approval_expires_at: datetime
    authorized_scope: str
    idempotency_key: str = Field(min_length=1)


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed: bool
    code: str
    reason: str


class JournalEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str
    request_id: str
    template_id: str
    state: ExecutionState
    timestamp: datetime
    reason: str


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str
    state: ExecutionState
    reason: str
    gate_results: list[GateResult]


class ApprovalVerifier(Protocol):
    def verify(self, request: ExecutionRequest) -> GateResult: ...


class FreshStateCollector(Protocol):
    def collect(self, request: ExecutionRequest) -> FactsEnvelope: ...


class BackupProvider(Protocol):
    def ready(self, request: ExecutionRequest) -> GateResult: ...


class SimulationValidator(Protocol):
    def validate(self, request: ExecutionRequest) -> GateResult: ...


class SecretProvider(Protocol):
    def ready(self, request: ExecutionRequest) -> GateResult: ...


class TemplateExecutor(Protocol):
    def execute(self, request: ExecutionRequest, commands: list[str]) -> str: ...


class VerificationProvider(Protocol):
    def verify(self, request: ExecutionRequest) -> GateResult: ...


class RecoveryProvider(Protocol):
    def recover(self, request: ExecutionRequest) -> GateResult: ...


class LockAndJournal(Protocol):
    def acquire(self, key: str) -> GateResult: ...
    def release(self, key: str) -> None: ...
    def lookup(self, key: str) -> ExecutionState | None: ...
    def append(self, entry: JournalEntry) -> None: ...


@dataclass
class ExecutionDependencies:
    """Typed dependency bag. None never means permit."""

    approval: ApprovalVerifier | None = None
    collector: FreshStateCollector | None = None
    backup: BackupProvider | None = None
    simulation: SimulationValidator | None = None
    secrets: SecretProvider | None = None
    executor: TemplateExecutor | None = None
    verifier: VerificationProvider | None = None
    recovery: RecoveryProvider | None = None
    journal: LockAndJournal | None = None


def execute_coordinated(
    request: ExecutionRequest,
    template: RemediationTemplate,
    dependencies: ExecutionDependencies,
    *,
    allow_test_template: bool = False,
) -> ExecutionResult:
    """Gate an injected executor. Production catalog templates remain non-executable."""
    gates: list[GateResult] = []
    if not allow_test_template or template.validation_level != "test_only_executable":
        return _blocked(request, gates, "TEMPLATE_NOT_EXECUTABLE")
    if dependencies.journal is None:
        return _blocked(request, gates, "JOURNAL_UNAVAILABLE")
    journal = dependencies.journal
    existing = journal.lookup(request.idempotency_key)
    if existing is not None:
        return _blocked(request, gates, f"IDEMPOTENCY_{existing}")
    lock = journal.acquire(request.idempotency_key)
    gates.append(lock)
    if not lock.allowed:
        return _blocked(request, gates, lock.code)
    try:
        for gate in _prechecks(request, template, dependencies):
            gates.append(gate)
            if not gate.allowed:
                return _blocked(request, gates, gate.code)
        _journal(journal, request, template, ExecutionState.PRECHECKED, "all gates passed")
        _journal(journal, request, template, ExecutionState.APPROVED, "trusted approval verified")
        _journal(journal, request, template, ExecutionState.EXECUTING, "bounded executor invoked")
        outcome = dependencies.executor.execute(request, request.candidate.commands)  # type: ignore[union-attr]
        if outcome != "confirmed_applied":
            state = (
                ExecutionState.NEEDS_MANUAL_RECOVERY
                if outcome in {"timeout", "partial"}
                else ExecutionState.FAILED
            )
            _journal(journal, request, template, state, f"executor outcome: {outcome}")
            return ExecutionResult(
                action_id=request.action_id, state=state, reason=outcome, gate_results=gates
            )
        _journal(
            journal, request, template, ExecutionState.VERIFYING, "independent postchecks required"
        )
        verified = dependencies.verifier.verify(request)  # type: ignore[union-attr]
        gates.append(verified)
        if not verified.allowed:
            _journal(journal, request, template, ExecutionState.FAILED, verified.code)
            return ExecutionResult(
                action_id=request.action_id,
                state=ExecutionState.FAILED,
                reason=verified.code,
                gate_results=gates,
            )
        _journal(journal, request, template, ExecutionState.VERIFIED, "postchecks passed")
        return ExecutionResult(
            action_id=request.action_id,
            state=ExecutionState.VERIFIED,
            reason="VERIFIED",
            gate_results=gates,
        )
    finally:
        journal.release(request.idempotency_key)


def reconcile_unknown(
    request: ExecutionRequest, dependencies: ExecutionDependencies
) -> ExecutionResult:
    """Restart reconciliation never retries an unknown write."""
    if dependencies.journal is None or dependencies.journal.lookup(request.idempotency_key) not in {
        ExecutionState.NEEDS_MANUAL_RECOVERY,
        ExecutionState.EXECUTING,
    }:
        return ExecutionResult(
            action_id=request.action_id,
            state=ExecutionState.FAILED,
            reason="NO_UNKNOWN_ACTION",
            gate_results=[],
        )
    return ExecutionResult(
        action_id=request.action_id,
        state=ExecutionState.NEEDS_MANUAL_RECOVERY,
        reason="RECONCILIATION_REQUIRED",
        gate_results=[],
    )


def staged_rollout(
    requests: list[ExecutionRequest],
    template: RemediationTemplate,
    dependencies: ExecutionDependencies,
    *,
    batch_size: int = 1,
    allow_test_template: bool = False,
) -> list[ExecutionResult]:
    results: list[ExecutionResult] = []
    for request in requests:
        result = execute_coordinated(
            request, template, dependencies, allow_test_template=allow_test_template
        )
        results.append(result)
        if result.state != ExecutionState.VERIFIED:
            break
    return results


def _prechecks(
    request: ExecutionRequest, template: RemediationTemplate, deps: ExecutionDependencies
) -> list[GateResult]:
    required = [
        deps.approval,
        deps.collector,
        deps.backup,
        deps.simulation,
        deps.secrets,
        deps.executor,
        deps.verifier,
    ]
    if any(item is None for item in required):
        return [
            GateResult(
                allowed=False,
                code="DEPENDENCY_UNAVAILABLE",
                reason="Production dependency is absent.",
            )
        ]
    if request.approval_expires_at <= datetime.now(UTC):
        return [GateResult(allowed=False, code="APPROVAL_EXPIRED", reason="Approval has expired.")]
    if (
        request.candidate.template_id != template.template_id
        or request.candidate.template_version != template.version
    ):
        return [
            GateResult(
                allowed=False, code="TEMPLATE_MISMATCH", reason="Candidate template is not exact."
            )
        ]
    fresh = deps.collector.collect(request)  # type: ignore[union-attr]
    if (
        str(fresh.org_id) != request.org_id
        or str(fresh.asset_id) != request.asset_id
        or fresh.platform != request.candidate.platform
    ):
        return [
            GateResult(
                allowed=False, code="STALE_OR_WRONG_TARGET", reason="Fresh target identity differs."
            )
        ]
    if sorted(ref.sha256 for ref in fresh.evidence_refs) != sorted(request.current_evidence_hashes):
        return [
            GateResult(allowed=False, code="STALE_CONFIGURATION", reason="Fresh evidence differs.")
        ]
    if request.simulation.candidate_hash != request.candidate.candidate_hash:
        return [
            GateResult(
                allowed=False, code="SIMULATION_MISMATCH", reason="Simulation candidate differs."
            )
        ]
    if any(o.service_preservation_evaluated is False for o in request.simulation.outcomes):
        return [
            GateResult(
                allowed=False,
                code="SERVICE_COVERAGE_INADEQUATE",
                reason="Setting-only simulation cannot preserve service.",
            )
        ]
    return [
        deps.approval.verify(request),
        deps.backup.ready(request),
        deps.simulation.validate(request),
        deps.secrets.ready(request),
    ]  # type: ignore[union-attr]


def _blocked(request: ExecutionRequest, gates: list[GateResult], reason: str) -> ExecutionResult:
    return ExecutionResult(
        action_id=request.action_id, state=ExecutionState.FAILED, reason=reason, gate_results=gates
    )


def _journal(
    journal: LockAndJournal,
    request: ExecutionRequest,
    template: RemediationTemplate,
    state: ExecutionState,
    reason: str,
) -> None:
    journal.append(
        JournalEntry(
            action_id=request.action_id,
            request_id=request.request_id,
            template_id=template.template_id,
            state=state,
            timestamp=datetime.now(UTC),
            reason=reason,
        )
    )
