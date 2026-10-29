"""Stable typed boundaries for later device-engine phases."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid5

from .execution import ExecutionRequest
from .models import CanonicalError, FactsEnvelope, OperationStatus, UnsupportedOperationResult
from .network_predicates import NetworkControlPolicy, PredicateResult, evaluate_network_controls
from .simulation import SimulationInput, SimulationResult, simulate_what_if
from .verification import (
    OutcomeProvider,
    RecollectionProvider,
    VerificationRequest,
    VerificationResult,
    verify_post_fix,
)

_REQUEST_NAMESPACE = UUID("f0f48a86-d985-48c3-a330-51adfc8fb068")


def evaluate_device(
    envelope: FactsEnvelope,
    policy: NetworkControlPolicy,
) -> list[PredicateResult]:
    """Return device-specific predicate evidence; central policy stays external."""
    return evaluate_network_controls(envelope, policy)


def candidates(command: dict[str, Any] | None = None) -> UnsupportedOperationResult:
    return _not_implemented("candidates", "Remediation candidates are not implemented in Phase 1.")


def simulate(input_model: SimulationInput | dict[str, Any]) -> SimulationResult:
    """Run the offline simulation boundary; no transport or write path is reachable."""
    if isinstance(input_model, dict):
        input_model = SimulationInput.model_validate(input_model)
    return simulate_what_if(input_model)


def execute(command: ExecutionRequest | dict[str, Any] | None = None) -> UnsupportedOperationResult:
    return _result(
        "execute",
        OperationStatus.REJECTED,
        "LIVE_WRITE_BLOCKED",
        "No production execution dependencies are configured; no transport was called.",
    )


def verify(
    request: VerificationRequest | dict[str, Any] | None = None,
    provider: RecollectionProvider | None = None,
    outcome_provider: OutcomeProvider | None = None,
) -> VerificationResult | UnsupportedOperationResult:
    if not isinstance(request, VerificationRequest):
        return _not_implemented("verify", "A typed verification request is required.")
    return verify_post_fix(request, provider, outcome_provider=outcome_provider)


def _not_implemented(operation: str, message: str) -> UnsupportedOperationResult:
    return _result(operation, OperationStatus.NOT_IMPLEMENTED, "NOT_IMPLEMENTED", message)


def _result(
    operation: str, status: OperationStatus, code: str, message: str
) -> UnsupportedOperationResult:
    return UnsupportedOperationResult(
        operation=operation,
        status=status,
        error=CanonicalError(
            code=code,
            message=message,
            request_id=uuid5(_REQUEST_NAMESPACE, operation),
            details={"phase": "phase6"},
            retryable=False,
        ),
    )
