from datetime import UTC, datetime, timedelta
from uuid import UUID

from cisguard_device.execution import (
    ExecutionDependencies,
    ExecutionRequest,
    ExecutionState,
    GateResult,
    JournalEntry,
    execute_coordinated,
    reconcile_unknown,
    staged_rollout,
)
from cisguard_device.models import EvidenceReference, FactsEnvelope, SimulationVerdict
from cisguard_device.remediation import RemediationCandidate, RemediationTemplate
from cisguard_device.simulation import SimulationResult


class FakeJournal:
    def __init__(self):
        self.states, self.entries, self.locked = {}, [], False

    def acquire(self, key):
        if self.locked:
            return GateResult(allowed=False, code="LOCKED", reason="locked")
        self.locked = True
        return GateResult(allowed=True, code="LOCKED", reason="ok")

    def release(self, key):
        self.locked = False

    def lookup(self, key):
        return self.states.get(key)

    def append(self, entry: JournalEntry):
        self.entries.append(entry)
        self.states[entry.action_id] = entry.state


class FakeGate:
    def __init__(self, allowed=True, code="OK"):
        self.allowed, self.code = allowed, code

    def verify(self, request):
        return GateResult(allowed=self.allowed, code=self.code, reason=self.code)

    def ready(self, request):
        return GateResult(allowed=self.allowed, code=self.code, reason=self.code)

    def validate(self, request):
        return GateResult(allowed=self.allowed, code=self.code, reason=self.code)


class FakeCollector:
    def __init__(self, envelope):
        self.envelope = envelope

    def collect(self, request):
        return self.envelope


class FakeExecutor:
    def __init__(self, outcome="confirmed_applied"):
        self.outcome, self.calls = outcome, 0

    def execute(self, request, commands):
        self.calls += 1
        return self.outcome


def _objects():
    org, asset = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    evidence = "a" * 64
    env = FactsEnvelope(
        org_id=UUID(org),
        asset_id=UUID(asset),
        platform="test",
        vendor="test",
        model="m",
        os_or_firmware_version="1",
        collector_version="t",
        collection_method="fixture",
        collected_at=datetime.now(UTC),
        facts={},
        evidence_refs=[
            EvidenceReference(
                sha256=evidence,
                source_identity="x",
                artifact_location="fixture://x",
                timestamp=datetime.now(UTC),
            )
        ],
    )
    candidate = RemediationCandidate(
        candidate_hash="b" * 64,
        template_id="test",
        template_version="1",
        org_id=org,
        asset_id=asset,
        platform="test",
        target_identity={},
        parameters={},
        source_evidence_hashes=[evidence],
        expected_preconditions={},
        commands=["redacted"],
    )
    simulation = SimulationResult(
        model_version="1",
        backend="custom",
        verdict=SimulationVerdict.SAFE_IN_MODEL,
        outcomes=[],
        candidate_hash=candidate.candidate_hash,
        source_evidence_hashes=[evidence],
        contracts_hash="c" * 64,
        topology_hash=None,
        supported_capabilities=[],
        unsupported_capabilities=[],
        limitations=[],
    )
    request = ExecutionRequest(
        request_id="r",
        action_id="a",
        plan_id="p",
        org_id=org,
        asset_id=asset,
        candidate=candidate,
        current_evidence_hashes=[evidence],
        simulation=simulation,
        approval_expires_at=datetime.now(UTC) + timedelta(hours=1),
        authorized_scope="test",
        idempotency_key="a",
    )
    template = RemediationTemplate(
        template_id="test",
        version="1",
        check_id="T",
        feature_id="T",
        platforms=["test"],
        firmware_scope="test",
        validation_level="test_only_executable",
        required_facts=[],
        dependencies=[],
        conflicts=[],
        risks=[],
        backup_requirement="test",
        reversibility="none",
        recovery_limitations=[],
        post_change_checks=[],
    )
    return env, request, template


def _deps(env, *, approval=True, outcome="confirmed_applied", verify=True):
    executor, journal = FakeExecutor(outcome), FakeJournal()
    deps = ExecutionDependencies(
        approval=FakeGate(approval, "REJECTED"),
        collector=FakeCollector(env),
        backup=FakeGate(),
        simulation=FakeGate(),
        secrets=FakeGate(),
        executor=executor,
        verifier=FakeGate(verify, "POSTCHECK_UNKNOWN"),
        journal=journal,
    )
    return deps, executor, journal


def test_preview_catalog_and_missing_approval_block_before_transport():
    env, request, template = _objects()
    deps, executor, _ = _deps(env, approval=False)
    assert (
        execute_coordinated(request, template, deps, allow_test_template=False).reason
        == "TEMPLATE_NOT_EXECUTABLE"
    )
    assert executor.calls == 0
    result = execute_coordinated(request, template, deps, allow_test_template=True)
    assert result.reason == "REJECTED" and executor.calls == 0


def test_success_requires_postcheck_and_timeout_requires_reconciliation():
    env, request, template = _objects()
    deps, executor, journal = _deps(env)
    assert (
        execute_coordinated(request, template, deps, allow_test_template=True).state
        == ExecutionState.VERIFIED
    )
    assert executor.calls == 1 and all("redacted" not in e.reason for e in journal.entries)
    env, request, template = _objects()
    deps, _, journal = _deps(env, outcome="timeout")
    assert (
        execute_coordinated(request, template, deps, allow_test_template=True).state
        == ExecutionState.NEEDS_MANUAL_RECOVERY
    )
    journal.states[request.idempotency_key] = ExecutionState.NEEDS_MANUAL_RECOVERY
    assert reconcile_unknown(request, deps).reason == "RECONCILIATION_REQUIRED"


def test_staged_rollout_stops_after_failed_postcheck():
    env, request, template = _objects()
    deps, _, _ = _deps(env, verify=False)
    second = request.model_copy(update={"action_id": "b", "idempotency_key": "b"})
    results = staged_rollout([request, second], template, deps, allow_test_template=True)
    assert len(results) == 1 and results[0].state == ExecutionState.FAILED
