"""Isolated JSON consumer smoke test; this is not Mandar worker integration."""

from datetime import timedelta
from pathlib import Path

from cisguard_device.models import AssessmentStatus
from cisguard_device.network_predicates import NetworkControlPolicy, evaluate_network_controls
from cisguard_device.remaining_devices import collect_remaining_fixture
from cisguard_device.remediation import generate_candidates, preview_dry_run
from cisguard_device.simulation import (
    ServiceSafetyContract,
    SimulationInput,
    simulate_what_if,
    simulation_contracts_hash,
    simulation_topology_hash,
)
from cisguard_device.verification import (
    TrustedOutcomes,
    VerificationRequest,
    VerificationStatus,
    drift_events,
    verify_post_fix,
)


class _SyntheticRecollection:
    def __init__(self, envelope):
        self.envelope = envelope

    def collect(self, _request):
        return self.envelope


class _SyntheticOutcomes:
    def evaluate(self, request, fresh):
        return TrustedOutcomes(
            org_id=request.org_id,
            asset_id=request.asset_id,
            change_id=request.change_id,
            evidence_hashes=[ref.sha256 for ref in fresh.evidence_refs],
            control_outcomes={"DEV-M26-001": VerificationStatus.PASS},
            service_outcomes={"unused-port-path": VerificationStatus.PASS},
            observed_at=fresh.collected_at,
            vantage="synthetic-consumer",
            provenance="synthetic_fixture",
        )


def test_isolated_consumer_flow_is_json_serializable_and_offline() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "remaining" / "cisco_switch" / "weak"
    envelope = collect_remaining_fixture(fixture / "manifest.json")
    policy = NetworkControlPolicy(
        session_timeout_seconds=300,
        expected_vty_lines=[0, 1, 2, 3, 4],
        designated_unused_ports=["GigabitEthernet1/0/2"],
    )
    results = evaluate_network_controls(envelope, policy)
    assert any(
        result.check_id == "DEV-M26-001" and result.status == AssessmentStatus.FAIL
        for result in results
    )
    candidates, rejected = generate_candidates(
        envelope, results, policy, ["ios_shutdown_unused_interface"]
    )
    assert not rejected and len(candidates) == 1
    candidate = candidates[0]
    assert preview_dry_run(candidate, envelope).outcome == "PREDICTED_NOT_EXECUTED"
    contracts = [
        ServiceSafetyContract(
            contract_id="unused-port-path",
            version="1",
            kind="path_available",
            interfaces=["GigabitEthernet1/0/2"],
            required=False,
        )
    ]
    topology = {
        "paths": [
            {
                "path_id": "synthetic-unused-path",
                "interfaces": ["GigabitEthernet1/0/2"],
                "modeled_available": True,
            }
        ]
    }
    simulation = simulate_what_if(
        SimulationInput(
            envelope=envelope,
            candidate=candidate,
            contracts=contracts,
            contracts_hash=simulation_contracts_hash(contracts),
            topology=topology,
            topology_hash=simulation_topology_hash(topology),
            backend="custom",
        )
    )
    assert simulation.verdict.value == "SAFE_IN_MODEL"
    baseline = envelope.model_copy(
        update={"collected_at": envelope.collected_at - timedelta(seconds=1)}
    )
    request = VerificationRequest(
        org_id=str(envelope.org_id),
        asset_id=str(envelope.asset_id),
        change_id="synthetic-change",
        candidate_hash=candidate.candidate_hash,
        template_id=candidate.template_id,
        template_version=candidate.template_version,
        policy_version="synthetic-policy-v1",
        baseline=baseline,
        required_check_ids=["DEV-M26-001"],
        service_contract_ids=["unused-port-path"],
        max_age_seconds=200000,
    )
    verification = verify_post_fix(
        request,
        _SyntheticRecollection(envelope),
        outcome_provider=_SyntheticOutcomes(),
    )
    assert verification.status == VerificationStatus.PASS
    assert verification.fresh_provenance == "synthetic_fixture"
    assert drift_events(baseline, envelope) == []
    # Worker payloads remain JSON-compatible and preserve evidence identity.
    assert (
        candidate.model_dump_json()
        and simulation.model_dump_json()
        and verification.model_dump_json()
    )
