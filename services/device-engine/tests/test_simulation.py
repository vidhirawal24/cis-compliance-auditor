import json
import socket
import subprocess
from datetime import UTC, datetime
from uuid import UUID

import pytest

from cisguard_device.cli import main
from cisguard_device.errors import DeviceEngineError
from cisguard_device.models import AssessmentStatus, EvidenceReference, FactsEnvelope
from cisguard_device.network_predicates import NetworkControlPolicy, PredicateResult
from cisguard_device.operations import simulate
from cisguard_device.remediation import generate_candidates
from cisguard_device.simulation import (
    ServiceSafetyContract,
    SimulationInput,
    simulate_what_if,
    simulation_contracts_hash,
    simulation_topology_hash,
)

ORG = UUID("11111111-1111-4111-8111-111111111111")
ASSET = UUID("22222222-2222-4222-8222-222222222222")


def _env(http: bool | None = True) -> FactsEnvelope:
    at = datetime(2026, 10, 29, tzinfo=UTC)
    return FactsEnvelope(
        org_id=ORG,
        asset_id=ASSET,
        platform="cisco_switch",
        vendor="Cisco",
        model="test",
        os_or_firmware_version="IOS-XE 17.9",
        collector_version="test",
        collection_method="fixture",
        collected_at=at,
        facts={
            "management": {
                "http_enabled": http,
                "vty_lines": [{"name": "0-4", "exec_timeout_seconds": 600}],
            },
            "interfaces": [{"name": "GigabitEthernet1/0/2", "configured_shutdown": False}],
        },
        evidence_refs=[
            EvidenceReference(
                sha256="a" * 64,
                source_identity="fixture",
                artifact_location="fixture://x",
                timestamp=at,
            )
        ],
    )


def _candidate(check: str, template: str):
    result = PredicateResult(
        check_id=check,
        feature_id="M",
        org_id=ORG,
        asset_id=ASSET,
        status=AssessmentStatus.FAIL,
        actual={},
        expected={},
        explanation="test",
    )
    policy = NetworkControlPolicy(
        session_timeout_seconds=300,
        expected_vty_lines=[0, 1, 2, 3, 4],
        designated_unused_ports=["GigabitEthernet1/0/2"],
    )
    return generate_candidates(_env(), [result], policy, [template])[0][0]


def _input(candidate, contracts, topology=None, backend="custom") -> SimulationInput:
    return SimulationInput(
        envelope=_env(),
        candidate=candidate,
        contracts=contracts,
        contracts_hash=simulation_contracts_hash(contracts),
        topology=topology,
        topology_hash=simulation_topology_hash(topology) if topology else None,
        backend=backend,
    )


def test_template_effects_and_configuration_scope() -> None:
    http = _candidate("DEV-M21-001", "ios_disable_http")
    contract = ServiceSafetyContract(contract_id="http", version="1", kind="local_http_disabled")
    output = simulate_what_if(_input(http, [contract]))
    assert output.verdict.value == "SAFE_IN_MODEL"
    assert output.outcomes[0].scope == "desired_configuration"
    assert output.outcomes[0].service_preservation_evaluated is False
    assert "SSH management access" in output.outcomes[0].limitations[0]

    vty = _candidate("DEV-M21-004", "ios_set_vty_timeout")
    timeout = ServiceSafetyContract(
        contract_id="vty", version="1", kind="vty_timeout_max", session_timeout_max=300
    )
    assert simulate_what_if(_input(vty, [timeout])).verdict.value == "SAFE_IN_MODEL"

    shutdown = _candidate("DEV-M26-001", "ios_shutdown_unused_interface")
    path = ServiceSafetyContract(
        contract_id="path", version="1", kind="path_available", interfaces=["GigabitEthernet1/0/2"]
    )
    topo = {
        "paths": [
            {"path_id": "admin", "interfaces": ["GigabitEthernet1/0/2"], "modeled_available": True}
        ]
    }
    output = simulate_what_if(_input(shutdown, [path], topo))
    assert output.verdict.value == "VIOLATES_CONTRACT"
    assert output.outcomes[0].affected_paths == ["admin"]
    assert "alternate paths" in output.outcomes[0].limitations[0]


def test_verdicts_precedence_missing_evidence_and_unchanged_contract() -> None:
    http = _candidate("DEV-M21-001", "ios_disable_http")
    missing = ServiceSafetyContract(
        contract_id="missing", version="1", kind="path_available", interfaces=["x"]
    )
    assert simulate_what_if(_input(http, [missing])).verdict.value == "INSUFFICIENT_EVIDENCE"
    unsupported = ServiceSafetyContract(
        contract_id="nat", version="1", kind="local_http_disabled", required_semantics=["nat"]
    )
    violated = ServiceSafetyContract(
        contract_id="vty", version="1", kind="vty_timeout_max", session_timeout_max=100
    )
    result = simulate_what_if(_input(http, [unsupported, missing, violated]))
    assert [x.verdict.value for x in result.outcomes] == [
        "UNSUPPORTED",
        "INSUFFICIENT_EVIDENCE",
        "VIOLATES_CONTRACT",
    ]
    assert result.verdict.value == "VIOLATES_CONTRACT"
    assert simulate_what_if(_input(http, [])).verdict.value == "INSUFFICIENT_EVIDENCE"
    # An unchanged candidate is evaluated from the explicit model, not marked unsupported.
    topo = {
        "paths": [
            {"path_id": "admin", "interfaces": ["GigabitEthernet1/0/2"], "modeled_available": True}
        ]
    }
    unchanged = ServiceSafetyContract(
        contract_id="path", version="1", kind="path_available", interfaces=["GigabitEthernet1/0/2"]
    )
    assert simulate_what_if(_input(http, [unchanged], topo)).verdict.value == "SAFE_IN_MODEL"


def test_missing_topology_membership_only_and_unsupported_semantics() -> None:
    shutdown = _candidate("DEV-M26-001", "ios_shutdown_unused_interface")
    path = ServiceSafetyContract(
        contract_id="path", version="1", kind="path_available", interfaces=["GigabitEthernet1/0/2"]
    )
    assert simulate_what_if(_input(shutdown, [path])).verdict.value == "INSUFFICIENT_EVIDENCE"
    membership = {"paths": [{"interfaces": ["GigabitEthernet1/0/2"]}]}
    assert (
        simulate_what_if(_input(shutdown, [path], membership)).verdict.value
        == "INSUFFICIENT_EVIDENCE"
    )
    for semantic in ("nat", "authentication", "stateful_flow"):
        contract = ServiceSafetyContract(
            contract_id=semantic,
            version="1",
            kind="local_http_disabled",
            required_semantics=[semantic],
        )
        assert simulate_what_if(_input(shutdown, [contract])).verdict.value == "UNSUPPORTED"


def test_integrity_identity_and_baseline_immutability() -> None:
    candidate = _candidate("DEV-M21-001", "ios_disable_http")
    contract = ServiceSafetyContract(contract_id="http", version="1", kind="local_http_disabled")
    env = _env()
    before = env.model_dump(mode="json")
    input_model = _input(candidate, [contract]).model_copy(update={"envelope": env})
    assert simulate(input_model).verdict.value == "SAFE_IN_MODEL"
    assert env.model_dump(mode="json") == before
    tampered = candidate.model_copy(deep=True)
    tampered.parameters["x"] = "y"
    with pytest.raises(DeviceEngineError, match="hash"):
        simulate_what_if(_input(tampered, [contract]))
    invalid = _input(candidate, [contract]).model_copy(update={"contracts_hash": "0" * 64})
    with pytest.raises(DeviceEngineError, match="Contract hash"):
        simulate_what_if(invalid)
    topology = {"paths": []}
    invalid_topology = _input(candidate, [contract], topology).model_copy(
        update={"topology_hash": "0" * 64}
    )
    with pytest.raises(DeviceEngineError, match="Topology hash"):
        simulate_what_if(invalid_topology)
    wrong_env = _env().model_copy(update={"asset_id": UUID("33333333-3333-4333-8333-333333333333")})
    mismatch = _input(candidate, [contract]).model_copy(update={"envelope": wrong_env})
    with pytest.raises(DeviceEngineError, match="identity"):
        simulate_what_if(mismatch)


def test_batfish_does_not_fallback_and_cli_json(tmp_path, capsys) -> None:
    candidate = _candidate("DEV-M21-001", "ios_disable_http")
    contract = ServiceSafetyContract(contract_id="http", version="1", kind="local_http_disabled")
    body = _input(candidate, [contract]).model_dump(mode="json")
    body.pop("backend")
    path = tmp_path / "simulation.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["simulate", "--input", str(path), "--backend", "custom"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "SAFE_IN_MODEL"
    assert main(["simulate", "--input", str(path), "--backend", "batfish"]) == 0
    batfish = json.loads(capsys.readouterr().out)
    assert batfish["backend"] == "batfish" and batfish["verdict"] == "UNSUPPORTED"
    scenarios = {
        "violates": ServiceSafetyContract(
            contract_id="vty", version="1", kind="vty_timeout_max", session_timeout_max=100
        ),
        "insufficient": ServiceSafetyContract(
            contract_id="path", version="1", kind="path_available", interfaces=["x"]
        ),
        "unsupported": ServiceSafetyContract(
            contract_id="nat",
            version="1",
            kind="local_http_disabled",
            required_semantics=["nat"],
        ),
    }
    expected = {
        "violates": "VIOLATES_CONTRACT",
        "insufficient": "INSUFFICIENT_EVIDENCE",
        "unsupported": "UNSUPPORTED",
    }
    for name, scenario_contract in scenarios.items():
        scenario = _input(candidate, [scenario_contract]).model_dump(mode="json")
        scenario.pop("backend")
        scenario_path = tmp_path / f"{name}.json"
        scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
        assert main(["simulate", "--input", str(scenario_path), "--backend", "custom"]) == 0
        assert json.loads(capsys.readouterr().out)["verdict"] == expected[name]
    assert main(["simulate", "--input", str(path), "--backend", "custom", "--max-bytes", "1"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "FILE_TOO_LARGE"


def test_simulation_never_uses_transport_or_subprocess(monkeypatch) -> None:
    candidate = _candidate("DEV-M21-001", "ios_disable_http")
    contract = ServiceSafetyContract(contract_id="http", version="1", kind="local_http_disabled")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("simulation must not use a transport or subprocess")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert simulate_what_if(_input(candidate, [contract])).verdict.value == "SAFE_IN_MODEL"
