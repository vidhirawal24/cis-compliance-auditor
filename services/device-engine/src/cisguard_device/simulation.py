"""Bounded offline Phase-8 what-if model; it never contacts or changes a device."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .errors import DeviceEngineError
from .models import FactsEnvelope, SimulationVerdict
from .remediation import RemediationCandidate

MODEL_VERSION = "1.1.0"
_UNSUPPORTED_SEMANTICS = {"nat", "authentication", "stateful_flow"}


class ServiceSafetyContract(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_id: str
    version: str
    kind: Literal["local_http_disabled", "vty_timeout_max", "path_available"]
    required: bool = True
    port: int | None = Field(default=None, ge=1, le=65535)
    interfaces: list[str] = Field(default_factory=list)
    session_timeout_max: int | None = Field(default=None, ge=1)
    required_semantics: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class SimulationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: FactsEnvelope
    candidate: RemediationCandidate
    contracts: list[ServiceSafetyContract]
    contracts_hash: str | None = None
    topology: dict[str, Any] | None = None
    topology_version: str | None = None
    topology_hash: str | None = None
    backend: Literal["custom", "batfish"]


class ContractOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contract_id: str
    verdict: SimulationVerdict
    scope: Literal["desired_configuration", "modeled_service_path"]
    service_preservation_evaluated: bool
    baseline: dict[str, Any]
    candidate: dict[str, Any]
    assumptions: list[str]
    affected_interfaces: list[str]
    affected_paths: list[str] = Field(default_factory=list)
    limitations: list[str]


class SimulationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_version: str
    backend: str
    verdict: SimulationVerdict
    outcomes: list[ContractOutcome]
    candidate_hash: str
    source_evidence_hashes: list[str]
    contracts_hash: str
    topology_hash: str | None
    supported_capabilities: list[str]
    unsupported_capabilities: list[str]
    limitations: list[str]


def simulation_contracts_hash(contracts: list[ServiceSafetyContract]) -> str:
    """Canonical hash callers bind to the exact supplied contract collection."""
    return _hash([contract.model_dump(mode="json") for contract in contracts])


def simulation_topology_hash(topology: dict[str, Any]) -> str:
    """Canonical hash callers bind to the exact supplied topology document."""
    return _hash(topology)


def simulate_what_if(input_model: SimulationInput) -> SimulationResult:
    """Evaluate a signed candidate against explicit offline facts and model inputs."""
    _validate_input_bindings(input_model)
    if input_model.backend == "batfish":
        return batfish_unavailable_result(input_model)
    envelope, candidate = input_model.envelope, input_model.candidate
    outcomes = [
        _evaluate(c, envelope, candidate, input_model.topology) for c in input_model.contracts
    ]
    evidence = sorted(ref.sha256 for ref in envelope.evidence_refs)
    return SimulationResult(
        model_version=MODEL_VERSION,
        backend="custom",
        verdict=_aggregate([o.verdict for o in outcomes]),
        outcomes=outcomes,
        candidate_hash=candidate.candidate_hash,
        source_evidence_hashes=evidence,
        contracts_hash=simulation_contracts_hash(input_model.contracts),
        topology_hash=(
            simulation_topology_hash(input_model.topology) if input_model.topology else None
        ),
        supported_capabilities=[
            "local_http_setting",
            "vty_timeout",
            "explicit_modeled_interface_path",
        ],
        unsupported_capabilities=[
            "nat",
            "authentication",
            "stateful_flow",
            "dynamic_routing",
            "application_policy",
            "live_reachability",
        ],
        limitations=[
            "SAFE_IN_MODEL is not live safety, execution approval, or an end-to-end service test."
        ],
    )


def _validate_input_bindings(input_model: SimulationInput) -> None:
    envelope, candidate = input_model.envelope, input_model.candidate
    if candidate.org_id != str(envelope.org_id) or candidate.asset_id != str(envelope.asset_id):
        raise DeviceEngineError(
            "SIMULATION_IDENTITY_MISMATCH", "Candidate and snapshot identity differ."
        )
    if sorted(ref.sha256 for ref in envelope.evidence_refs) != sorted(
        candidate.source_evidence_hashes
    ):
        raise DeviceEngineError(
            "SIMULATION_EVIDENCE_MISMATCH", "Candidate evidence hashes differ from snapshot."
        )
    if _candidate_hash(candidate) != candidate.candidate_hash:
        raise DeviceEngineError("CANDIDATE_TAMPERED", "Candidate content hash is invalid.")
    expected_contracts_hash = simulation_contracts_hash(input_model.contracts)
    if input_model.contracts_hash is None:
        raise DeviceEngineError(
            "CONTRACT_HASH_REQUIRED", "Simulation input must bind its contracts hash."
        )
    if input_model.contracts_hash != expected_contracts_hash:
        raise DeviceEngineError(
            "CONTRACT_HASH_MISMATCH", "Contract hash does not match supplied contracts."
        )
    if input_model.topology is None:
        if input_model.topology_hash is not None:
            raise DeviceEngineError(
                "TOPOLOGY_HASH_MISMATCH", "Topology hash was supplied without topology."
            )
        return
    expected_topology_hash = simulation_topology_hash(input_model.topology)
    if input_model.topology_hash is None:
        raise DeviceEngineError(
            "TOPOLOGY_HASH_REQUIRED", "Simulation input must bind its topology hash."
        )
    if input_model.topology_hash != expected_topology_hash:
        raise DeviceEngineError(
            "TOPOLOGY_HASH_MISMATCH", "Topology hash does not match supplied topology."
        )


def batfish_unavailable_result(input_model: SimulationInput) -> SimulationResult:
    """Explicit optional boundary; never substitutes custom simulation output."""
    return SimulationResult(
        model_version=MODEL_VERSION,
        backend="batfish",
        verdict=SimulationVerdict.UNSUPPORTED,
        outcomes=[
            _unsupported(
                c, "Batfish service/integration is not configured; no Batfish run occurred."
            )
            for c in input_model.contracts
        ],
        candidate_hash=input_model.candidate.candidate_hash,
        source_evidence_hashes=sorted(ref.sha256 for ref in input_model.envelope.evidence_refs),
        contracts_hash=simulation_contracts_hash(input_model.contracts),
        topology_hash=(
            simulation_topology_hash(input_model.topology) if input_model.topology else None
        ),
        supported_capabilities=[],
        unsupported_capabilities=["batfish_service_unavailable"],
        limitations=["No custom-model fallback was run."],
    )


def _evaluate(
    contract: ServiceSafetyContract,
    envelope: FactsEnvelope,
    candidate: RemediationCandidate,
    topology: dict[str, Any] | None,
) -> ContractOutcome:
    unsupported = sorted(set(contract.required_semantics).intersection(_UNSUPPORTED_SEMANTICS))
    if unsupported:
        return _unsupported(contract, f"Unsupported required semantics: {', '.join(unsupported)}.")
    if contract.kind == "local_http_disabled":
        value = envelope.facts.get("management", {}).get("http_enabled")
        if value is None:
            return _unknown(contract, "HTTP setting was not collected.", "desired_configuration")
        changed = False if candidate.template_id == "ios_disable_http" else value
        verdict = (
            SimulationVerdict.SAFE_IN_MODEL
            if changed is False
            else SimulationVerdict.VIOLATES_CONTRACT
        )
        return _outcome(
            contract,
            verdict,
            "desired_configuration",
            False,
            {"http_enabled": value},
            {"http_enabled": changed},
            [],
            [
                "This checks the local HTTP setting only; it does not establish preserved HTTP "
                "or SSH management access."
            ],
        )
    if contract.kind == "vty_timeout_max":
        if contract.session_timeout_max is None:
            return _unknown(contract, "Contract timeout bound is missing.", "desired_configuration")
        old = [
            line.get("exec_timeout_seconds")
            for line in envelope.facts.get("management", {}).get("vty_lines", [])
        ]
        if not old or any(value is None for value in old):
            return _unknown(
                contract, "Complete VTY timeout facts are missing.", "desired_configuration"
            )
        new = (
            candidate.parameters.get("timeout_seconds")
            if candidate.template_id == "ios_set_vty_timeout"
            else max(old)
        )
        verdict = (
            SimulationVerdict.SAFE_IN_MODEL
            if new <= contract.session_timeout_max
            else SimulationVerdict.VIOLATES_CONTRACT
        )
        return _outcome(
            contract,
            verdict,
            "desired_configuration",
            False,
            {"max_timeout": max(old)},
            {"max_timeout": new},
            [],
            ["This checks modeled VTY timeout configuration, not live session preservation."],
        )
    return _path_outcome(contract, candidate, topology)


def _path_outcome(
    contract: ServiceSafetyContract,
    candidate: RemediationCandidate,
    topology: dict[str, Any] | None,
) -> ContractOutcome:
    if topology is None:
        return _unknown(
            contract, "Explicit topology is required for path contract.", "modeled_service_path"
        )
    paths = topology.get("paths")
    if not isinstance(paths, list):
        return _unknown(contract, "Topology paths are missing.", "modeled_service_path")
    relevant = [
        p
        for p in paths
        if isinstance(p, dict) and set(contract.interfaces).intersection(p.get("interfaces", []))
    ]
    if not relevant:
        return _unknown(
            contract,
            "No supplied topology path matches contract interfaces.",
            "modeled_service_path",
        )
    if any(path.get("modeled_available") is not True for path in relevant):
        return _unknown(
            contract,
            "Relevant topology paths lack explicit modeled availability.",
            "modeled_service_path",
        )
    interface = (
        candidate.parameters.get("interface")
        if candidate.template_id == "ios_shutdown_unused_interface"
        else None
    )
    affected_paths = [
        str(path.get("path_id", index))
        for index, path in enumerate(relevant)
        if interface in path.get("interfaces", [])
    ]
    affected = [interface] if affected_paths and isinstance(interface, str) else []
    verdict = (
        SimulationVerdict.VIOLATES_CONTRACT
        if affected_paths and contract.required
        else SimulationVerdict.SAFE_IN_MODEL
    )
    return _outcome(
        contract,
        verdict,
        "modeled_service_path",
        True,
        {"relevant_paths_modeled_available": True},
        {"relevant_paths_modeled_available": not bool(affected_paths)},
        affected,
        [
                "Only explicit modeled paths were evaluated; alternate paths and actual service "
                "reachability remain unknown."
        ],
        affected_paths,
    )


def _outcome(
    contract: ServiceSafetyContract,
    verdict: SimulationVerdict,
    scope: Literal["desired_configuration", "modeled_service_path"],
    preserved: bool,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    affected_interfaces: list[str],
    limitations: list[str],
    affected_paths: list[str] | None = None,
) -> ContractOutcome:
    return ContractOutcome(
        contract_id=contract.contract_id,
        verdict=verdict,
        scope=scope,
        service_preservation_evaluated=preserved,
        baseline=baseline,
        candidate=candidate,
        assumptions=contract.assumptions,
        affected_interfaces=affected_interfaces,
        affected_paths=affected_paths or [],
        limitations=limitations,
    )


def _unknown(
    contract: ServiceSafetyContract,
    reason: str,
    scope: Literal["desired_configuration", "modeled_service_path"],
) -> ContractOutcome:
    return _outcome(
        contract, SimulationVerdict.INSUFFICIENT_EVIDENCE, scope, False, {}, {}, [], [reason]
    )


def _unsupported(contract: ServiceSafetyContract, reason: str) -> ContractOutcome:
    return _outcome(
        contract, SimulationVerdict.UNSUPPORTED, "modeled_service_path", False, {}, {}, [], [reason]
    )


def _aggregate(verdicts: list[SimulationVerdict]) -> SimulationVerdict:
    if not verdicts:
        return SimulationVerdict.INSUFFICIENT_EVIDENCE
    for value in (
        SimulationVerdict.VIOLATES_CONTRACT,
        SimulationVerdict.UNSUPPORTED,
        SimulationVerdict.INSUFFICIENT_EVIDENCE,
    ):
        if value in verdicts:
            return value
    return SimulationVerdict.SAFE_IN_MODEL


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _candidate_hash(candidate: RemediationCandidate) -> str:
    return _hash(
        {
            "org_id": candidate.org_id,
            "asset_id": candidate.asset_id,
            "template": candidate.template_id,
            "version": candidate.template_version,
            "platform": candidate.platform,
            "parameters": candidate.parameters,
            "evidence": sorted(candidate.source_evidence_hashes),
            "preconditions": candidate.expected_preconditions,
        }
    )
