# Device-engine integration contract

## What Mandar imports

Install `services/device-engine` in the worker environment and import from
`cisguard_device`. Stable Phase-1 public imports include the Phase-0 models plus fixture
and unsupported-operation functions.

```python
probe_fixture(manifest_path: Path, *, platform: str | None = None) -> dict[str, Any]
collect_fixture(
    manifest_path: Path,
    *,
    platform: str | None = None,
    max_bytes: int | None = None,
) -> FactsEnvelope
load_manifest(path: Path) -> FixtureManifest
load_expected_envelope(manifest_path: Path) -> FactsEnvelope

evaluate_device(envelope: FactsEnvelope, policy: NetworkControlPolicy) -> list[PredicateResult]
candidates(command: dict[str, Any] | None = None) -> UnsupportedOperationResult
simulate(input_model: SimulationInput | dict[str, Any]) -> SimulationResult
execute(command: dict[str, Any] | None = None) -> UnsupportedOperationResult
verify(command: dict[str, Any] | None = None) -> UnsupportedOperationResult

probe_windows_fixture(manifest_path: Path) -> dict[str, Any]
collect_windows_fixture(manifest_path: Path) -> FactsEnvelope
collect_windows_local(
    *, org_id: UUID, asset_id: UUID, model: str = "local-windows-host",
    timeout_seconds: int = 120, max_output_bytes: int = 4194304,
) -> FactsEnvelope
collect_windows_winrm(
    *, target: str, secret_provider: SecretProvider, org_id: UUID,
    asset_id: UUID, model: str = "remote-windows-host",
    timeout_seconds: int = 120, max_output_bytes: int = 4194304,
) -> FactsEnvelope
parse_windows_capture(content: bytes) -> WindowsCapture
classify_windows_capture(capture: WindowsCapture) -> WindowsClassification

probe_linux_fixture(manifest_path: Path) -> dict[str, Any]
collect_linux_fixture(manifest_path: Path) -> FactsEnvelope
collect_linux_local(
    *, org_id: UUID, asset_id: UUID, model: str = "local-linux-host",
    timeout_seconds: int = 120, max_output_bytes: int = 4194304,
) -> FactsEnvelope
collect_linux_ssh(
    *, target: str, port: int, known_hosts: Path,
    secret_provider: SSHSecretProvider, org_id: UUID, asset_id: UUID,
    model: str = "remote-linux-host", timeout_seconds: int = 120,
) -> FactsEnvelope
parse_linux_capture(content: bytes) -> LinuxCapture
classify_linux_capture(capture: LinuxCapture) -> LinuxClassification

ingest_xccdf_results(path: Path, *, synthetic: bool = False) -> XccdfResultDocument
inspect_scap_content(path: Path) -> dict[str, Any]
run_local_openscap(
    *, content_path: Path, profile_id: str, output_path: Path,
    expected_platform: str, timeout_seconds: int = 900,
) -> OpenScapRunResult
```

The provisional synchronous adapter SDK is:

```python
probe_version(source: FixtureInput) -> str | None
collect(source: FixtureInput, *, read_only: bool = True) -> CollectedArtifact
parse(raw: CollectedArtifact) -> ParsedConfiguration
normalize(raw: CollectedArtifact, parsed: ParsedConfiguration) -> FactsEnvelope
supported_controls() -> Sequence[str]
remediation_capabilities() -> Sequence[str]
execute_approved_change(change: Mapping[str, Any]) -> None
```

`execute_approved_change` is the optional future boundary in conceptual terms; the
Phase-1 fixture adapter implements it only to reject every call with
`LIVE_WRITE_BLOCKED`.

The device engine returns collection facts and provenance. Mandar's central policy
engine remains solely responsible for applicability, CIS control evaluation, findings,
exceptions, and scoring. This package must not become a second policy engine.

## Provisional decisions

`packages/contracts/v1/` did not exist during phase 0. Therefore every local model is a
clearly marked **PROVISIONAL compatibility model**, not a team-approved frozen
contract. The guide fixes the listed fields and enum values but leaves these signatures
unresolved:

- Whether `request_id` is required for collector errors that originate outside an API
  request, and who creates it.
- Whether `details` is any JSON value or specifically a JSON object. This foundation
  conservatively uses an optional object.
- Whether evidence field names should be `source_identity` / `artifact_location` or
  other canonical names; the guide specifies meanings but not exact keys.
- Whether timestamps must be serialized with `Z` rather than the equivalent `+00:00`.
- Whether platform, vendor, collection method, capability names, and error codes will
  be frozen enums/registries.
- Whether empty or unknown model/version strings should be null. The provisional model
  requires explicit non-empty strings and the self-test uses the literal `unknown`.
- Whether adapter methods are synchronous, asynchronous, or split into transport and
  pure parsing protocols. The Phase-1 provisional interface is synchronous and
  transport-free.
- Whether `collect()` returns raw bytes, structured JSON, or an artifact handle. It is
  provisionally a read-only mapping.

When Mandar publishes independently importable v1 models, replace or re-export these
local compatibility classes only after schema-diff review. Do not silently maintain two
production schemas.

## Validation and unknown semantics

UUID fields use UUID validation. `collected_at` and evidence timestamps require an
aware UTC offset. Unknown configuration facts remain explicit JSON `null`; collectors
must not replace them with secure defaults. Unsupported platforms raise
`UnsupportedPlatformError`, rather than falling back to a generic success path.

## Evidence artifact convention

An evidence reference records a lowercase SHA-256 digest, a non-secret command/API
identity, artifact location, and UTC timestamp. For local fixtures, use a relative path
under a future fixture corpus or a `fixture://` URI. Such artifacts are synthetic and
not encrypted; their metadata must not claim encryption.

The Phase-1 loader hashes exact source bytes before UTF-8 decoding. Extracted facts carry
line references inside `facts`; this compatible extension does not alter the canonical
envelope. Parsing is deterministic and configuration content is never executed.

Production sensitive artifacts are separate: Mandar will provide encrypted private
storage and access control. A production storage reference may only be described as
encrypted after encryption actually occurred. Raw credentials, keys, tokens, and
privileged secret content never belong in the envelope.

Windows source failures appear both in each fact group's `collection_state` and in the
canonical error list. Denied/error/unavailable sources normalize to `value: null`, never
to secure-looking defaults. `facts.deployment.effective_domain_policy_verified` is false
in Phase 2; domain membership alone is not effective-policy evidence.

Linux fact groups follow the same source-state convention. `/etc/os-release` identity is
strict; derivatives are unsupported rather than inferred. XCCDF results are supplemental
artifacts with their own hashes and raw states. Their provisional shared status is not a
central policy verdict and Mandar must not score it without authorized mapping/context.

## Phase 4 public firewall SDK

```python
probe_firewall_fixture(manifest_path: Path) -> dict[str, Any]
collect_firewall_fixture(manifest_path: Path, *, max_bytes: int = 4194304) -> FactsEnvelope
parse_firewall_capture(content: bytes, *, max_bytes: int = 4194304) -> FirewallCapture
resolve_objects(objects: Mapping[str, Any], *, max_depth: int = 16) -> dict[str, Any]
collect_paginated(fetch_page: Callable, *, max_pages: int = 100) -> list[Any]
collect_asa_ssh(
    *, target: str, known_hosts: Path, secret_provider: FirewallSecretProvider,
    org_id: UUID, asset_id: UUID, client_factory: Callable,
    timeout_seconds: int = 60,
) -> dict[str, Any]
```

Firewall facts are evidence, not findings. Denial is unavailable, stored policy is not
proof of installation, and Check Point Gaia evidence remains separate.

## Phase 7 remediation preparation SDK

```python
list_remediation_templates() -> list[RemediationTemplate]
generate_candidates(envelope, results, policy, template_ids=None) -> tuple[list[RemediationCandidate], list[dict[str, str]]]
preview_dry_run(candidate, envelope) -> DryRunPreview
recovery_specification(candidate, envelope) -> RecoverySpecification
create_encrypted_backup(path, content, metadata, *, cipher) -> dict[str, Any]
read_encrypted_backup(path, *, cipher, org_id, asset_id) -> bytes
```

`BackupCipher` is Mandar/OpenBao integration boundary. These APIs create no device
connections, approvals, execution authorization, restore, or tested rollback.

## Phase 8 simulation SDK

```python
simulate_what_if(input_model: SimulationInput) -> SimulationResult
simulate(input_model: SimulationInput | dict[str, Any]) -> SimulationResult
simulation_contracts_hash(contracts: list[ServiceSafetyContract]) -> str
simulation_topology_hash(topology: dict[str, Any]) -> str
```

`SimulationInput` binds the candidate to envelope identity/evidence, and binds the exact
contracts and any topology by canonical hashes. Results separate `desired_configuration`
from `modeled_service_path`; a local HTTP outcome never proves management-service continuity.
`path_available` requires explicit `modeled_available: true`, not path membership alone.
Batfish is an optional backend and presently returns `UNSUPPORTED` with no fallback.

## Phase 9 execution SDK

```python
execute_coordinated(request, template, dependencies, *, allow_test_template=False) -> ExecutionResult
staged_rollout(requests, template, dependencies, *, batch_size=1, allow_test_template=False) -> list[ExecutionResult]
reconcile_unknown(request, dependencies) -> ExecutionResult
```

`ExecutionRequest` is provisional pending Mandar's shared ActionEnvelope. Production must inject
trusted approval, durable lock/journal/idempotency, fresh collection, secrets, backup, supported
executor, recovery and independent verifier; no default implementation permits execution.

## Phase 5 public SDK

```python
probe_remaining_fixture(path: Path) -> dict[str, Any]
collect_remaining_fixture(path: Path, *, max_bytes: int = 4194304) -> FactsEnvelope
parse_sophos_xml(content: bytes) -> dict[str, Any]
parse_panos_xml(content: bytes) -> dict[str, Any]
parse_cisco_ios_sources(
    config: bytes, operational: bytes | None, *, platform: str,
    designated_unused_ports: list[str] | None,
) -> dict[str, Any]
```

Inputs are vendor-shaped raw sources, not hand-normalized facts. The manifest is only
the provenance/completeness wrapper.

## Phase 6 public SDK: Network Predicates & Offline Import

```python
# Evaluators & Policy
evaluate_network_controls(
    envelope: FactsEnvelope,
    policy: NetworkControlPolicy,
) -> list[PredicateResult]

evaluate_device(
    envelope: FactsEnvelope,
    policy: NetworkControlPolicy,
) -> list[PredicateResult]

# Offline Import
import_offline_file(
    path: Path,
    metadata: OfflineImportMetadata,
    *,
    max_bytes: int = 4194304,
    operational_path: Path | None = None,
) -> FactsEnvelope
```

### Models & Registries

```python
class NetworkControlPolicy(StrictModel):
    session_timeout_seconds: int  # Required
    sensitive_ports: list[int] = [22, 23, 80, 443, 3389]
    required_vlans: list[str] | None = None
    designated_unused_ports: list[str] | None = None
    management_interface_inventory: list[str] | None = None
    management_interface_inventory_complete: bool = False
    interface_roles: dict[str, str] | None = None
    max_acl_complexity: int = 500

class PredicateResult(StrictModel):
    check_id: str
    feature_id: str
    org_id: UUID
    asset_id: UUID
    status: AssessmentStatus
    actual: dict[str, Any]
    expected: dict[str, Any]
    evidence_refs: list[str]
    explanation: str
    applicability_note: str = ""
    limitations: list[str] = []
    error_code: str | None = None
    remediation: str | None = None

class EvidenceProvenance(StrEnum):
    USER_SUPPLIED_CAPTURE = "user_supplied_capture"
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    LIVE_COLLECTION = "live_collection"  # Rejected by offline import

class OfflineImportMetadata(StrictModel):
    source_type: str
    platform: str
    org_id: UUID
    asset_id: UUID
    capture_timestamp: datetime | None = None
    provenance: EvidenceProvenance = EvidenceProvenance.USER_SUPPLIED_CAPTURE
    completeness: Literal["complete", "partial", "unknown"]  # Required
    collector_version: str = "0.1.0"
    model: str | None = None
```
