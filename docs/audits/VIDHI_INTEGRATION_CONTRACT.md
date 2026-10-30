# Vidhi Device Engine Integration Contract

Status: provisional until Mandar publishes `packages/contracts/v1`.

## Package and entry points

- Package: `cisguard_device`, Python 3.11+.
- CLI: `python -m cisguard_device`; JSON on stdout, diagnostics on stderr.
- Core dependency: Pydantic 2.x. Optional groups cover networking, parsing, Windows remote, and Linux remote.
- Public imports are exported from `cisguard_device.__init__`.

Primary flow:

1. Collect/replay into `FactsEnvelope` using platform collector functions.
2. Call `evaluate_device(envelope, NetworkControlPolicy)` for bounded M20-M33 predicate evidence.
3. Call `generate_candidates(...)` and `preview_dry_run(...)` only for supported preview templates.
4. Call `simulate_what_if(SimulationInput)` for the bounded custom model.
5. Call `verify_post_fix(...)` only with trusted recollection and outcome providers.
6. Do not call live execution in production; `execute()` is blocked.

## Canonical collector output

`FactsEnvelope` v1.0.0 contains `org_id`, `asset_id`, `platform`, `vendor`, `model`, `os_or_firmware_version`, `collector_version`, `collection_method`, UTC `collected_at`, normalized `facts`, `evidence_refs`, supported/unsupported capabilities, and structured errors. Each evidence reference carries SHA-256, source identity, artifact location, and UTC timestamp.

Compatibility gaps Mandar must resolve explicitly:

- Local models are marked provisional and have not been generated from `packages/contracts/v1`.
- Benchmark ID/version/profile, rule applicability, policy-pack version, and official CIS mapping are not fields on `FactsEnvelope`; Mandar's evaluation job must supply and persist them.
- Collection errors are structured, but job/attempt identity and tenant authorization are external.
- Evidence locations do not themselves guarantee encrypted storage or access control.
- Async job scheduling, retry policy, idempotency, database persistence, and distributed worker routing are Mandar-owned.
- Approval signatures, vault references, policy exceptions, findings, scoring, and audit trail are external.

## Credentials and environment

Production should inject `SecretProvider`/`SSHSecretProvider` implementations backed by Mandar's vault. Development providers read `CISGUARD_WINRM_USERNAME`, `CISGUARD_WINRM_PASSWORD`, `CISGUARD_SSH_USERNAME`, and `CISGUARD_SSH_PASSWORD` when those transports are explicitly selected. Secrets must never be serialized into jobs, facts, evidence, or logs.

## Exceptions and process behavior

Library collectors raise typed device-engine/validation errors at invalid boundaries. CLI machine errors are structured JSON and nonzero. Unavailable operations return typed `UnsupportedOperationResult`. Callers must preserve `NOT_ASSESSED`, `UNSUPPORTED`, and partial provenance; they must not translate them to PASS.

## Safe synthetic invocation

```python
from pathlib import Path

from cisguard_device import collect_remaining_fixture

envelope = collect_remaining_fixture(
    Path("fixtures/remaining/cisco_switch/secure/manifest.json")
)
payload_for_mandar = envelope.model_dump(mode="json")
assert payload_for_mandar["collection_method"].startswith("offline")
```

This example is fixture replay only. Mandar should validate the payload against the frozen shared contract before accepting it into a worker pipeline.

## External services

Core offline replay requires none. Optional live paths require the authorized target and transport dependencies. OpenSCAP requires a locally installed `oscap` plus compatible content/profile. Production remediation and Batfish services are not implemented.
