# Phase 0 validation record

Validated locally on 29 October 2026 using Windows and Python 3.12.14.

**Result: 209 passed, 0 failures, 0 errors, 0 skipped.** Pytest reported 19.88 seconds. Machine-readable evidence: [phase0-tests.xml](phase0-tests.xml).

## Validated artifacts

- 88 distinct feature rows: M01-M38, E01-E30, I01-I20; source requirement and acceptance text, owner/RACI and UNTESTED product status preserved.
- 61 documented HTTP operations with explicit request/response schemas, tenant header, permissions, feature IDs and canonical errors.
- 70 generated JSON Schema documents checked against Draft 2020-12; OpenAPI 3.1 validated by openapi-spec-validator.
- 14 synthetic wire examples validated by both JSON Schema and Pydantic, including UUID/UTC/version and unknown-field behavior.
- Regenerated artifacts match committed-on-disk model output; proposed snapshot digest matches its exact file inventory.
- Negative tests cover invalid/absent worker versions, write-capable collection requests, raw password/command fields, foreign result correlation, cross-tenant evidence, missing provenance, unsupported capabilities, false scores, false PASS/FAIL evidence, exception status misuse, self-approval, plan-author approval, executable UNSAT plans and incomplete dual verification.
- Mock collector returns UNSUPPORTED; simulation/execution/verification refuse operation. ExecutionResult cannot claim VERIFIED.
- `pip check`: No broken requirements found. Exact test environment is in `infra/phase0-requirements.lock.txt`.

Contract proposal SHA-256: `63572b7b51b849a1c4e630d422e70d3972b1eb85f8244bb6f87941b927186757`.

## Reproduce

From the workspace root after environment setup in `infra/README.md`:

```powershell
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache --junitxml=docs/core/phase0-tests.xml apps/api/tests
```

## Limits and exit status

These are contract/specification checks, including one registry-preservation test per feature. They do **not** implement or validate the 88 product features. No live API, JWT authorization, MFA flow, RLS, storage encryption, device collector, vendor compatibility, simulation, actual hardening, reporting output or performance target was exercised. Cross-field Pydantic tests do not make JSON Schema alone sufficient for every semantic safety invariant.

Phase 0 authoring and local validation: DONE. Three-owner agreement/final contract freeze: PENDING. Product implementation: UNTESTED. External dependencies remain in [blockers-assumptions.md](blockers-assumptions.md). See [phase0-handoff.md](phase0-handoff.md) for the next review gate.
