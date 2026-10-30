# Proposed v1 schema and route diff

Baseline: empty workspace plus the pasted frozen v1 outline. This is a reviewable proposal, not an assertion of three-person agreement. No runtime routes exist yet.

## Preserved

`/api/v1`, Bearer Supabase access tokens, UUID identifiers, UTC timestamps, cursor/limit pagination, six assessment states, separate exception overlays, four simulation verdicts, eleven execution states, canonical success envelope and canonical error shape. Scans expose assessed_compliance_pct and assessment_coverage_pct directly in data as in the playbook example, with reconciliation counts added.

## Clarified or added for review

- Evidence facts use typed category arrays of `{path,value,evidence_ids,observed_at}` instead of the illustrative untyped nested `{management:{telnet_enabled:true}}`. This is a deliberate proposed change requiring consumer agreement. It gives every observed fact provenance. A fact-bearing sample must have a corresponding EvidenceRef; the playbook's empty-reference illustration is not accepted as real evidence.
- EvidenceRef adds UUID evidence_id and names the source and encrypted location fields explicitly. Error details use sanitized text arrays. Private locations are opaque `private://bucket/org/object` references; only authorized download responses carry expiring HTTPS URLs.
- Tenant selection uses validated `X-Org-ID`; all mutation requests carry Idempotency-Key. Page data contains items and next_cursor. Backend data remains the score source. Coverage denominator, four-decimal rounding and null zero denominators are specified in ADR 0003.
- Worker collection, simulation, execution and verification messages are distinct from public request bodies. Parameters for privileged actions are server-validated references. Simulation and planning POSTs return accepted job/resource IDs; outcome resources are read after completion.
- New role names, job states, collection outcome states, error codes and plan outcomes are explicit. These do not change technical assessment statuses.

## PRD aliases resolved

| PRD representative route | Canonical v1 | Treatment |
|---|---|---|
| POST /audits | POST /scans | Playbook name wins; same read-only behavior |
| GET /audits/{id} | GET /scans/{scan_id} | No duplicate alias in v1 |
| GET /verification/{id} | GET /verifications/{verification_id} | Plural playbook family |
| GET /audit-events | GET /audit-history | Same tenant-scoped immutable event history |
| POST /plans/{id}/approve | POST /approvals | Bind plan_id and exact plan hash |
| POST /plans/{id}/execute | POST /changes | Bind plan, approval, simulation and precheck |

Additional concrete routes resolve source-required behavior not detailed in the outline: DELETE /assets/{id} retires an asset, POST /policy-overrides, POST /manual-reviews, POST /exceptions/{id}/decision, POST/GET /prechecks, GET /reports/{id}, POST /verifications and POST /proof-packages. Retirement must preserve historical findings/evidence.

The complete method-by-method inventory is `packages/contracts/v1/route_catalog.py`; OpenAPI records request/response types, authorization permission, feature tags and standard error responses for every operation. Optional unlisted workflow details must be resolved by a reviewed contract change before implementation, not invented by a consumer.

## Approval record

Review digest and sign-offs are stored in `freeze.json`. Mandar preparation is not a substitute for Apoorva/Vidhi review. No API deployment, shared schema publication, merge, vendor support or product acceptance is implied by this proposal.
