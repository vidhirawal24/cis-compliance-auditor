# Mandar Phase 0 handoff

Start with [source and scope map](phase0-prd-map.md), [88-feature RACI](feature-raci.md), [backend domain map](backend-domain-map.md) and [schema/route diff](schema-route-diff.md). The contract is at `packages/contracts/v1/`; there is no parallel `contracts/v1/` copy.

## Prepared deliverables

- Both complete PDF sources reviewed and hashed; all 88 feature requirements and acceptance criteria extracted with page references.
- Per-feature ownership, accountable owner, stable acceptance ID and honest product status.
- Pydantic schemas, generated OpenAPI/JSON Schemas, role matrix, synthetic wire fixtures and a hashed proposal record.
- Typed device-engine port with no vendor implementation or fabricated device success.
- ADRs for governance, tenant/auth/secrets, scoring/evidence and safe jobs/changes; blocker/security log and development checklists.
- Reproducible Python 3.12 contract-validation environment, dependency lock and tests. See [validation record](phase0-validation.md).

## Independent consumer work

Apoorva can generate types/mocks from the proposed OpenAPI after reviewing the explicit differences. All UI data remains synthetic until connected to a verified backend. Vidhi can validate worker messages and normalized evidence using the self-contained JSON Schemas without importing API or Supabase. Neither consumer should assume live API routes or collector support exists. Mandar owns the API port and the contract generator.

Integration must compare identical schema_version and contract digest, run cross-consumer fixtures (including negative semantic cases), and verify permissions/tenant behavior with the real backend. Request/results must match job_id, scan_id, asset_id and org_id. Late or foreign worker results are rejected.

## Before Phase 1

Review proposed fact layout, coverage formula, exact route names, roles, idempotency and execution checks. Record all three approvals against the digest in freeze.json. Confirm repository/branch policy, original PS mapping, exact benchmark/source rights and test-lab inventory. Provision local Supabase/OpenBao only through the later foundation work; never put privileged secrets into examples or prompts.

Phase 0 authoring and local validation can be complete while these external review/access gates remain open. No release claim of 88/88 working features, no deployed Auth/RLS, no runtime performance claim and no vendor compatibility claim is made.
