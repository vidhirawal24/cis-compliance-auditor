# ADR 0001: Single versioned contract and review gate

Status: proposed for three-owner approval. References: playbook contract v1; PRD pp17,19.

`packages/contracts/v1/models.py` and `route_catalog.py` are the source of truth for generated OpenAPI 3.1 and JSON Schema 2020-12. Consumers may generate their own language types but must not hand-maintain alternative wire schemas. `generate.py --check` detects drift. Pydantic validates semantic relationships that JSON Schema alone cannot express; worker consumers must implement the same invariants and pass shared fixtures.

HTTP prefix `/api/v1`; Supabase access token in Authorization Bearer. Require `X-Org-ID`, validated against active membership; for organization paths it must equal the path tenant. `/organizations` lists only memberships; creating a tenant requires a provisioned owner context in v1. First-owner bootstrap is an out-of-band administrative process to define in Phase 1, never a public role assignment endpoint.

Success: `{schema_version: '1.0.0', data, meta: {request_id}}`. Lists wrap `{items, next_cursor}` in data. Errors use the unwrapped `{code, message, request_id, details?, retryable}`. The backend generates correlation IDs. Request IDs are UUIDs. Dates use UTC ISO8601 ending Z. All documented IDs are UUID strings. Tenant membership is required even when an ID is unguessable.

Cursor pagination: default 50, maximum 100; opaque cursor binds org/filter/sort and expires. Order by `(created_at, id)` or equivalent immutable stable tuple; reject changed filters or foreign cursors. Unknown filter keys return validation error. `/policies/{id}/diff` requires both version query parameters. Literal `/scans/schedules` and `/assets/discover` routes must be registered before parameter routes.

Non-GET requests require Idempotency-Key. Scope keys by org, actor, method and canonical route; persist body hash plus result for at least 24 hours (proposed operational setting). Same key/body returns the original result; changed body returns CONFLICT. Execution deduplication must survive that window by durable action IDs and checkpoints. Async endpoints return 202 with status/read identifiers; a SUCCEEDED job is orchestration completion, not a compliance PASS.

Semantic version policy: patch for documentation/validation corrections with unchanged accepted wire shapes; minor for compatible optional additions only after three-owner review; major for changed required fields, enum meanings, removals or incompatible schema restrictions. Because v1 models reject unknown fields, adding even an optional output field needs consumer compatibility tests and coordinated rollout; otherwise use v2. Version field must match negotiated schema, not silently auto-upgrade. Keep old audits/evidence tied to their original schema/evaluator/policy versions.

Freeze record starts PROPOSED. Mandar, Apoorva and Vidhi each record review reference, date and exact contract digest. Only then mark AGREED. Do not manufacture approvals or announce integration readiness from unit tests.
