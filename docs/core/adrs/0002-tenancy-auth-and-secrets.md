# ADR 0002: Tenant isolation and privilege boundaries

Status: proposed implementation design. References: PRD SEC-01 through SEC-12; stack pp3,8-9.

Validate JWT signature with an explicit algorithm allowlist, configured Supabase issuer/audience, expiration and not-before; use bounded cached JWKS and reject unknown key IDs after controlled refresh. Do not trust role/user metadata supplied by the browser. Resolve active membership and scoped permissions in the backend. Require aal2 for owner, security_admin, operator and approver. Logout/revocation and stale membership checks need Phase 1 integration tests.

The exact role matrix is `packages/contracts/v1/permissions.json`. The executive role sees aggregate trends only until an aggregate-only report view is implemented. Technical downloads require report.export. An owner cannot bypass change approval. Plan author, approver and executing operator must meet separation-of-duties policy; an actor holding several roles still cannot self-approve.

Enable RLS on every client-visible tenant table, with USING and WITH CHECK membership policies. Use composite `(org_id, id)` references on related rows to prevent cross-tenant joins. Browser clients never receive service-role keys. Backend service-role use is narrowly scoped because it bypasses RLS: explicit tenant predicates, resource ownership and permission checks remain mandatory. A scoped Postgres role/context is preferred for ordinary queries. Test read/write/delete, RPC, storage and Realtime isolation for two tenants in Phase 1.

OpenBao stores privileged secrets. Contracts carry opaque `credential_reference_id`, not vault payloads. Evidence artifacts are encrypted before upload; private storage metadata includes sha256 and tenant prefix. Artifact URLs are short-lived, scoped and issued only after authorization. Browser API bodies and worker messages must not include passwords, keys, raw access tokens or free-form commands. `JsonValue` fact/expected/observed fields are redacted structured data; schema validation cannot discover semantic secrets. Collection sanitization and log redaction remain mandatory runtime controls.

Reject SSRF targets and webhook destinations outside explicit scope, including link-local/cloud metadata and loopback except approved local deployments; resolve DNS securely and recheck redirects/resolution before connection. Never accept a request URL as proof of authorization. Discovery CIDRs must be canonicalized and intersected with approved ranges. Strict TLS and SSH host-key verification are defaults.

Append-controlled audit events include actor, organization, resource, request ID, UTC time and hash chain. Encrypt sensitive backups, enforce retention, verify manifest signatures with rotated key IDs, and export sanitized summaries. A hash chain does not alone prove tamper resistance against an unrestricted database administrator; signing and restricted writers are required.

Phase 0 validates shapes and negative semantic cases only. No JWT verifier, RLS migration, secret vault, encryption or production security guarantee is claimed.
