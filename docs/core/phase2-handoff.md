# Phase 2: Auth, permissions and secret boundaries

Prepared 29 October 2026. Scope: E15-E19 and the relevant SEC controls. Read the final validation record alongside this handoff. Feature-level completion is not inferred from passing unit tests.

## Implemented

- JWT verification: fixed Supabase issuer/origin, authenticated audience/role, required subject/iat/expiry, expiration/not-before checks, RS256 and ES256 signatures via JWKS, algorithm/key-type checks, unknown-key refresh with five-second throttling, five-minute local cache and online user validation. Legacy HS256 signatures are checked by Supabase Auth, never using the anon key as a signing secret. Online validation fails closed on provider outage. Supabase edge caching still affects emergency key revocation; deployment cache restart is available for immediate local refresh.
- The six seed roles and permissions come directly from `packages/contracts/v1/permissions.json`: owner, security_admin, auditor, operator, approver, executive. No browser metadata or token custom role grants organization privileges. Active organization membership is rechecked in the backend, with explicit tenant predicates even when the configured SQL login is privileged. Owner has no automatic approval/execution power.
- aal2 is required for privileged roles and changes. `/me/mfa` remains readable by an active aal1 member to support step-up. MFA enrollment/challenge stays in Supabase Auth; this backend does not implement or store TOTP seeds.
- Membership administration forbids self-role changes and serializes updates per organization. Invitation tokens are generated once, stored only as SHA-256 hashes, expire in 24 hours and require the exact verified email, tenant and (for privileged roles) aal2. Acceptance is row-locked and single-use. Duplicate membership cannot silently escalate privileges. Invitations are returned for manual delivery; no email was sent.
- Approval API and SQL triggers verify actor identity, actual plan author, exact plan hash, expiry and approver role/MFA. Change inserts require a matching unexpired approval independent of the operator and author. This does not implement device execution or replace the later simulation/precheck gates.
- Success events record tenant, actor, resource and request ID in append-controlled audit rows. Denial records store request ID, category and timestamp in a private table. No tokens, passwords, invitation tokens or request bodies enter these audit records. Runtime can insert but cannot modify/delete audit history. Hash-chain signing remains a later proof-phase feature.
- Database-backed rate limiting allows 60 authenticated-request attempts per direct client IP per fixed minute across API instances; IPs are HMAC-hashed. Forwarded headers are not trusted. Configure ingress accordingly; users behind one NAT share a bucket. Rate-limit storage failures fail closed. Requests missing a Bearer header are rejected immediately; ingress-level connection/unauthenticated flood protection remains deployment responsibility.
- Credential endpoints accept only a label and generate tenant-scoped opaque references. OpenBao secret values are accessible only through the worker connector with an exact org/reference token scope. No browser secret-read route exists. Runtime database access cannot enumerate another tenant's secrets.

## Routes

| Method | Route | Authorization |
|---|---|---|
| GET | /api/v1/me, /api/v1/auth/session | Active membership and role MFA policy |
| GET | /api/v1/me/permissions | Current member's seeded permissions |
| GET | /api/v1/me/mfa | Active membership, including before step-up |
| GET | /api/v1/organizations/{org_id}/members | Owner + aal2, signed tenant-bound cursor |
| PATCH | /api/v1/organizations/{org_id}/members/{user_id} | Owner + aal2, never self |
| POST | /api/v1/organizations/{org_id}/invitations | Owner + aal2 |
| POST | /api/v1/invitations/{id}/accept | Verified identity/email and one-use token |
| POST | /api/v1/credential-references | Owner + aal2; vault provisioning is separate |
| POST | /api/v1/approvals | Approver + aal2, independent of author |

All tenant routes require X-Org-ID. Responses use the v1 envelope/errors. The Phase 0 shared contract remains proposed; new security route definitions are a reviewable extension. Mutation retry semantics are currently single-use invitation acceptance or explicit conflict checks; general Idempotency-Key response replay from the Phase 0 proposal is not yet implemented for these new endpoints. Consumers must not blindly retry creation calls.

## Database and frontend boundary

Applied revisions: `0002_security` and `0003_approval_guards`, following `0001_foundation`. New functions use fixed search paths and explicit execute grants; PUBLIC access is revoked. Restrictive owner/update/actor policies intersect the original tenant policy instead of widening it through permissive OR conditions.

The Supabase authenticated browser role can SELECT only its own active membership columns. It cannot mutate membership or read credential references. Other domain data remains backend-only; no broad frontend grants or automatic PostgREST schema exposure were enabled. If the team enables the private schema in Supabase's Data API configuration, these database restrictions still apply. Frontend code was not created or modified.

The administrator connection still exists in the ignored backend environment; API transactions SET LOCAL ROLE to the restricted runtime role. The session context (`app.user_id`, tenant, aal, verified email) is trusted only because backend verification sets it; never distribute that SQL login to browsers. Provision a separate restricted login for production. SQL administrators necessarily remain privileged and are outside RLS's protection boundary.

## OpenBao and external gates

See `infra/openbao/README.md` and the exact-path policy template. No OpenBao address/CA/worker AppRole credentials were supplied, so live vault login, TLS deployment, token rotation and actual device-secret retrieval remain unverified. Tests use clearly synthetic HTTP fixtures. Do not place root tokens in the API environment. A real authorized worker dispatcher must issue/revoke short-lived path-scoped tokens; the application does not claim to have deployed that external lifecycle.

Supabase database policies were tested live using rolled-back synthetic records. No test users, email invitations or device credentials were created in Supabase Auth. Real end-to-end sign-in/MFA enrollment and deployed ingress behavior require authorized test identities and deployment validation. The service-role key remains blank and is not needed for this implementation.

## Run and test

Use the Phase 1 environment and existing ignored `.env`:

```powershell
& infra/.venv-phase0/Scripts/python.exe -m alembic -c apps/api/alembic.ini current
& infra/.venv-phase0/Scripts/python.exe -m uvicorn cisguard_api.main:app --host 127.0.0.1 --port 8000
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

Without the opt-in, database integration tests skip. Unit HTTP audit persistence is stubbed so ordinary unit tests never write to live storage. Live tests explicitly exercise the actual database functions/policies and roll back fixtures. Seed role definitions are the existing canonical role matrix, not invented Supabase accounts.

References: [Supabase signing keys and cache behavior](https://supabase.com/docs/guides/auth/signing-keys), [OpenBao AppRole](https://openbao.org/docs/auth/approle/), [OpenBao policy controls](https://openbao.org/docs/concepts/policies/).
