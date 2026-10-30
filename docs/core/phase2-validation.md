# Phase 2 validation

29 October 2026, Python 3.12 on Windows.

- Supabase connectivity & live PostgreSQL security policies: passed against live database instance.
- Alembic migrations: `0002_security` and `0003_approval_guards` applied; database at head (`0003_approval_guards`).
- Total test results: **248 passed** (246 unit/contract/HTTP security tests + 2 live database security and tenant-isolation tests). One upstream Starlette/httpx deprecation warning.
- JWT verification: RS256/ES256 JWKS key fetching, bounded 5-minute cache with 5-second rotation throttling, algorithm allowlisting, signature validation, expiry and not-before checks, legacy fallback to Supabase Auth online validation.
- RBAC and membership: 6 canonical seed roles (`owner`, `security_admin`, `auditor`, `operator`, `approver`, `executive`) enforced in backend. User cannot alter own role. Invitations are single-use SHA-256 hashed tokens tied to verified email addresses and organization IDs.
- MFA enforcement: `aal2` required for privileged roles and state-changing operations. `/me/mfa` accessible at `aal1` for step-up guidance.
- Separation of duties: Approvals enforce plan authorship separation both at API layer and via PostgreSQL database triggers. Plan author cannot approve their own changes.
- Row-Level Security (RLS): Strict tenant boundaries and browser-role restrictions. Browser authenticated role can SELECT only own active membership record; cannot mutate memberships or read credential references.
- Secrets governance: OpenBao references only. Device credentials and SSH keys are never accepted or returned in API payloads or stored in Postgres.
- Rate limiting: PostgreSQL-backed HMAC-hashed client IP rate limiter (60 req/min burst bucket), failing closed on database error.
- Audit trail: Append-only audit logging for successful operations with user, tenant, resource, and request IDs; access denials recorded with categorized codes in private audit table. Sanitized records with zero secret leakage.

Run all tests including live PostgreSQL security checks:

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

Exit gate status: Phase 2 deliverables verified. Live OpenBao deployment and production Supabase MFA end-user enrolment require authorized staging infrastructure.

