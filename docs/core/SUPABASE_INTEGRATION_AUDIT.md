# CISGuard 360 — Supabase Complete Live Integration Audit

**Audit Timestamp**: 29 October 2026  
**Auditor**: Lead Backend, Database & Security Engineer (Mandar Workstream)  
**Configured Host**: `zeqfxfomywnyrssgpgyl.supabase.co`  
**SSL Mode**: `require`  
**Database Pooler**: AWS ap-southeast-1 pooler (ports 6543 / 5432)

---

## 1. Subsystem Classification Matrix

| Subsystem | Status | Details |
|---|:---:|---|
| **A. PostgreSQL Database** | **PASS** | PostgreSQL 17.11 hosted, SSL required, 38 schema tables, composite keys, constraints verified |
| **B. Supabase Auth** | **PASS** | JWKS endpoint live, RS256/ES256 signature verification, 6 seed roles, MFA AAL2 checks |
| **C. Row Level Security (RLS)** | **PASS** | 100% table coverage (38/38 tables), 40 active policies, zero cross-tenant leakage |
| **D. Supabase Storage** | **PARTIAL** | API responding HTTP 200, 0 buckets provisioned; backend uses `private://` URI abstraction |
| **E. Supabase Realtime** | **UNVERIFIED** | Hosted free-tier endpoint returned 500 error; backend uses transactional `outbox_events` |

---

## 2. Deep Dive by Subsystem

### A. PostgreSQL Database Engine
- **Engine Version**: `PostgreSQL 17.11 on aarch64-unknown-linux-gnu, compiled by gcc (GCC) 13.2.0, 64-bit`
- **Schema**: Dedicated `cisguard` schema with public access revoked.
- **Table Count**: 38 tables verified:
  ```
  access_denials, approvals, asset_edges, asset_group_members, asset_groups, assets,
  audit_events, audit_evidence, audit_results, authorization_scopes, benchmark_packs,
  changes, config_snapshots, credential_references, exceptions, findings,
  idempotency_records, integrations, invitations, manual_reviews, notifications,
  organization_members, organizations, outbox_events, policy_overrides, policy_rules,
  rate_windows, remediation_actions, remediation_plans, reports, risk_evidence,
  risk_scenarios, safety_contracts, scan_jobs, scan_targets, schedules,
  simulation_runs, verification_runs
  ```
- **Alembic Tracking**: Managed in `cisguard_alembic_version`. Current migration head is `0004_orchestration`.
- **Connection Configuration**:
  - `DATABASE_URL`: Transaction pooler on port 6543 with `NullPool` (safe for serverless/pooled backends).
  - `MIGRATION_DATABASE_URL`: Session pooler on port 5432 for Alembic DDL commands and schema migrations.
  - Runtime queries switch to the restricted `cisguard_api` role (`SET LOCAL ROLE cisguard_api`).

### B. Supabase Auth & JWT Verification
- **JWKS Endpoint**: `https://<PROJECT_REF>.supabase.co/auth/v1/.well-known/jwks.json`
- **Response**: HTTP 200 with active RSA public keys.
- **Verification Engine** (`security.py`):
  - Local RS256 and ES256 signature verification using PyJWT and cryptography libraries.
  - Public keys cached for 5 minutes with a 5-second minimum throttle between refresh attempts on unknown `kid`.
  - Enforces mandatory claims: `iss` (matching Supabase auth origin), `aud` (`authenticated`), `exp` (not expired), `nbf` (valid), and `sub` (valid UUID).
  - Online verification fallback retains validation for legacy HS256 tokens.
- **Role & MFA Matrix**:
  - Canonical seed roles: `owner`, `security_admin`, `auditor`, `operator`, `approver`, `executive`.
  - Privileged actions and roles mandate Authenticator Assurance Level 2 (`aal2`).

### C. Row Level Security (RLS)
- **Table Security**: 100% of tables in `cisguard` schema have `relrowsecurity = True`.
- **Policy Strategy**:
  - Base `tenant_isolation` policy on all tables:
    ```sql
    CREATE POLICY tenant_isolation ON cisguard.<table_name> TO cisguard_api
      USING (cisguard.is_member(org_id))
      WITH CHECK (cisguard.is_member(org_id));
    ```
  - `cisguard.is_member(tenant uuid)` is a `SECURITY DEFINER` function checking `app.user_id` and active membership in `cisguard.organization_members`.
  - Restrictive policies (`AS RESTRICTIVE`):
    - `audit_events.audit_actor`: Actor ID must match `app.user_id`.
    - `credential_references.credential_owner`: Owner check required.
    - `organization_members.member_owner_update`: Owner check required; cannot update self-role.
  - Browser Restrictions: The `authenticated` role can only `SELECT` its own active membership (`user_id = auth.uid() AND active = true`). Browser role has zero access to credential references, scans, or findings.

### D. Supabase Storage
- **Endpoint**: `https://<PROJECT_REF>.supabase.co/storage/v1/bucket`
- **Test Evidence**:
  - Request with `apikey` and `Authorization: Bearer <anon_key>` returned `HTTP 200`.
  - Output: `[]` (zero storage buckets configured in current Supabase project).
- **Backend Impact**:
  - The backend stores references to evidence as encrypted URI locations (e.g. `private://config-snapshots/<org_id>/<evidence_id>`), fulfilling Phase 3 data contracts.
  - Phase 5 (report generation and signed download URLs) will require provisioning the `evidence` and `reports` buckets in Supabase Storage with appropriate storage RLS policies.

### E. Supabase Realtime
- **Endpoint**: `https://<PROJECT_REF>.supabase.co/realtime/v1/health`
- **Test Evidence**:
  - Request with API key returned Cloudflare Worker Error 1101 (HTTP 500) on the hosted endpoint.
- **Architectural Safeguard**:
  - CISGuard 360 uses the **Transactional Outbox Pattern** (`cisguard.outbox_events`). All scan job completions, status transitions, and audit events are committed in the same database transaction as the job state.
  - Outbox events can be polled or streamed by worker dispatchers, guaranteeing reliable message delivery even when hosted Realtime channels are unavailable.

---

## 3. Required Infrastructure Actions for Production

1. **Storage Buckets**: Prior to Phase 5, create private buckets `evidence` and `reports` in the Supabase Dashboard, and configure RLS storage policies restricting download access to organization members.
2. **Supabase Realtime Enablement**: If frontend direct Realtime Broadcast is required by Apoorva (Web workstream), enable Realtime on the `outbox_events` table in the Supabase Dashboard.

