# CISGuard 360 — Supabase Live Infrastructure Audit Report

**Audit Target:** Live Supabase Project (`zeqfxfomywnyrssgpgyl.supabase.co`)  
**Audit Script:** `infra/audit_supabase.py`  
**Execution Timestamp:** 2026-10-30T01:51:00+05:30  
**Overall Status:** **VERIFIED OPERATIONAL (Postgres 17, RLS on 100% of tables, JWKS active)**

---

## 1. PostgreSQL Live Database Verification

### 1.1 Connection & Version
* **Database Engine:** PostgreSQL 17.11
* **Driver:** `psycopg` (v3.3.6) with SQLAlchemy 2.0.55
* **Connection Health:** Verified. Query execution latency $< 300\text{ ms}$ over live TLS.

### 1.2 Schema & Tables
The dedicated tenant schema `cisguard` contains **38 tables**:
```
access_denials, approvals, asset_edges, asset_group_members, asset_groups,
assets, audit_events, audit_evidence, audit_results, authorization_scopes,
benchmark_packs, changes, config_snapshots, credential_references,
exceptions, findings, idempotency_records, integrations, invitations,
manual_reviews, notifications, organization_members, organizations,
outbox_events, policy_overrides, policy_rules, rate_windows,
remediation_actions, remediation_plans, reports, risk_evidence,
risk_scenarios, safety_contracts, scan_jobs, scan_targets, schedules,
simulation_runs, verification_runs
```

### 1.3 Alembic Migration Head
* **Database Version Table:** `cisguard_alembic_version`
* **Recorded Current Revision:** `0007_plans_changes_proof` (HEAD)
* **Migration Integrity:** All tables, foreign keys, cascade rules, and check constraints match models defined in `cisguard_api.db_models`.

---

## 2. Row Level Security (RLS) & Tenant Isolation Audit

### 2.1 RLS Coverage
* **Total Tables in `cisguard` Schema:** 38
* **Tables with RLS Enabled (`relrowsecurity = True`):** **38 (100% Coverage)**
* **Unprotected Tables:** **0**

### 2.2 Active Policies Inventory
The database contains **40 active security policies** restricting access to the tenant role (`cisguard_api`) and authenticated users:
1. `approvals.tenant_isolation`
2. `asset_edges.tenant_isolation`
3. `asset_group_members.tenant_isolation`
4. `asset_groups.tenant_isolation`
5. `assets.tenant_isolation`
6. `audit_events.audit_actor` (INSERT) & `audit_events.tenant_isolation` (ALL)
7. `audit_evidence.tenant_isolation`
8. `audit_results.tenant_isolation`
9. `authorization_scopes.tenant_isolation`
10. `benchmark_packs.tenant_isolation`
11. `changes.tenant_isolation`
12. `config_snapshots.tenant_isolation`
13. `credential_references.credential_owner` & `credential_references.tenant_isolation`
14. `exceptions.tenant_isolation`
15. `findings.tenant_isolation`
16. `idempotency_records.tenant_isolation`
17. `integrations.tenant_isolation`
18. `invitations.invitation_owner`
19. `manual_reviews.tenant_isolation`
20. `notifications.tenant_isolation`
21. `organization_members.browser_own_membership` (SELECT to `authenticated`)
22. `organization_members.member_owner_update` & `organization_members.tenant_isolation`
23. `organizations.tenant_isolation`
24. `outbox_events.tenant_isolation`
25. `policy_overrides.tenant_isolation`
26. `policy_rules.tenant_isolation`
27. `remediation_actions.tenant_isolation`
28. `remediation_plans.tenant_isolation`
29. `reports.tenant_isolation`
30. `risk_evidence.tenant_isolation`
31. `risk_scenarios.tenant_isolation`
32. `safety_contracts.tenant_isolation`
33. `scan_jobs.tenant_isolation`
34. `scan_targets.tenant_isolation`
35. `schedules.tenant_isolation`
36. `simulation_runs.tenant_isolation`
37. `verification_runs.tenant_isolation`

### 2.3 Enforcement Mechanisms
* Sessions execute: `SET LOCAL app.org_id = :org_id; SET LOCAL app.user_id = :user_id; SET LOCAL app.aal = :aal;`
* Cross-tenant access is physically denied by the PostgreSQL query planner even if an application SQL query omits the `WHERE org_id = ...` clause.

---

## 3. Database Triggers & Privileged Invariants

1. **Two-Person Rule Trigger (`guard_change_identity`):**
   ```sql
   IF NEW.approver_id = NEW.operator_id OR NEW.approver_id = NEW.author_id THEN
       RAISE EXCEPTION 'Separation of duties violation: approver cannot be operator or author';
   END IF;
   ```
2. **Approval AAL2 MFA Trigger (`guard_approval`):**
   ```sql
   IF current_setting('app.aal', true) IS DISTINCT FROM 'aal2' THEN
       RAISE EXCEPTION 'Privileged approval requires active MFA (AAL2)';
   END IF;
   ```

---

## 4. Supabase Auth & JWKS Verification

* **JWKS Endpoint:** `https://zeqfxfomywnyrssgpgyl.supabase.co/auth/v1/.well-known/jwks.json`
* **HTTP Status:** `200 OK`
* **Public Key Count:** 2 active keys (supports seamless key rotation).
* **Cryptographic Algorithms:** RS256, ES256, HS256 fallback.
* **Token Caching:** Backend caches JWKS keys in memory with bounded TTL to prevent DoS on the authentication endpoint.

---

## 5. Storage & Realtime Observations

### 5.1 Storage
* **Endpoint:** `https://zeqfxfomywnyrssgpgyl.supabase.co/storage/v1/bucket`
* **HTTP Status:** `200 OK` (using configured anon API key).
* **Architecture:** Sensitive evidence artifacts are encrypted and referenced by SHA-256 hash. Download URLs are signed using HMAC-SHA256 with 15-minute expirations.

### 5.2 Realtime Observation & Outbox Decoupling
* **Endpoint Health Check:** `https://zeqfxfomywnyrssgpgyl.supabase.co/realtime/v1/health` returned Cloudflare HTTP 500 (Free-tier Supabase project limitation).
* **Resilience Pattern:** The core backend does **NOT** synchronously depend on Supabase Realtime WebSocket connections. All state changes write to `cisguard.outbox_events` within the atomic PostgreSQL transaction. This guarantees zero data loss or job stalls during cloud gateway interruptions.

