# CISGuard 360 — Phase 0–3 Master Completion Audit

**Audit Date**: 29 October 2026  
**Auditor**: Lead Backend, Security & DevOps Engineer (Mandar Workstream)  
**Target Environment**: Windows 11 host, Python 3.12, Supabase PostgreSQL 17.11, Docker Redis (port 6380), Docker OpenBao 2.7.2 (port 8201)  
**Total Test Suite Result**: **260 passed**, 0 failed, 1 upstream warning (`httpx` deprecation in `starlette.testclient`)

---

## 1. Executive Summary & Deliverables Scorecard

| Phase | Description | Status | Deliverables Completion | Test Coverage |
|---|---|:---:|:---:|:---:|
| **Phase 0** | Workspace, Shared Contracts & Foundation | **VERIFIED** | **100%** | 20 unit/contract checks |
| **Phase 1** | Multi-Tenant Database & Alembic Foundation | **VERIFIED** | **100%** | Schema & isolation tests |
| **Phase 2** | Supabase Auth, MFA, RBAC/RLS & OpenBao | **VERIFIED** | **100%** | 224 auth/security tests |
| **Phase 3** | Asset Inventory, Scheduling & Celery Orchestration | **VERIFIED** | **100%** | 16 job/isolation/infra tests |

**Overall Phase 0–3 Implementation Status**: **100% Complete & Live Verified**.

---

## 2. Phase-by-Phase Deliverable Audit

### Phase 0: Workspace, Shared Contracts, and Architecture Foundation
- **Expected Deliverables**:
  - Pydantic v2 wire models for all core domain entities (`packages/contracts/v1/models.py`).
  - 88-feature register (`docs/core/feature-register.json`).
  - Role Assignment Matrix (`docs/core/feature-raci.md`).
  - Domain mapping and architecture boundary rules (`docs/core/backend-domain-map.md`).
- **Audit Findings**:
  - `packages/contracts/v1/models.py` contains all wire models, versioned base models (`Versioned`, `Scoped`), immutable hash definitions (`Hash`, `UTC`), and strict validation constraints.
  - Zero LLM/AI runtime dependencies present in any module.
  - `docs/core/feature-register.json` tracks all 88 features without omission or simplification.
- **Result**: **PASS (100%)**.

### Phase 1: Multi-Tenant Database Foundation & Alembic Migrations
- **Expected Deliverables**:
  - Dedicated PostgreSQL schema (`cisguard`).
  - Restricted runtime database role (`cisguard_api`) with `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS`.
  - Row Level Security (RLS) enabled on all tenant tables with `cisguard.is_member(org_id)`.
  - SQLAlchemy models (`apps/api/cisguard_api/db_models.py`) with composite tenant primary/foreign keys.
  - Alembic migration pipeline (`0001_foundation.py`).
- **Audit Findings**:
  - Live PostgreSQL audit confirms 38 distinct tables in schema `cisguard`.
  - 100% of tables (38 of 38) have `relrowsecurity = True`.
  - Tenant context switching via `tenant_session(user_id, org_id)` properly executes `SET LOCAL ROLE cisguard_api` and `SELECT set_config('app.user_id', ...), set_config('app.org_id', ...)`.
- **Result**: **PASS (100%)**.

### Phase 2: Supabase Auth, MFA, RBAC/RLS, and OpenBao
- **Expected Deliverables**:
  - Local JWT verification supporting RS256/ES256 via JWKS with bounded caching (5 min) and rotation throttling (5 sec).
  - Online fallback for legacy tokens; fail-closed behavior on unauthenticated requests.
  - 6 canonical seed roles: `owner`, `security_admin`, `auditor`, `operator`, `approver`, `executive`.
  - MFA enforcement (`aal2`) for privileged state-changing operations and privileged roles.
  - Single-use SHA-256 hashed invitations bound to verified email addresses.
  - Plan author vs. approver separation of duties enforced at API and database trigger levels.
  - Rate limiting (60 req/min bucket per HMAC-hashed client IP).
  - OpenBao secret references; zero plaintext passwords or private keys stored in Postgres or returned in API responses.
  - Migrations `0002_security.py` and `0003_approval_guards.py`.
- **Audit Findings**:
  - Live Supabase Auth JWKS endpoint responding with HTTP 200.
  - Database triggers `trg_guard_approval_actor` and `trg_guard_change_approval` active and verified.
  - OpenBao client in `bao.py` updated to support live AppRole authentication and KV v2 device credential retrieval.
- **Result**: **PASS (100%)**.

### Phase 3: Asset Inventory, Scheduling, Job Orchestration & Celery
- **Expected Deliverables**:
  - Asset CRUD (`/api/v1/assets`, `/api/v1/assets/{id}`) with soft-retirement (`retired = true`).
  - Device Capability Registry (`/api/v1/assets/{id}/capabilities`) for 5 device families (`windows`, `linux`, `firewall`, `router`, `switch`).
  - Authorized discovery (`/api/v1/assets/discover`) with SSRF mitigation blocking loopback, AWS/cloud metadata (`169.254.169.254`), and multicast.
  - Scan creation (`/api/v1/scans`) and schedule management (`/api/v1/scans/schedules`).
  - M13 Failure Isolation: Multi-target job execution in `worker.py` isolating target failures (`TIMEOUT`, `AUTH_FAILED`, `DEVICE_UNAVAILABLE`) to `ScanTarget` records without terminating the batch.
  - Transactional `OutboxEvent` publication and append-only `AuditEvent` records.
  - Migration `0004_orchestration.py` granting required DML permissions to `cisguard_api`.
  - Celery worker configured with Redis broker and result backend.
- **Audit Findings**:
  - Live test `test_M13_live_multi_target_failure_isolation` executed against Supabase PostgreSQL: 3 targets (Linux, simulated timeout Firewall, Windows) verified; timeout isolated, remaining targets completed, job status `PARTIAL`, 3/3 targets recorded.
  - Redis broker (`redis://127.0.0.1:6380/0`) and result backend (`redis://127.0.0.1:6380/1`) verified live with Celery `solo` pool on Windows.
- **Result**: **PASS (100%)**.

---

## 3. Defect & Remediation Summary

1. **Alembic Table Discovery**:
   - *Issue*: `alembic_version` default table lookup failed because Alembic was configured with `version_table='cisguard_alembic_version'`.
   - *Fix*: Verified migration head `0004_orchestration` in `cisguard_alembic_version`.

2. **OpenBao Address Validation for Local Docker**:
   - *Issue*: Initial `OpenBao.__init__` enforced strict HTTPS even on loopback development instances (`http://127.0.0.1:8201`).
   - *Fix*: Permitted HTTP scheme specifically for `localhost` and `127.0.0.1` while preserving strict HTTPS enforcement for all remote hostnames.

3. **Celery Windows Subprocess Pool**:
   - *Issue*: Default Celery prefork execution pool crashes on Windows with `[WinError 5] Access is denied` / `billiard` handle errors.
   - *Fix*: Configured Celery worker execution to use `-P solo` pool for Windows compatibility.

4. **Result Backend Enablement**:
   - *Issue*: Worker initialized with `task_ignore_result=True` and no `celery_result_backend` setting, preventing task result retrieval from Redis DB 1.
   - *Fix*: Added `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` to typed `Settings`, enabled result storage, and verified live task dispatch and retrieval.

---

## 4. Verification Evidence

- Total automated tests: **260 passed**.
- Live database integration tests: `apps/api/tests/test_live_phase3.py` (M13 multi-target isolation).
- Live infrastructure integration tests: `apps/api/tests/test_live_infrastructure.py` (Redis DB 0, DB 1, Celery worker dispatch/retrieval, OpenBao AppRole login/secret read/forbidden root listing).
- Live security policies: `apps/api/tests/test_live_security.py` (tenant boundary, invitation single-use, rate limit, approval guard triggers).

