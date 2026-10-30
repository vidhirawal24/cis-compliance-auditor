# CISGuard 360 — Phase 10 Integration & Collaborator Handoff Package

**Workstream:** Mandar (Lead Backend + Database + Auth + Core Algorithms)  
**API & Worker Interface Version:** `1.0.0` (Frozen Contract)  
**Target Collaborators:** Apoorva (`apps/web`), Vidhi (`services/device-engine`)  
**Database Schema Head:** `0007_plans_changes_proof`  
**Automated Test Suite:** 365 Tests Passed (100% Pass Rate across Unit, Security, Hypothesis, and Live Integration)

---

## 1. Collaborator Interface Overview & Version Freeze

All API communication, payloads, and worker message queues strictly conform to **Contract v1.0.0** (`packages/contracts/v1`):

- **Base HTTP Prefix:** `/api/v1`
- **Authentication:** Supabase Auth Bearer JWT tokens (`Authorization: Bearer <token>`) passed with `X-Org-Id: <uuid>` tenant context.
- **Resource Envelope:**
  ```json
  {
    "schema_version": "1.0.0",
    "data": { ... },
    "meta": { "request_id": "<uuid>" }
  }
  ```
- **Error Response Envelope:**
  ```json
  {
    "code": "ERROR_CODE_STRING",
    "message": "Human readable message",
    "request_id": "<uuid>",
    "details": {},
    "retryable": false
  }
  ```
- **Execution States:** `DRAFT` $\to$ `SIMULATED` $\to$ `PRECHECKED` $\to$ `PENDING_APPROVAL` $\to$ `APPROVED` $\to$ `EXECUTING` $\to$ `VERIFYING` $\to$ `VERIFIED` / `FAILED` / `ROLLED_BACK`.

---

## 2. Mock Device Engine & Port Architecture (For Mandar & Apoorva)

Because Vidhi owns `services/device-engine`, Mandar's backend uses a decoupled port adapter:
- **Location:** `apps/api/cisguard_api/device_port.py`
- **Local Development / Mock Server:** `apps/api/cisguard_api/mock_engine.py` (served via Docker Compose on port `8090`).
- **Fixture Fallback Mode:** When live device connectivity is not yet established, the worker utilizes synthetic offline fixtures (`offline_fixture`) to perform deterministic CIS benchmark rule evaluation without fabricating success on real hardware.

---

## 3. Local Environment Setup & Docker Compose Guide

### 3.1 Prerequisites
- Docker & Docker Compose
- Python 3.12+ (if running API locally outside container)
- Access to Supabase PostgreSQL instance (configured in `apps/api/.env`)

### 3.2 Running the Full Infrastructure
From the project root:
```bash
docker compose -f infra/docker-compose.yml up -d
```
Services launched:
1. `api`: FastAPI REST API on `http://127.0.0.1:8000`
2. `worker`: Celery background job executor connected to Redis
3. `redis`: Redis broker on port `6379` (mapped to `6380` on Windows host)
4. `mock-device-engine`: Synthetic adapter service on port `8090`
5. `postgres` (optional profile): Local PostgreSQL on port `54322`

### 3.3 Database Migration Order
Alembic migrations must be executed in order:
```bash
cd apps/api
alembic upgrade head
```
Revisions applied:
- `0001_initial`: Core organizations, users, assets, scopes, credential references.
- `0002_rls_policies`: Supabase RLS policies and tenant boundaries.
- `0003_openbao_secrets`: OpenBao secret reference bindings.
- `0004_policy_engine`: Benchmark packs, rules, overrides, exceptions, manual reviews.
- `0005_scap_importer`: SCAP/XCCDF XML import staging tables.
- `0006_reports_findings`: Canonical findings, trends, notifications, audit events.
- `0007_plans_changes_proof`: Remediation plans, CP-SAT actions, safety contracts, approvals, changes, verification runs, drift events.

---

## 4. Contract Schema & Fixture Registry

All JSON schemas and sample fixtures are published and verified:
- **OpenAPI Specification:** `docs/core/phase7-9-openapi.json` and `packages/contracts/v1/openapi.yaml`
- **JSON Schemas:** `packages/contracts/v1/json-schemas/` (44 schemas including `Scan.schema.json`, `Finding.schema.json`, `Plan.schema.json`, `Proof.schema.json`).
- **Sanitized Fixtures:** `packages/contracts/v1/examples/` (sanitized sample payloads for every contract model).

---

## 5. Collaborator Merge Sequence (Post-Phase 10)

```
Step 1: Mandar exports stable contracts/v1 and OpenAPI (COMPLETED).
Step 2: Vidhi installs services/device-engine as an editable Python package inside Mandar's worker environment.
Step 3: Mandar wires live device engine calls into worker Celery tasks, replacing synthetic fixture fallback.
Step 4: Apoorva points frontend typed API client (apps/web) to FastAPI endpoints with Supabase JWT bearer tokens.
Step 5: End-to-end acceptance run: login -> asset onboarding -> scan job -> findings -> graph -> CP-SAT plan -> approval -> execution -> verification -> signed proof dossier.
```

