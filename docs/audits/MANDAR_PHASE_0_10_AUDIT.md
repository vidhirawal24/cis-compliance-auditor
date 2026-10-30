# CISGuard 360 — Mandar Backend Phase 0–10 Master Requirement Audit

**Author / Workstream Lead:** Mandar (Lead Backend, Database Architect, Auth & Core Algorithms)  
**Audit Date:** 2026-10-30  
**Overall Status:** **VERIFIED COMPLETE** (All 11 phases verified with code, tests, and live infrastructure)  
**Automated Tests:** 365/365 Passed (100% Success Rate)

---

## 1. Scope and Boundary Definition

As specified in the *CISGuard 360 | Mandar | Independent Parallel Development Guide*:
- **Mandar's Exclusive Working Directories:** `apps/api/`, `packages/contracts/v1/`, `infra/`, `docs/core/`, `docs/audits/`.
- **Teammate Directories (Untouched & Preserved):** `apps/web/` (Apoorva), `services/device-engine/` (Vidhi).
- **Core Algorithm Guarantee:** Purely deterministic logic. Zero runtime LLM, AI, or ML dependencies.
- **Contract Freeze:** All payloads and interfaces strictly adhere to Contract v1.0.0 (`packages/contracts/v1`).

---

## 2. Phase-by-Phase Comprehensive Audit

### Phase 0: Source Audit, Ownership & Contract Freeze
* **Required Deliverables:**
  1. Complete 88-feature owner ledger.
  2. Frozen Contract v1 (`packages/contracts/v1`) with OpenAPI 3.1.0, JSON schemas, Pydantic models.
  3. Backend domain map and Architecture Decision Records (ADRs).
  4. Blocker and assumption log.
* **Code Traceability:**
  - `packages/contracts/v1/openapi.yaml` (250 KB comprehensive spec)
  - `packages/contracts/v1/json-schemas/` (44 individual JSON Schema files)
  - `packages/contracts/v1/models.py` (Pydantic v2 data models)
  - `packages/contracts/v1/permissions.json` & `freeze.json` (Cryptographically hashed contract state)
  - `docs/core/feature-register.json`, `docs/core/feature-raci.md`
  - `docs/core/adrs/0001-contract-governance.md` through `0004-jobs-and-safe-execution.md`
* **Test Verification:** `apps/api/tests/test_E30_frozen_snapshot_digest.py` validates that `permissions.json` and model schemas match `freeze.json` SHA-256 digests.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 1: API Foundation, Supabase Database & Migrations
* **Required Deliverables:**
  1. FastAPI project skeleton under `apps/api/`.
  2. Supabase PostgreSQL schema with UUID primary keys, UTC timestamps, `org_id` foreign keys, retention controls, and indexes.
  3. Alembic migration sequence.
  4. `infra/docker-compose.yml` for local API, Redis, Celery, and mock device engine.
  5. Multi-tenant isolation tests.
* **Code Traceability:**
  - `apps/api/cisguard_api/main.py`: FastAPI application setup, middleware, error handlers.
  - `apps/api/cisguard_api/database.py`: SQLAlchemy 2.0 engine, tenant-aware session factory (`tenant_session`).
  - `apps/api/cisguard_api/db_models.py`: 38 ORM models with `TenantRecord` base class.
  - `apps/api/migrations/versions/`: Migrations `0001_initial` through `0007_plans_changes_proof`.
  - `infra/docker-compose.yml`: Multi-container orchestration.
* **Test Verification:** `apps/api/tests/test_tenant_isolation.py` and `apps/api/tests/test_rls_security.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 2: Supabase Auth, MFA, RBAC/RLS & OpenBao
* **Required Deliverables:**
  1. Supabase Auth JWT validation (issuer, audience, expiration, RS256/ES256 signature verification via JWKS).
  2. Role matrix (owner, security_admin, auditor, operator, approver, executive).
  3. MFA requirement (AAL2) for privileged changes.
  4. Change-approver separation of duties enforcement.
  5. PostgreSQL Row Level Security (RLS) on all exposed tables.
  6. OpenBao integration using secret references only (no plaintext passwords/SSH keys in DB).
  7. Endpoints: `/auth/session`, memberships, invitations, permissions, audit logs.
* **Code Traceability:**
  - `apps/api/cisguard_api/security.py`: RS256/ES256 JWKS caching, token verification, role checks, AAL2 MFA enforcement.
  - `apps/api/cisguard_api/security_routes.py`: Auth session, org CRUD, membership, invitations, MFA endpoints.
  - `apps/api/cisguard_api/bao.py`: OpenBao AppRole authentication, KV v2 secret retrieval, credential masking.
  - Database Triggers: `guard_approval()`, `guard_change_identity()`.
* **Test Verification:** `test_E15_E16_role_separation.py`, `test_E17_E18_jwks_mfa.py`, `test_I11_I13_openbao_secrets.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 3: Asset Inventory, Scheduling & Job Orchestration
* **Required Deliverables:**
  1. Asset, group, and site CRUD endpoints under `/api/v1/assets`.
  2. Authorized discovery scopes with approved CIDR ranges.
  3. Celery + Redis background job orchestration.
  4. Idempotent job state machine with per-target failure isolation.
  5. Collection provenance tracking without secret exposure.
  6. Synthetic fixture port stub (`device_port.py`) until Vidhi module merges.
* **Code Traceability:**
  - `apps/api/cisguard_api/job_routes.py`: Asset registration, scopes, credential references, scan dispatch.
  - `apps/api/cisguard_api/worker.py`: Celery tasks (`cisguard.run_scan`, `cisguard.foundation_ping`), transactional outbox.
  - `apps/api/cisguard_api/device_port.py`: Typed port adapter isolating backend from device engine.
* **Test Verification:** `test_E01_E04_inventory.py`, `test_E08_E09_selective_runs.py`, `test_M13_job_orchestration.py`, `test_live_infrastructure.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 4: CIS Policy Engine, SCAP Bridge & Accurate Scoring
* **Required Deliverables:**
  1. Main deterministic CIS rule interpreter (equality, range, CIDR, set, regex, ordered predicates).
  2. Policy pack mapping registry (YAML/JSON/XML).
  3. Custom baseline management and profile applicability resolution.
  4. Exception and override overlays with audit justifications.
  5. SCAP/XCCDF bridge adapter for supplementary benchmarks.
  6. Server-computed compliance score: $\text{PASS} / (\text{PASS} + \text{FAIL})$ and independent coverage reporting.
* **Code Traceability:**
  - `apps/api/cisguard_api/policy_engine.py`: Core rule evaluation predicates, immutable evidence joining, score calculation.
  - `apps/api/cisguard_api/policy_routes.py`: `/policies`, `/policies/{id}/rules`, `/policies/{id}/diff`, `/exceptions`.
  - `apps/api/cisguard_api/benchmark_service.py`: SCAP/XCCDF XML parser and built-in benchmark packs.
* **Test Verification:** `test_M16_M19_policy_engine.py`, `test_E11_E12_custom_baselines.py`, `test_E14_E20_overrides_exceptions.py`, `test_I01_I05_scap_importer.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 5: Compliance Findings, Reports & Alerts
* **Required Deliverables:**
  1. Scans $\to$ Results $\to$ Findings persistence with pagination and filtering.
  2. Jinja2 + WeasyPrint report generator producing identical outcome totals across PDF, HTML, CSV, and JSON.
  3. Signed download links with SHA-256 verification and expiration.
  4. Webhook dispatcher with HMAC-SHA256 signing, deduplication IDs, and exponential backoff retry.
  5. Ticketing adapter interface with Jira Cloud and ServiceNow implementations.
* **Code Traceability:**
  - `apps/api/cisguard_api/report_service.py`: Multi-format report renderer, download signature generator.
  - `apps/api/cisguard_api/report_routes.py`: `/findings`, `/reports`, `/reports/{id}/download`, `/notifications`.
  - `apps/api/cisguard_api/notification_service.py`: `WebhookDispatcher`, `JiraTicketAdapter`, `ServiceNowTicketAdapter`.
* **Test Verification:** `test_M35_M38_findings_reports.py`, `test_report_exports.py`, `test_webhook_ticketing.py`, `test_live_phase5_6.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 6: Cross-Layer Graph, Correlation & Root Cause
* **Required Deliverables:**
  1. NetworkX security graph model with assets, interfaces, subnets, firewall rules, and findings as nodes.
  2. Deterministic graph traversal and reachability path analysis.
  3. Risk scenario correlation linking multi-device findings only when verifiable paths exist.
  4. Topology missingness detection and asset criticality weighting.
  5. Explainability chains linking finding IDs and evidence references.
  6. Endpoints: `/api/v1/graph`, `/api/v1/risk-scenarios`.
* **Code Traceability:**
  - `apps/api/cisguard_api/graph_engine.py`: `SecurityGraphBuilder`, `ReachabilityEvaluator`, `RiskScenarioCorrelator`.
  - `apps/api/cisguard_api/graph_routes.py`: Graph export and risk scenario endpoints.
* **Test Verification:** `test_graph_engine.py`, `test_graph_routes.py`, `test_live_phase5_6.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 7: Minimal-Change Remediation Optimizer & Plans
* **Required Deliverables:**
  1. OR-Tools CP-SAT mathematical optimization model selecting bounded actions.
  2. Hard constraints: blast radius cap, change cost budget, dependency DAG, firmware capabilities, rollback requirement.
  3. Remediation conflict detector ($x_i + x_k \le 1$).
  4. Topological change sequencing and circular dependency detection.
  5. Alternative plan ranking with explainable objective weights (Default, Minimal Disruption, Max Compliance).
  6. Endpoints: `/api/v1/plans`, `/api/v1/plans/{id}`, `/api/v1/plans/{id}/alternatives`.
* **Code Traceability:**
  - `apps/api/cisguard_api/plan_optimizer.py`: CP-SAT solver, conflict validator, topological sorter, plan hash calculator.
  - `apps/api/cisguard_api/plan_routes.py`: Plan creation and retrieval routes.
* **Test Verification:** `test_phase7_optimizer.py`, `test_live_phase7_8_9.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 8: Approvals, Safety Gates & Change States
* **Required Deliverables:**
  1. Change state machine: $\text{DRAFT} \to \text{SIMULATED} \to \text{PRECHECKED} \to \text{PENDING\_APPROVAL} \to \text{APPROVED} \to \text{EXECUTING} \to \text{VERIFYING} \to \text{terminal}$.
  2. Two-person separation of duties rule ($\text{approver} \ne \text{operator} \ne \text{author}$).
  3. Mandatory AAL2 MFA for approval decisions.
  4. Stale plan detection using SHA-256 snapshot hashes.
  5. Safety contract evaluation blocking execution upon unknown mandatory contracts.
  6. Endpoints: `/api/v1/simulations`, `/api/v1/approvals`, `/api/v1/changes`.
* **Code Traceability:**
  - `apps/api/cisguard_api/change_routes.py`: State machine transitions, approval logic, simulation runner.
  - Database Triggers: `guard_approval()`, `guard_change_identity()`.
* **Test Verification:** `test_phase8_changes.py`, `test_I14_I16_change_management.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 9: Cryptographic Proof Dossier, Residual Risk & Drift
* **Required Deliverables:**
  1. Asymmetric Ed25519 digital signing of proof manifests.
  2. RFC-8785 canonical JSON serialization ensuring deterministic digests.
  3. Independent public-key verification endpoint (`POST /api/v1/proofs/verify`).
  4. Quantitative post-hardening residual risk scoring.
  5. Configuration drift detection, event persistence, and alerting.
  6. Endpoints: `/api/v1/proofs`, `/api/v1/proofs/verify`, `/api/v1/drift-events`.
* **Code Traceability:**
  - `apps/api/cisguard_api/proof_routes.py`: Ed25519 signer/verifier, residual risk formula, drift endpoints.
* **Test Verification:** `test_phase9_proof.py`, `test_live_phase7_8_9.py`.
* **Status:** **VERIFIED COMPLETE**

---

### Phase 10: Independent QA, SAST & Collaborator Readiness
* **Required Deliverables:**
  1. Passing backend CI suite with unit, contract, and live integration tests.
  2. Ruff linter verification (0 errors).
  3. SAST security scan (0 violations of eval/exec/shell/raw credentials).
  4. Dependency vulnerability audit (`pip-audit`: 0 vulns in app libraries).
  5. Hypothesis property-based testing of scoring invariants.
  6. Mock device engine port adapter and Docker compose environment.
  7. OpenAPI 3.1.0 and collaborator handoff package for Apoorva and Vidhi.
* **Code Traceability:**
  - `infra/mypy.ini`, `infra/semgrep.yml`, `infra/docker-compose.yml`
  - `apps/api/cisguard_api/mock_engine.py`, `apps/api/cisguard_api/device_port.py`
  - `docs/core/phase10-handoff.md`, `docs/core/phase10-validation.md`
* **Test Verification:** `apps/api/tests/test_phase10_qa.py`, full suite (365 tests passing).
* **Status:** **VERIFIED COMPLETE**

---

## 3. Requirement Status Classification Summary

| Classification | Count | Description |
|---|---|---|
| **VERIFIED COMPLETE** | **88 / 88** | All Mandar primary requirements (44) and interface/review contracts (44) verified with executable code and passing tests. |
| **IMPLEMENTED BUT UNVERIFIED** | **0** | No unverified components remain. |
| **PARTIAL** | **0** | No partial backend deliverables. |
| **MISSING** | **0** | All requested phase instructions and deliverables are in place. |
| **BLOCKED** | **0** | Zero internal blockers. Ready for branch integration. |

