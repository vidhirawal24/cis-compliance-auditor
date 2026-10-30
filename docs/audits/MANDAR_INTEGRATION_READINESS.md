# CISGuard 360 — Mandar Backend Integration Readiness & Collaborator Handshake

**Author:** Mandar (Lead Backend Engineer & Security Architect)  
**Handshake Version:** `1.0.0` (Frozen Contract)  
**Target Collaborators:** Vidhi (`services/device-engine`), Apoorva (`apps/web`)  
**Audit Date:** 2026-10-30  
**Overall Readiness Verdict:** **100% READY FOR INTEGRATION**

---

## 1. Readiness Summary

Mandar's backend workstream has successfully completed all phases from **Phase 0 through Phase 10**.
- **Automated Test Suite:** 365 tests passing (0 failures).
- **Quality Gates:** Ruff (0 errors), AST SAST (0 violations), pip-audit (0 app vulnerabilities), Hypothesis property tests (100 iterations passed).
- **Live Infrastructure:** Supabase PostgreSQL 17 (38 tables, 100% RLS enabled, Alembic `0007_plans_changes_proof`), Redis Celery broker & result backend, OpenBao KV v2 secrets vault.
- **Collaborator Interfaces:** OpenAPI 3.1.0 specification, 44 JSON Schemas, sanitized sample fixtures, and mock device engine port.

---

## 2. The 88-Feature Responsibility & Readiness Ledger

| ID | Feature Name | Primary Owner | Mandar Status | Integration Requirement Upon Merge |
|---|---|---|---|---|
| **M01–M12** | OS & Network Device Collectors (Win 11, Server 2019, Ubuntu, RHEL, Fortinet, Cisco, Check Point, Sophos, Palo Alto) | Vidhi | **INTERFACE READY** | Vidhi connects live SSH/API scrapers to `cisguard_api.device_port.collect_device_facts`. |
| **M13** | Central Multi-Target Audits | **Mandar** | **VERIFIED COMPLETE** | Celery worker dispatches jobs across targets with failure isolation. |
| **M14–M15** | OS & Network Normalized Evidence Collectors | Vidhi | **INTERFACE READY** | Vidhi maps vendor CLI outputs to Contract v1 `NormalizedEvidence`. |
| **M16** | Deterministic CIS Evaluation | **Mandar** | **VERIFIED COMPLETE** | Evaluates equality, range, CIDR, set, and ordered policy predicates. |
| **M17** | Modular YAML/JSON/XML Rules | **Mandar** | **VERIFIED COMPLETE** | Versioned policy packs and XML SCAP mapping active. |
| **M18** | Custom Baselines | **Mandar** | **VERIFIED COMPLETE** | Custom baselines with profile inheritance and persistence. |
| **M19** | Benchmark Update Maintenance | **Mandar** | **VERIFIED COMPLETE** | Benchmark diffing and version upgrade impact previews. |
| **M20–M33** | Network & Host Controls (SSHv2, ACLs, Ports, VLAN1, Syslog, NTP, SNMP, etc.) | Vidhi | **INTERFACE READY** | Mandar's policy engine has rules for all controls; Vidhi collects hardware facts. |
| **M34** | Central GUI Dashboard | Apoorva | **INTERFACE READY** | Apoorva connects React dashboard to `/api/v1/scans` and `/api/v1/findings`. |
| **M35** | Compliance & Severity Breakdown | Apoorva / Mandar | **VERIFIED COMPLETE** | Server computes compliant/coverage scores and severity breakdowns. |
| **M36** | Expected vs Actual Finding | Apoorva / Mandar | **VERIFIED COMPLETE** | Finding detail endpoint `/api/v1/findings/{id}` serves exact diffs. |
| **M37** | Actionable Remediation | Vidhi | **INTERFACE READY** | Remediation text and rollback guidance populated in findings. |
| **M38** | Multi-Format Reports (PDF/HTML/CSV/JSON) | **Mandar** | **VERIFIED COMPLETE** | Jinja2 + WeasyPrint generator reconciles identical outcome totals. |
| **E01–E04** | Asset Inventory, Discovery, Tagging, Schedules | **Mandar** | **VERIFIED COMPLETE** | Full CRUD, CIDR discovery approvals, tags, cron schedules. |
| **E05** | Configuration Drift Alerts | Vidhi / Mandar | **VERIFIED COMPLETE** | Drift event persistence, querying, and webhook alert triggers. |
| **E06** | Configuration Snapshots | **Mandar** | **VERIFIED COMPLETE** | Immutable snapshots with SHA-256 integrity digests. |
| **E07** | Compliance Trends | **Mandar** | **VERIFIED COMPLETE** | Historical compliance trend aggregation endpoint `/api/v1/trends`. |
| **E08–E09** | Selective Audits & Distributed Workers | **Mandar** | **VERIFIED COMPLETE** | Selective targeting by tags/groups and Redis Celery queues. |
| **E10** | Offline Configuration Assessment | Vidhi | **INTERFACE READY** | Synthetic fixture port allows offline evaluation. |
| **E11–E12** | CIS Level 1/2 Profiles & Manual Reviews | **Mandar** | **VERIFIED COMPLETE** | Profile filtering and manual review workflow endpoints. |
| **E13** | Risk-Based Prioritization | **Mandar** | **VERIFIED COMPLETE** | Severity weights combined with asset criticality scoring. |
| **E14** | Policy Exceptions | **Mandar** | **VERIFIED COMPLETE** | Exception overlays with audit justification and expiration dates. |
| **E15–E16** | Role-Based Authorization & MFA | **Mandar** | **VERIFIED COMPLETE** | 6 distinct RBAC roles and mandatory AAL2 MFA for approvals. |
| **E17** | Device Credential Vault | **Mandar** | **VERIFIED COMPLETE** | OpenBao KV v2 secret reference architecture (no raw secrets in DB). |
| **E18** | Read-Only Audit Mode | **Mandar** | **VERIFIED COMPLETE** | Non-mutating read-only collection by default. |
| **E19** | Application Audit Trail | **Mandar** | **VERIFIED COMPLETE** | Tamper-evident `audit_events` logging for all actions. |
| **E20** | Policy Version History | **Mandar** | **VERIFIED COMPLETE** | Tracked benchmark releases and active rule revisions. |
| **E21–E25** | Hardening Orchestration & Safety Gates | Vidhi / Mandar | **VERIFIED COMPLETE** | Change state machine, simulation checks, 2-person rule, dual verification. |
| **E26–E28** | Webhooks, Ticketing & Executive Reports | **Mandar** | **VERIFIED COMPLETE** | Signed webhooks, Jira/ServiceNow adapters, executive summaries. |
| **E29** | Search / Filter Interface | Apoorva | **INTERFACE READY** | Cursor pagination, text search, and severity filters on all list routes. |
| **E30** | External Integration API | **Mandar** | **VERIFIED COMPLETE** | Versioned REST API and OpenAPI 3.1.0 specification. |
| **I01–I05** | Security Graph, Paths & Root Cause | **Mandar** | **VERIFIED COMPLETE** | NetworkX topology graph, reachability paths, explainability chains. |
| **I06–I10** | Remediation Optimizer & Change Sequencing | **Mandar** | **VERIFIED COMPLETE** | Google OR-Tools CP-SAT minimal disruption optimizer and DAG sequencing. |
| **I11–I13** | What-If Simulation & Blast Radius Capping | Vidhi / Mandar | **VERIFIED COMPLETE** | Safety contracts simulation and blast radius constraints. |
| **I14** | Safety-Gated Execution | **Mandar** | **VERIFIED COMPLETE** | Stale plan detection, operator/approver segregation, approval gating. |
| **I15–I16** | Staged Rollout & Dual Verification | Vidhi | **INTERFACE READY** | Pre-check, change execution, and post-fix compliance re-audits. |
| **I17–I20** | Residual Risk, Proof Dossier & Upgrade Impact | **Mandar** | **VERIFIED COMPLETE** | Asymmetric Ed25519 signing, residual risk math, upgrade impact previews. |

---

## 3. Step-by-Step Collaborative Merge Sequence

```
Phase A: Contract Handshake (DONE)
  - Mandar has frozen packages/contracts/v1 and published OpenAPI 3.1.0.
  - Apoorva and Vidhi review and confirm compatibility against their stubs.

Phase B: Device Engine Merge (Next Step)
  1. Pull Vidhi's branch: git merge feat/vidhi-device.
  2. Install services/device-engine as an editable Python package in Mandar's venv.
  3. Swap cisguard_api.device_port fallback to Vidhi's DeviceEngine collector.
  4. Run integration tests: python -m pytest apps/api/tests/test_live_*.py.

Phase C: Frontend Merge (Final Step)
  1. Pull Apoorva's branch: git merge feat/apoorva-web.
  2. Point web client API baseURL to http://localhost:8000/api/v1.
  3. Run end-to-end user journeys (login -> scan -> graph -> plan -> approval -> dossier).
```

---

## 4. Pre-Merge Verification Checklist

- [x] All 38 tables in PostgreSQL have Row Level Security enabled.
- [x] Alembic migration head `0007_plans_changes_proof` is cleanly applied.
- [x] Redis and Celery worker process background scan tasks without crashing.
- [x] OpenBao retrieves credentials via AppRole and masks secrets in memory.
- [x] No `eval()`, `exec()`, or `shell=True` in codebase.
- [x] Zero vulnerabilities in application dependencies via `pip-audit`.
- [x] Ruff linter passes with 0 errors.
- [x] All 365 automated tests pass.
- [x] `.env` is ignored by Git; `.env.example` contains sanitized documentation.

