# CISGuard 360 — Phase 4 Readiness Report & Architectural Transition

**Date**: 29 October 2026  
**Auditor**: Lead Backend, Architecture & Security Engineer (Mandar Workstream)  
**Readiness Verdict**: **GO — FULLY READY FOR PHASE 4 IMPLEMENTATION**

---

## 1. Readiness Decision Matrix

| Readiness Pillar | Status | Evaluation |
|---|:---:|---|
| **Data Contracts & Wire Models** | **READY** | `cisguard_contracts.v1` defines all `PolicyRule`, `PolicyPack`, `PolicyDiff`, `AssessmentStatus`, and `Finding` types. |
| **Multi-Tenant Database Foundation** | **READY** | Schema `cisguard` live with 38 tables, all RLS-enabled, migration head `0004_orchestration`. |
| **Authentication & Authorization** | **READY** | Supabase Auth JWKS verification, 6 seed roles, MFA step-up (`aal2`), separation of duties. |
| **Asset & Job Orchestration** | **READY** | Asset CRUD, capability registry, M13 failure isolation, Celery worker, transactional outbox. |
| **Infrastructure Services** | **READY** | Live Redis (port 6380) broker + result backend, live OpenBao (port 8201) AppRole auth. |
| **Automated Test Suite** | **READY** | **260 passed**, 0 failed across unit, contract, HTTP, and live database integration suites. |

---

## 2. Phase 4 Scope & Technical Requirements

According to the authoritative Parallel Development Guide:
> **PHASE 4: CIS policy engine, SCAP bridge and accurate scoring**  
> Scope: M16–M19, E11–E12, E14, E20, I19, I20.  
> Deliverables: Versioned policy pack service, deterministic rule interpreter, applicability and score correctness.

### Core Modules to Implement in Phase 4:
1. **Deterministic Rule Interpreter**:
   - Predicate operators: `equals`, `range`, `cidr_contains`, `set_membership`, `regex` (restricted/safe), `ordered_acl`, `xccdf_oval`.
   - Zero runtime LLM or probabilistic reasoning: purely mathematical and rule-based evaluation.
2. **Benchmark & Rule Mapping Registry**:
   - YAML, JSON, and XML policy pack ingestion.
   - Profile resolution (e.g. "Level 1", "Level 2").
   - Applicability filters matching device OS, firmware, and platform facts.
3. **Evidence & Evaluation Outcomes**:
   - Distinct statuses preserved: `PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL_REVIEW`, `ERROR`, `NOT_ASSESSED`.
   - Unknown/missing evidence must NEVER evaluate to `PASS`.
   - Exception overlays and policy overrides joined without modifying original benchmark rules.
4. **Scoring Engine**:
   - Accurate score formula: `assessed_compliance = PASS / (PASS + FAIL)`.
   - Assessment coverage reported independently: `(PASS + FAIL + MANUAL_REVIEW) / TOTAL`.
5. **OpenSCAP / ComplianceAsCode Adapter**:
   - Structured importer for SCAP / XCCDF streams; supplementary, never automatically equivalent to official CIS controls.

---

## 3. Immediate Action Plan for Phase 4 Kick-Off

1. Implement `apps/api/cisguard_api/policy_engine.py` with the 7 deterministic predicate operators.
2. Build the benchmark pack loader supporting CIS YAML/JSON definitions with rights status tracking.
3. Wire the evaluation engine into `execute_scan_job` in `worker.py` to evaluate collected facts against policy rules and populate `cisguard.audit_results`.
4. Implement compliance score reconciliation and benchmark upgrade diff calculations.
5. Create Phase 4 unit and live test suite covering M16–M19, E11–E12, E14, E20, I19, I20.

