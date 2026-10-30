# CISGuard 360 — Phase 7, 8 & 9 Backend Architecture & Handoff Specification

**Workstream:** Mandar (Lead Backend Engineer, Security Architect)  
**System Version:** `0.9.0`  
**Database Schema Head:** `0007_plans_changes_proof`  
**Execution Environment:** Python 3.12, FastAPI, SQLAlchemy 2.0 (PostgreSQL RLS), OR-Tools CP-SAT, NetworkX, Ed25519 (cryptography), Celery, Redis, OpenBao KV v2  
**Runtime AI Policy:** STRICT ZERO LLM / ZERO ML RUNTIME USAGE. Pure deterministic algorithms only.

---

## 1. Phase 7: Minimal-Change Remediation Optimizer & Planning Engine

### 1.1 Mathematical Optimization Formulation (OR-Tools CP-SAT)
The remediation optimizer selects an optimal, minimal-impact subset of remediation candidates to resolve target CIS benchmark non-compliance findings without violating operational safety invariants.

Given:
- Candidate remediation actions $A = \{a_1, a_2, \dots, a_n\}$.
- Action selection boolean variables $x_i \in \{0, 1\}$ for each candidate $a_i$.
- Non-compliance findings $F = \{f_1, f_2, \dots, f_m\}$.
- Matrix $R_{ij} = 1$ if action $a_i$ resolves finding $f_j$, else $0$.
- Finding weights $W_j$ proportional to severity (CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1).
- Action costs $C_i$ (disruption/change cost).
- Action blast radius $B_i$.
- Maximum permitted blast radius $B_{\max}$.
- Service disruption budget $D_{\max}$.
- Mutually exclusive conflict pairs $E_{\text{conflict}} \subseteq A \times A$.
- Dependency requirements $D_{\text{dep}} \subseteq A \times A$, where $(a_i, a_j)$ indicates $a_i$ requires $a_j$.

**Objective Function:**
$$\max \quad \sum_{j} W_j \cdot y_j - \lambda_1 \sum_{i} C_i \cdot x_i - \lambda_2 \sum_{i} B_i \cdot x_i$$
Subject to:
1. Finding resolution linkage:
   $$\forall f_j: \quad y_j \le \sum_{i: R_{ij}=1} x_i, \quad y_j \in [0, 1]$$
2. Blast radius constraint:
   $$\sum_{i} B_i \cdot x_i \le B_{\max}$$
3. Service disruption threshold:
   $$\sum_{i} D_i \cdot x_i \le D_{\max}$$
4. Mutual exclusion (conflict pairs):
   $$\forall (a_i, a_k) \in E_{\text{conflict}}: \quad x_i + x_k \le 1$$
5. Dependency satisfaction:
   $$\forall (a_i, a_j) \in D_{\text{dep}}: \quad x_i \le x_j$$
6. Firmware compatibility:
   $$x_i = 0 \quad \text{if } a_i \notin \text{SupportedFirmwareCapabilities}$$
7. Rollback requirement:
   $$x_i = 0 \quad \text{if require\_rollback is True and } a_i.\text{rollback\_action is null}$$

### 1.2 Graph-Based Sequencing & Conflict Resolution
1. **Dependency DAG:** Remediation candidates form a directed graph $G = (A, D_{\text{dep}})$.
2. **Topological Sort:** Execution order is determined using Kahn's algorithm / NetworkX `topological_sort`.
3. **Cycle Rejection:** Any detected cycle in $D_{\text{dep}}$ yields `UNSAT` with status `CYCLE_DETECTED`.
4. **UNSAT Diagnosis:** If CP-SAT finds no feasible solution, the optimizer evaluates relaxation bounds and reports unsatisfied constraints (`UNSAT: BLAST_RADIUS_EXCEEDED`, `UNSAT: NO_ROLLBACK_ACTION`, `NO_VALIDATED_PLAN`).

### 1.3 Alternative Trade-Off Ranking
The optimizer generates multiple Pareto-optimal alternative plans:
- **Default Plan:** Balanced risk reduction vs. minimal change cost.
- **Minimal Disruption Plan:** Minimizes change cost and blast radius with bounded compliance gain.
- **Maximum Compliance Plan:** Maximizes resolved finding weights under loosened blast bounds.

---

## 2. Phase 8: Safety Gates, Approver Separation & Orchestration State Machine

### 2.1 Change State Machine
The lifecycle of all remediation execution strictly follows a non-reversible state machine:

```
[DRAFT]
   │
   ▼
[SIMULATED] ──(Fails simulation contracts)──► [FAILED_PRECHECK]
   │
   ▼
[PRECHECKED] ──(Blocked by safety gate)──► [BLOCKED]
   │
   ▼
[PENDING_APPROVAL] ──(Rejected by approver)──► [REJECTED]
   │
   ▼
[APPROVED] ──(Stale hash / Timeout)──► [EXPIRED]
   │
   ▼
[EXECUTING] ──(Command execution failure)──► [ROLLED_BACK] / [FAILED]
   │
   ▼
[VERIFYING] ──(Post-hardening checks pass)──► [COMPLETED]
   │
   └──(Post-hardening checks fail)──► [ROLLED_BACK]
```

### 2.2 Security Policies & Mandatory Invariants (E21–E25, I14–I16)
1. **Two-Person Rule / Separation of Duties:**
   The database trigger `guard_change_identity()` and application-layer guards enforce:
   $$\text{approver\_id} \ne \text{operator\_id} \quad \land \quad \text{approver\_id} \ne \text{author\_id}$$
   Owners and Operators cannot approve their own remediation changes.
2. **Mandatory MFA (AAL2):**
   Approvals require an active session verified with Authenticator Assurance Level 2 (`aal2`). The database trigger `guard_approval()` enforces `current_setting('app.aal') = 'aal2'`.
3. **Snapshot & Hash Integrity:**
   `plan_hash` is computed as the SHA-256 digest of normalized actions and target state. Any change in device configuration between simulation and execution invalidates the plan with `STALE_PLAN_DETECTED`.
4. **Safety Contracts:**
   Target assets must satisfy pre-declared `safety_contracts` (e.g. `bgp_keepalive_active`, `mgmt_ssh_accessible`, `ospf_neighbor_count >= 2`). If unknown mandatory contracts exist, autonomous execution is blocked.

---

## 3. Phase 9: Cryptographic Proof-of-Hardening Dossier & Drift Engine

### 3.1 Asymmetric Ed25519 Signing (E05, E19, I17–I20)
1. **RFC-8785 Canonical Serialization:**
   Audit evidence manifests, baseline results, and executed changes are serialized to JSON with deterministic key sorting and UTF-8 encoding.
2. **Ed25519 Digital Signatures:**
   The system signs canonical evidence manifests using asymmetric Ed25519 keys (`cryptography.hazmat.primitives.asymmetric.ed25519`).
3. **Public Key Verification:**
   Clients or third-party auditors can independently verify dossiers via `POST /api/v1/proofs/verify` using the server's public key without requiring database access or server secrets.

### 3.2 Residual Risk Quantification (E06, I18)
Post-hardening residual risk is quantitatively calculated:
$$\text{Residual Risk} = \sum_{f \in \text{Unresolved Findings}} \text{Severity Weight}(f) \times \text{Asset Criticality}(a) \times (1 - \text{Mitigation Factor})$$

### 3.3 Drift Detection & Real-Time Monitoring (E26–E28)
- Periodic audit scans compare current device state against the signed proof-of-hardening baseline.
- Any unexpected modification to hardened controls emits a structured `drift_event` (`SEVERITY: HIGH/CRITICAL`).
- Emits real-time notifications via Webhooks with HMAC-SHA256 signatures, exponential backoff, and Jira/ServiceNow ticketing adapters.

---

## 4. API Endpoints Reference Catalog (Phase 7–9)

| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/plans` | Generate CP-SAT remediation plan | `operator` (`plan.write`) |
| `GET` | `/api/v1/plans/{id}` | Retrieve generated remediation plan | `operator`, `approver`, `auditor` |
| `GET` | `/api/v1/plans/{id}/alternatives`| List ranked trade-off alternatives | `operator`, `approver`, `auditor` |
| `POST` | `/api/v1/simulations` | Simulate plan execution against safety contracts | `operator` (`change.execute`) |
| `GET` | `/api/v1/simulations/{id}` | Inspect simulation results & verdicts | `operator`, `approver`, `auditor` |
| `POST` | `/api/v1/approvals` | Submit signed approval decision (AAL2 MFA) | `approver` (`change.approve`) |
| `GET` | `/api/v1/approvals/{id}` | Retrieve approval status and audit logs | `operator`, `approver`, `auditor` |
| `POST` | `/api/v1/changes` | Create change ticket bound to approved plan | `operator` (`change.execute`) |
| `GET` | `/api/v1/changes/{id}` | Get change status and state machine progress | `operator`, `approver`, `auditor` |
| `POST` | `/api/v1/changes/{id}/advance` | Advance state machine (EXECUTE, VERIFY) | `operator` (`change.execute`) |
| `POST` | `/api/v1/proofs` | Generate Ed25519 signed proof dossier | `auditor` (`report.export`) |
| `POST` | `/api/v1/proofs/verify` | Verify Ed25519 digital signature of dossier | Public / Any authenticated role |
| `GET` | `/api/v1/drift-events` | Query detected compliance drift events | `auditor`, `security_admin` |
| `POST` | `/api/v1/drift-events` | Ingest new configuration drift detection | `operator` (`audit.scan`) |

---

## 5. Summary of Test Validation
- **Total Test Suite:** 356 automated tests.
- **Passing:** 356 (100% pass rate).
- **Execution Time:** ~2m 34s across full suite.
- **Live Infrastructure Tested:** Supabase PostgreSQL with RLS, Redis (Celery queues), OpenBao (KV v2 secrets).

