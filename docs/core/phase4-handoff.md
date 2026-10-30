# Phase 4: CIS Policy Engine, SCAP Bridge, and Accurate Scoring

Prepared 29 October 2026. Scope: M16–M19, E11–E12, E14, E20, I19, I20. Read this document alongside `docs/core/phase4-validation.md` and `docs/core/phase4-openapi.json`.

## Implemented Architecture

### 1. Deterministic CIS Rule Interpreter (M16, E20)
- **Zero Runtime AI/LLM Prohibition**: Built entirely on deterministic predicates without heuristics or probabilistic models.
- **8 Allowlisted Predicate Operators**:
  1. `equals`: Exact string, numeric, boolean, or structural equality.
  2. `contains`: Substring or array element containment.
  3. `regex`: Strict regular expression pattern matching with `is_safe_regex()` guard preventing exponential backtracking / ReDoS.
  4. `range`: Closed interval numeric checks (`min_val <= actual <= max_val`).
  5. `set_membership`: Verifies membership within discrete allowlists or denylists.
  6. `cidr_contains`: Evaluates whether target IP addresses fall within authorized subnet masks.
  7. `ordered_acl`: Sequential evaluation of security access-control lists ensuring high-precedence reject rules precede allow rules.
  8. `xccdf_oval`: Supplementary evaluation for parsed OpenSCAP XCCDF criteria.
- **Missing Evidence Defense**: If a required inspection path is missing or unresolved from collected facts, the rule evaluates strictly to `ERROR`. It **NEVER defaults to PASS**.
- **Platform & Profile Applicability**:
  - `is_platform_applicable()`: Filters controls based on asset `family`, `platform`, and semantic/lexical OS `os_or_firmware_version`.
  - Profile selection (`Level 1`, `Level 2`, `Workstation`, `Server`) dynamically restricts active rules during scan execution.

### 2. Accurate Scoring and Reconciled Coverage (M17, M35)
- **Preserved Status Taxonomy (E11, E12)**:
  Findings and results explicitly preserve:
  - `PASS`: Compliant with benchmark control definition.
  - `FAIL`: Non-compliant.
  - `NOT_APPLICABLE`: Target platform or hardware does not meet applicability conditions.
  - `MANUAL_REVIEW`: Control requires administrative inspection or procedural evidence.
  - `ERROR`: Collection error, timeout, or missing fact.
  - `NOT_ASSESSED`: Control excluded from active profile or evaluation scope.
- **Exact Canonical Scoring Formula**:
  - `assessed_compliance = PASS / (PASS + FAIL)` (calculated server-side as floating-point percentage in range [0.0, 100.0]).
  - If `PASS + FAIL == 0`, `assessed_compliance = 0.0`.
  - Coverage is reported completely independently: `coverage = (evaluated_rules / total_applicable_rules) * 100.0`.
  - Scoring summaries explicitly detail counts for `pass_count`, `fail_count`, `not_applicable_count`, `manual_review_count`, `error_count`, `not_assessed_count`, and active `exceptions_count`.

### 3. Benchmark Registry, Diffing, and Upgrade Preview (M16, I19, I20)
- **Canonical Hash & Rights Attribution**:
  - Benchmark packs calculate deterministic `content_sha256` via canonical JSON representation.
  - Rights tracking enforces `rights_status` (`AUTHORIZED`, `UNREVIEWED`, `RESTRICTED`) and tracks source attribution (`authorized_cis_mapping`).
- **Benchmark Version Diff (`compute_benchmark_diff`)**:
  - Evaluates changes between versions (e.g. Ubuntu 22.04 CIS v1 vs v2):
    - `added_control_ids`: Controls introduced in newer release.
    - `removed_control_ids`: Deprecated or deleted controls.
    - `modified_control_ids`: Changed predicate operators, expected values, or descriptions.
- **Asset Upgrade Impact Preview (`preview_benchmark_upgrade` / `POST /api/v1/policies/{id}/upgrade-preview`)**:
  - Evaluates how a benchmark upgrade will impact specific assets based on their platform and prior finding results.

### 4. Supplementary OpenSCAP Bridge (M19)
- **XXE-Hardened XML Ingestion**:
  - `parse_scap_xccdf_xml()` ingests XCCDF 1.2 XML with `lxml.etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)`.
  - Prohibits XML external entity injection and denial-of-service entity expansion.
- **Non-Equivalence Safeguards**:
  - SCAP benchmarks are explicitly recorded with `source = 'validated_scap_mapping'` and accompanied by a mandatory legal disclaimer: *"OpenSCAP and ComplianceAsCode mappings are supplementary technical baselines and are never automatically equivalent to official CIS Benchmarks"*.

### 5. Custom Baseline Overrides & Time-Boxed Exceptions (M18, E14)
- **Baseline Parameter Overrides (`PolicyOverride`)**:
  - Tenants customize specific control parameters (e.g., increase password history from 5 to 10) without mutating upstream benchmark packs.
  - Precedence: When evaluating a rule, active overrides for `(org_id, control_id)` supersede base rule definitions.
- **Exception Overlays & Separation of Duties (`PolicyException`)**:
  - Time-boxed exception requests (`POST /api/v1/exceptions`) require justification, risk level, review date, and expiration timestamp.
  - Active, approved exceptions temporarily convert finding verdict to `EXCEPTION` during the validity window, reducing false failures.
  - **Separation of Duties**: Approving an exception (`POST /api/v1/exceptions/{id}/decision`) strictly forbids self-approval (`ev.requested_by != actor_id`). Approvers must hold the `policy.override` permission.

### 6. Manual Review Evidence & Verification (E11, E12)
- Controls requiring administrative or procedural verification (e.g., password change policies, backup audits) are flagged with `requires_manual_review = True`.
- Findings for these controls initiate in `MANUAL_REVIEW` status.
- Evaluators and auditors submit manual review evidence (`POST /api/v1/manual-reviews`) with an immutable `EvidenceRef` (`private://evidence/...`), justification, and verdict (`PASS` or `FAIL`), transitioning the finding and updating scan compliance scores accordingly.

---

## Endpoints

| Method | Route | Permission Required | Description |
|---|---|---|---|
| GET | `/api/v1/policies` | `audit.read` | List installed benchmark policy packs |
| POST | `/api/v1/policies` | `policy.write` | Register new versioned policy pack |
| GET | `/api/v1/policies/{id}` | `audit.read` | Fetch benchmark pack details |
| GET | `/api/v1/policies/{id}/rules` | `audit.read` | List rules in pack (filterable by `?profile=`) |
| GET | `/api/v1/policies/{id}/diff` | `audit.read` | Compute diff between two benchmark versions |
| POST | `/api/v1/policies/{id}/upgrade-preview` | `audit.read` | Preview impact of policy upgrade on target assets |
| POST | `/api/v1/policies/scap-import` | `policy.write` | Ingest supplementary OpenSCAP XCCDF XML |
| GET | `/api/v1/policy-overrides` | `audit.read` | List custom baseline overrides |
| POST | `/api/v1/policy-overrides` | `policy.override` | Create or update custom baseline override |
| GET | `/api/v1/findings` | `audit.read` | List audit findings (filterable by scan, asset, status, severity) |
| GET | `/api/v1/findings/{id}` | `audit.read` | Get finding details including rule input and evidence refs |
| GET | `/api/v1/exceptions` | `audit.read` | List policy exception requests |
| POST | `/api/v1/exceptions` | `policy.override` | Request time-boxed policy exception |
| POST | `/api/v1/exceptions/{id}/decision` | `policy.override` | Approve or reject exception (separation of duties enforced) |
| POST | `/api/v1/manual-reviews` | `audit.scan` | Submit manual review evidence to resolve finding |
| GET | `/api/v1/scans/{id}/score` | `audit.read` | Retrieve canonical reconciled compliance and coverage score |

---

## Database and Migrations

- **Revision**: `0005_policy_engine` (head), applied to live PostgreSQL.
- Grants DML permissions to restricted runtime role `cisguard_api` on:
  - `cisguard.policy_rules`
  - `cisguard.policy_overrides`
  - `cisguard.findings`
  - `cisguard.exceptions`
  - `cisguard.manual_reviews`
- All queries strictly enforce tenant isolation and backend tenant checks (`cisguard.is_member(org_id)`).

---

## Testing Verification

```powershell
# Run all Phase 4 unit and interpreter tests (25 tests)
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests/test_phase4_policy_engine.py

# Run live PostgreSQL integration tests (End-to-end audit, findings, scoring, overrides, exceptions)
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests/test_live_phase4.py

# Run full project test suite across all phases (286 tests)
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache --junitxml=docs/core/phase4-tests.xml apps/api/tests
```

