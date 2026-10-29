# BaselineGuard - Phase 3 Implementation Review & Feature Handoff Matrix
**Role:** Frontend Owner (Apoorva)
**Date:** October 29, 2026
**Document Status:** Complete Phase 3 Implementation Review
**Product Branding:** BaselineGuard
**Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”
**Governing Directory:** `apps/web/` and `docs/frontend/`

---

## 1. Executive Summary

Phase 3 implements the **Compliance Dashboard, Scans and Findings** subsystems for **BaselineGuard** in `apps/web/`, strictly adhering to the PRD (M13, M34–M38, E04, E07, E08, E14, E18, E29), Final Tech Stack, and the *Apoorva Parallel Development Guide*.

All screens operate under strict read-only auditing constraints, consuming backend-provided compliance values without client-side score fabrication or manipulation. Synthetic fixtures deterministically represent all six immutable evaluation statuses: `PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL_REVIEW`, `ERROR`, and `NOT_ASSESSED`.

### Key Deliverables Completed:

1. **Overview Dashboard (`03_OverviewShell.tsx`) — M34, M35, E07:**
   - **Compliance vs. Coverage Separation:** Displayed as separate KPI metrics. Compliance rate formula: $\text{Compliance} = \frac{\text{PASS}}{\text{PASS} + \text{FAIL}}$. Coverage rate formula: $\text{Coverage} = \frac{\text{PASS} + \text{FAIL}}{\text{Total Applicable}}$.
   - **Visual Intelligence (Recharts):**
     - 30-day Posture Historical Trend (`E07`): Time-series line chart comparing Assessed Compliance % vs. Assessment Coverage %.
     - Severity Distribution Donut / Metric Cards (`M35`): Critical, High, Medium, Low breakdown with exact finding counts.
     - Platform Family Posture Stacked Bar Chart: Heterogeneous compliance posture across Windows, Linux, Cisco IOS, and perimeter Firewalls.
     - Category Risk Distribution: CIS benchmark categories mapped with failure counts and one-click filtering.
   - **Invariant Evaluation Status Manifest:** Explicit breakdown for all 6 immutable evaluation statuses with prominent warning: *`NOT_ASSESSED` is NEVER counted as `PASS`*.

2. **Audit Scan Launcher & Center (`06_ScanCenterShell.tsx`) — M13, E04, E08, E18:**
   - **Audit Launch Wizard (M13, E08, E18):** Target asset selector (multi-select, select all, clear), CIS Policy Pack picker, Profile Level toggle (`LEVEL_1` / `LEVEL_2`), and mandatory **Read-Only Audit Confirmation Checkbox** (`E18`).
   - **Scan Queue & Status (M13):** Real-time execution manifest tracking scans across states (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`). Animated progress bar for active runs, and per-target completion stats.
   - **Target Failure Drawer & Scan Retry:** Expandable inspection modal detailing per-target errors (e.g., API socket timeout, authentication token expired); one-click retry triggers dedicated API retry workflow.
   - **Recurring Schedules (E04):** Cron schedule table with frequency descriptions, active/paused status toggles, and modal form with standard 5-field cron syntax validation.

3. **Findings & Compliance Evidence Explorer (`09_FindingsShell.tsx`) — M36, M37, E14, E29:**
   - **Multi-Parameter Search & Filter (E29):** Text search (control ID, title, category, asset hostname), Severity filter pills, Status dropdown (all 6 invariant statuses), Category selector, and Target Asset dropdown.
   - **Expected vs. Observed State Comparison (M36):** Side-by-side formatted JSON comparison highlighting CIS benchmark requirement vs. live collector evidence.
   - **Immutable Evidence Provenance (M12):** Cryptographic SHA-256 hash display, source command/API query, artifact URI, and timestamp.
   - **Actionable Remediation Guidance (M37):** CLI commands displayed strictly as **non-executable preview text** with copy button, prominent operational risk warnings, and prerequisites checklist.
   - **Policy Exception Overlay (E14):** Approved exception manifest (approver email, expiration, rationale) with strict disclaimer: *exceptions do not alter `FAIL` to `PASS` in compliance scoring*.

---

## 2. Feature-to-Screen Handoff Mapping (Phase 3 Matrix)

| Feature ID | Feature Name | Primary Route / Component | UI Implementation & Security Controls | Status |
| :--- | :--- | :--- | :--- | :--- |
| **M13** | Audit Scan Execution & Queue | `/orgs/:orgId/scans`<br>[`06_ScanCenterShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/06_ScanCenterShell.tsx) | Scan manifest with progress tracking, per-target execution stats, retry action for failed runs, and run detail links. | **DONE** |
| **M34** | Multi-Tenant Posture Scoping | `/orgs/:orgId/overview`<br>[`03_OverviewShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/03_OverviewShell.tsx) | Posture metrics and asset findings strictly scoped to authorized organization `:orgId`. | **DONE** |
| **M35** | Severity-Based Finding Breakdown | `/orgs/:orgId/overview`<br>[`03_OverviewShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/03_OverviewShell.tsx) | Recharts donut chart and metric grid partitioning findings into Critical, High, Medium, and Low tiers. | **DONE** |
| **M36** | Expected vs Observed Side-by-Side Detail | `/orgs/:orgId/findings`<br>[`09_FindingsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/09_FindingsShell.tsx) | Two-pane side-by-side diff comparing CIS benchmark expected state vs observed collector facts. | **DONE** |
| **M37** | Actionable Remediation Guidance | `/orgs/:orgId/findings`<br>[`09_FindingsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/09_FindingsShell.tsx) | Non-executable read-only CLI code block with copy button, risk warnings, and prerequisites. | **DONE** |
| **M38** | Application Audit Trail | `/orgs/:orgId/audit`<br>[`18_AuditTrailShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/18_AuditTrailShell.tsx) | Scan dispatches and schedule mutations recorded in deterministic application audit log. | **DONE** |
| **E04** | Recurring Scheduled Audits | `/orgs/:orgId/scans?tab=SCHEDULES`<br>[`06_ScanCenterShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/06_ScanCenterShell.tsx) | Cron audit manager with active switches, delete actions, and 5-field cron expression validation. | **DONE** |
| **E07** | Posture Historical Trend Analysis | `/orgs/:orgId/overview`<br>[`03_OverviewShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/03_OverviewShell.tsx) | 30-day time-series line chart tracking Assessed Compliance % vs. Assessment Coverage %. | **DONE** |
| **E08** | Multi-Target Fleet Audit Wizard | `/orgs/:orgId/scans?tab=NEW_SCAN`<br>[`06_ScanCenterShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/06_ScanCenterShell.tsx) | Fleet dispatcher wizard selecting targets, policy baseline packs, and profile level. | **DONE** |
| **E14** | Policy Exception Tracking & Overlay | `/orgs/:orgId/findings`<br>[`09_FindingsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/09_FindingsShell.tsx) | Exception banner displaying approver and expiration while strictly retaining violation status. | **DONE** |
| **E18** | Read-Only Audit Execution Confirmation | `/orgs/:orgId/scans?tab=NEW_SCAN`<br>[`06_ScanCenterShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/06_ScanCenterShell.tsx) | Mandatory checkbox confirming `collect(read_only=True)`; dispatch blocked without explicit consent. | **DONE** |
| **E29** | Findings Search & Multi-Filter Explorer | `/orgs/:orgId/findings`<br>[`09_FindingsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/09_FindingsShell.tsx) | Multi-parameter search across controls, titles, categories, assets, severity, and evaluation statuses. | **DONE** |

---

## 3. Architecture & Security Invariants

### 3.1 Strict Separation of Compliance vs. Coverage
The frontend strictly treats **Compliance** and **Coverage** as distinct, non-fungible metrics:
- **Compliance %:** $\frac{\text{PASS}}{\text{PASS} + \text{FAIL}} \times 100$
- **Coverage %:** $\frac{\text{PASS} + \text{FAIL}}{\text{Total Applicable Rules}} \times 100$

All values are consumed directly from backend/fixture responses (`assessed_compliance_pct`, `assessment_coverage_pct`). The browser never manufactures, approximates, or recalculates compliance rates.

### 3.2 Evaluation Status Invariant (6 Immutable States)
Synthetic demo fixtures in `demoData.ts` and the UI explicitly support all six evaluation statuses defined in `contracts/v1`:
1. `PASS`: Control verified compliant with benchmark.
2. `FAIL`: Observed configuration violates benchmark.
3. `NOT_APPLICABLE`: Target platform or hardware lacks relevant capability (e.g., wireless on core router).
4. `MANUAL_REVIEW`: Physical security or administrative policy requiring human sign-off.
5. `ERROR`: Collector timeout or protocol fault.
6. `NOT_ASSESSED`: Control omitted due to privilege or capability limitation.

**Integrity Rule:** `NOT_ASSESSED`, `ERROR`, `MANUAL_REVIEW`, and `NOT_APPLICABLE` are **NEVER** counted as `PASS`. This rule is explicitly enforced in UI badges, overview counters, and unit test assertions.

### 3.3 Mandatory Read-Only Audit Consent (E18)
The scan dispatch wizard enforces a mandatory, non-bypassable confirmation checkbox:
> *"Confirm Read-Only Audit Execution: I acknowledge that this assessment will execute strictly read-only collection probes (`collect(read_only=True)`) and will make zero mutations to device configurations."*

Form submission is hard-blocked unless checked.

### 3.4 Non-Executable Remediation CLI (M37)
To ensure the web application remains strictly read-only and prevents arbitrary command injection or unintended infrastructure modification:
- Remediation commands are rendered in read-only `<pre>` text blocks.
- A clipboard copy button is provided with visual feedback.
- Prominent risk warnings and operational prerequisites are displayed alongside each command.
- The UI explicitly indicates that configuration changes must be scheduled through the Change Approval and What-If Simulation workflow (Phase 4).

---

## 4. Test Verification Matrix

All unit and integration test suites pass under Vitest and React Testing Library:

| Test Suite | File Path | Tests | Focus / Scenarios Tested |
| :--- | :--- | :--- | :--- |
| **Phase 3 Suite (New)** | [`src/test/phase3.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/phase3.test.tsx) | 11 | Compliance vs Coverage separation, 6 invariant statuses (`NOT_ASSESSED != PASS`), Recharts rendering, mandatory read-only consent (E18), scan queue progress, per-target error drawer, failed scan retry, 5-field cron schedule validation, side-by-side Expected vs Observed (M36), SHA-256 evidence hash (M12), non-executable remediation CLI (M37), and policy exception overlay (E14). |
| **Asset Management** | [`src/test/assets_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/assets_phase2.test.tsx) | 6 | Inventory table, tag filters, onboarding wizard (E18), discovery sweep with scope consent (E02), asset detail, and retirement workflow. |
| **Authentication** | [`src/test/auth_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/auth_phase2.test.tsx) | 5 | Login form validation, password recovery, MFA TOTP challenge, demo persona role switching. |
| **Tenant Isolation** | [`src/test/orgs_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/orgs_phase2.test.tsx) | 3 | Tenant listing, active tenant switching, cross-tenant 403 isolation screen (M34). |
| **Route Smoke Tests** | [`src/test/routes.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/routes.test.tsx) | 19 | All 19 route shells rendering without runtime panics. |
| **Navigation & RBAC** | [`src/test/navigation.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/navigation.test.tsx) | 3 | Role-aware menu filtering between Owner, Operator, Auditor, and Viewer. |
| **System States** | [`src/test/states.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/states.test.tsx) | 4 | Empty states, loading skeletons, error boundary panics, 403 forbidden screen. |
| **Total** | **7 Test Files** | **51** | **100% Passed (0 Failures)** |

---

## 5. Build & Compilation Verification

- `corepack pnpm --dir apps/web type-check`: **0 errors** (strict mode, `noUnusedLocals`, `noUnusedParameters`).
- `corepack pnpm --dir apps/web test`: **51 of 51 tests passed**.
- `corepack pnpm --dir apps/web build`: **Built in 8.94s**, production bundles emitted cleanly in `dist/`.
