# BaselineGuard Phase 6 review

Date: 2026-10-29 (Asia/Calcutta). Scope: planner, simulator and service-safety presentation only.

## Verified handover

- Repository: D:\Mini_Project_Hackathon; branch: feat/apoorva-web.
- Remote: https://github.com/vidhirawal24/cis-compliance-auditor.git.
- Initial HEAD and origin tracking ref: 2c95045c77b6d7af8bfc5d17e77f22ae7cbcef2b,
  feat(frontend): implement BaselineGuard phase 5. No initial ahead/behind difference.
- Phase 3 verified: cbe3a926e46667d3dbfc8b5173d6573a6fc04187.
- Phase 4 verified: 53f8aa09f699788618c2d3a75591542201148e18.
- Commit file changes, current screens, contracts, store, fixtures, routing and tests
  corroborate the Phase 3-5 implementations. Baseline run: 69/69 tests in 9 files.
- Initial worktree change: one extra blank line at EOF in phase5-review.md. It was
  preserved during implementation, then removed with explicit user authorization
  because it failed git diff --check. The file now matches HEAD and is not staged.
- No AGENTS.md found in the repository or its immediate parent.

## Sources and limits of verification

Read the available phase0/3/4/5 reviews, routes.md, component-plan.md,
contract-questions.md, README, and relevant implementation/test files. Earlier
reviews contain feature labels that do not always agree with the master mapping;
Phase 6 uses the I06-I15 descriptions in phase0-review.md and routes.md.

These authoritative PDFs are absent from the repository and were not read:
- CISGuard_360_Apoorva_Parallel_Development_Guide.pdf
- CISGuard_360_Complete_PRD_v1.pdf
- CISGuard_360_Final_Tech_Stack_v3.pdf

Searching user Downloads/Documents was denied by the filesystem permissions.
PRD-level feature verification remains BLOCKED. No individual ID is declared DONE
based on a similar screen or on previous-agent assertions. The user's supplied
Phase 6 requirements and the available repository mapping guided implementation.

## Architecture and implementation

Reused React 18, strict TypeScript, Vite, Tailwind, existing Card/Button/Input/Badge,
React Router routes and guards, ApiProvider, TanStack Query and frozen client types.
Dependencies already present: @xyflow/react (^12.3.1; installed 12.12.0), Recharts
(^2.12.7), React Hook Form (^7.53.0), Zod (^3.23.8) and @hookform/resolvers.
No dependency or lockfile changes. Cytoscape Phase 5 screens remain intact.

Changed files:
- apps/web/src/features/phase6/model.ts: typed frontend-only DEMO candidates,
  explicit selection, organization-scoped in-memory preview state, existing API
  reads, tenant/identity checks and a fail-closed approval eligibility calculation.
- apps/web/src/features/phase6/PlanDiagram.tsx: real React Flow nodes and dependency
  edges, zoom/pan/selection, read-only sequence, step detail and accessible fallback;
  service impact overlay using supplied topology with hypothetical impact labels.
- apps/web/src/features/phase6/SimulationPanels.tsx: distinct verdicts, synthetic
  baseline/candidate service diagrams, React Hook Form contract draft editor using
  the existing Zod schema with stricter local IPv4 CIDR/port validation.
- apps/web/src/features/phase6/RolloutPreview.tsx: historical DEMO batch, canary,
  event and halt presentation via the existing getChange read method.
- apps/web/src/routes/shells/12_RemediationPlannerShell.tsx: candidate comparison,
  selected state, fixture objective weights and meanings, conflicts/UNSAT and
  loading, empty, error and unsupported states.
- apps/web/src/routes/shells/13_WhatIfSimulatorShell.tsx: explicit DEMO preview,
  coverage/limitations, contract list, affected services, diagrams and approval gate.
- apps/web/src/routes/shells/14_ApprovalsHardeningShell.tsx: direct-navigation gate
  and action-handler guard, preventing bypass by navigating around the simulator.
- apps/web/src/test/phase6.test.tsx: 28 focused tests.
- apps/web/src/test/setup.ts: jsdom SVG getBBox shim for real React Flow edge tests.
- docs/frontend/contract-questions.md: concrete backend integration gaps.
- docs/frontend/phase6-review.md: this handover and verification record.

Only apps/web and docs/frontend changed. No API, device-engine, infrastructure or
shared contracts were modified. No generated output is staged.

## Contracts, provenance and safety

Existing typed models: RemediationPlan/RemediationAction, ServiceSafetyContract,
WhatIfSimulation, SecurityGraphData and HardeningChange. Existing read methods:
getRemediationPlan, getSimulation, getSafetyContracts, getSecurityGraph, getChange.
ApiClientInterface currently has only DemoApiClient implementation. Production
endpoint availability is not established; no URLs or wire contracts were invented.
There is no simulation-submit, alternative-list/generate, or contract-save method.

Frontend-only synthetic candidate metadata does not extend frozen wire contracts.
The balanced scenario displays stored fixture results; the restrictive scenario
explicitly adds a hypothetical management-SSH violation with no executable template.
Other scenarios show unsupported behavior, insufficient topology and UNSAT.
No optimizer or simulation engine is claimed to have run. Weights and comparison
scores are labeled illustrative, with no mathematical optimality claim.

SAFE_IN_MODEL, VIOLATES_CONTRACT, UNSUPPORTED and INSUFFICIENT_EVIDENCE have separate
labels, colors and explanations. Model safety never claims real-device verification.
Confirmed topology means confirmed in the DEMO input only. Service impacts are
hypothetical; absent endpoint identities and unknown downstream dependencies remain
explicit. An aggregate endpoint count is not converted into fabricated asset names.

Approval review requires an eligible current preview, nonempty plan, no conflicts,
no UNSAT, no known violations, positive model/topology coverage and sufficient
mandatory-contract evaluation count. Preview identity includes the supplied plan,
simulation, contracts and topology. Selection changes clear it; every contract edit
invalidates it and permanently blocks approval for that session because backend
re-evaluation is unavailable. Toggling mandatory off cannot bypass this gate.
Direct approval navigation is gated too. The browser state is not a security boundary:
the server remains responsible for final enforcement and approval authorization.
No new approval is issued by the simulator; no shell or device execution API is called.
The existing historical DEMO approval/hardening screen is otherwise preserved.

## Evidence-backed feature mapping

Names below come from phase0-review.md section 5.3 and routes.md. All overall statuses
remain PARTIAL pending authoritative PDF verification and supported production APIs.

| ID | Existing mapped description | Status | Implemented evidence / remaining limit |
| --- | --- | --- | --- |
| I06 | Minimal-Change Optimization | PARTIAL | Fixture candidate scores and objective meanings; typed-plan/weights tests. Production optimizer, objective submission and optimality proof unavailable. |
| I07 | Alternative Fix Comparison | PARTIAL | Side-by-side candidate cards, disruption/effort/steps and explicit selection; selection-to-simulator test. Alternatives are synthetic, not generated backend solutions. |
| I08 | Cross-Vendor Remediation Planning | PARTIAL | Cisco and Canonical actions with target, prerequisites and recovery details; typed plan and selected-node tests. No production cross-vendor planning operation. |
| I09 | Remediation Conflict Checks | PARTIAL | Supplied conflict messages and synthetic UNSAT with disabled progression; dedicated conflict/UNSAT tests. No constraint solver runs. |
| I10 | Change Sequencing | PARTIAL | Real @xyflow/react DAG, dependency edge, selected-node details and accessible list; real node/edge DOM assertions. DEMO dependencies only; no validated production resequencing. |
| I11 | Cross-Layer What-If Simulation | PARTIAL | Baseline/candidate React Flow service views, coverage and all verdicts; comparison and unsupported-state tests. Stored previews only, no simulation submission. |
| I12 | Service-Safety Contracts | PARTIAL | Existing contract display plus RHF/Zod local draft validation, malformed CIDR/port tests and invalidation on any edit. Persistence and re-evaluation blocked by absent API methods. |
| I13 | Blast-Radius Estimation | PARTIAL | Service overlay and supplied topology connections, estimated count, missing identities/topology and hypothetical downstream impacts; missing-topology/uncertainty tests. No complete impact evidence or endpoint list. |
| I14 | Safety-Gated Execution | PARTIAL | Simulator button, direct-route and handler guards; tests for violating hypotheses, aggregate violations, mandatory toggle, stale hash and missing preview. UI presentation invariant verified; server enforcement not implemented here. |
| I15 | Staged Hardening Rollout | PARTIAL | Read-only historical DEMO batches, canary events and halt flag; stage and halt tests. Production rollout, stop controls and automatic halt enforcement unavailable. |

## Actual verification results

Final implementation verification:
- corepack pnpm --dir apps/web type-check: PASS, exit 0.
- corepack pnpm --dir apps/web test: PASS, 97/97 tests across 10 files, 7.97s.
  Original Phase 0-5 suites remain passing; Phase 6 adds 28 tests.
- corepack pnpm --dir apps/web build: PASS, exit 0; 2,654 modules, 7.96s.
- git diff --check: PASS after the authorized pre-existing blank-line removal.

Tests cover actual React Flow nodes/edges and node selection, candidate selection,
weights, constraints/UNSAT, baseline/candidate views, all four verdicts, RHF validation,
contract edit invalidation, UI approval blocking including direct navigation, missing
and unsupported impact data, empty/loading/error states, API read-only behavior,
stale plan identity, tenant mismatch, historical canary telemetry and halt status.
Initial failures (ES target string API, ambiguous validation assertion and jsdom SVG
geometry) were fixed before the passing final runs; no test remains in the background.

Non-failing output: existing React Router future-flag notices and Recharts zero-size
jsdom notices. Vite reports a large bundle warning (about 1.98 MB minified JS);
no unrelated code splitting was attempted in this phase. No real-browser visual or
end-to-end device verification was performed.

## Checkpoint

Commit intended: feat(frontend): implement BaselineGuard phase 6.
Target: origin feat/apoorva-web. Full staged diff and whitespace checks are reviewed
before committing; the resulting hash and push/tracking status are reported in chat.
No Phase 7 work is included.
