# BaselineGuard Phase 7 review

Date: 2026-10-29, Asia/Calcutta. Scope: E21-E25, I14-I18 frontend presentation.

## Verified starting point and sources

Repository D:/Mini_Project_Hackathon, branch feat/apoorva-web, remote
https://github.com/vidhirawal24/cis-compliance-auditor.git. Initial tree clean;
HEAD and tracked origin ref both 1854d403c6ed4f6c2362e6a0e85b658375f313bf.
Its parent is Phase 5 commit 2c95045; Phase 3 and 4 history matches the handover.
Baseline: 97 tests in 10 files passed. No AGENTS.md found in repository/parent.

The user supplied the actual PDF paths during implementation. Read all three using
Git's pdftotext, without adding PDF tools or dependencies to the project:
- C:/Users/HP/Downloads/CISGuard_360_Apoorva_Parallel_Development_Guide.pdf
- C:/Users/HP/Downloads/CISGuard_360_Complete_PRD_v1.pdf
- C:/Users/HP/Downloads/CISGuard_360_Final_Tech_Stack_v3.pdf

The earlier source-availability blocker is resolved. Phase 6's historical review
accurately describes what was available then and is unchanged. Authoritative
references: guide page 9 Phase 7; PRD page 8 E21-E25, page 9 I14-I18,
sections 9.1-9.4 pages 14-15 (state machine, approval invalidation, dual checks,
proof). Tech Stack sections 11-14 define execution/evidence boundaries.
PDF workflow examples do not override the user's branch, ownership or commit rules.

Inspected README, phase reviews, feature map, UI component plan, routing/navigation,
auth/tenant guards, Phase 4-6 screens, API/client store, schemas/types, fixtures and
tests. Reused existing TanStack Query, UI primitives and Phase 6 safety state.

## Changed files and behavior

- apps/web/src/components/common/ApiState.tsx: loading, safe transport error,
  401/403 messages and retry for reads. Raw errors may include sensitive URLs;
  they are not echoed into the UI.
- apps/web/src/features/phase7/review.ts: stale approval/separation checks,
  hash-shape validation and conservative dual-verification outcome calculation.
- apps/web/src/routes/shells/14_ApprovalsHardeningShell.tsx: role-aware approval
  history/filter, immutable local review snapshot, stale-content detection even
  with reused hash, command previews, prerequisites, explicit backup/dry-run/safety
  unknowns, rollout events, canary halt, recovery guidance and disabled write paths.
- apps/web/src/routes/shells/15_VerificationProofShell.tsx: typed control/service
  verification, backend state gating, residual risk and proof manifest. Removed
  unconditional SUCCESS, fixed control/service claims and integrity claims.
- apps/web/src/api/store.ts: reset now restores approval/change/verification/proof
  records so synthetic mutation tests do not contaminate subsequent tests.
- apps/web/src/test/renderWorkspace.tsx: shared test provider/role helper.
- apps/web/src/test/phase7.test.tsx: 20 regression tests.
- apps/web/src/test/phase6.test.tsx: adds AuthProvider to the existing mount helper;
  all 28 assertions/tests retained, including violation blocking.
- docs/frontend/phase7-review.md and contract-questions.md: handoff and gaps.

## Supported operations and deliberate blockers

Reads use existing getApprovals, getChange, getProofPackage, getVerification and
Phase 6 getRemediationPlan/getSimulation/getSafetyContracts/getSecurityGraph.
No wire type or endpoint was added. DemoApiClient is still the only implementation.
The declared approvePlan and executeChange methods are NOT called by these views:
the adapter fabricates DEMO actors, while immutable server submission/target revision,
current dry-run, restore readiness and safety attestation are missing. No production
capability is inferred from a method declaration. Approval/execute controls show why
they are blocked, and no arbitrary CLI input or request path exists.

The Phase 6 preview gate remains in place. The history can be read while progression
is blocked; historical approval does not authorize a new execution. The immutable
local snapshot is explicitly not a server submission. Backend plan/target snapshot
binding and actor enforcement remain integration requirements.

SUCCESS requires a linked backend change in VERIFIED, overall_verified=true, and
both control and service PASS. Failed, unsupported, insufficient evidence and unknown
outcomes are separate. Record IDs are cross-checked. Service/control IDs, expected/
observed details and evidence URIs missing from v1 are explicitly unavailable.
Proof hashes are shape-checked only, not independently verified. The manifest flag
is described as a backend assertion; false/missing never means verified. Proof
downloads are blocked because expiry/retrieval behavior is undefined. No fabricated
artifact, download, approval, actor or timestamp is created by these screens.

## Feature evidence (PRD definitions)

| ID | PRD feature | Status | Evidence and remaining dependency |
| --- | --- | --- | --- |
| E21 | Approved auto-remediation | PARTIAL | Bounded change record/preconditions and no CLI submission tests; production allowlist, authorization and journaled execution blocked. |
| E22 | Dry-run preview | PARTIAL | Immutable intended commands/prerequisites; dry-run status UNKNOWN; typed validated diff/check result missing. |
| E23 | Approval workflow | PARTIAL | Decision history/filter, reviewer/reason/time, role separation and stale-content tests; server submit/reject and target revision binding missing. |
| E24 | Backup/recovery | PARTIAL | Hash and reported readiness displayed honestly, recovery guidance and missing retry support; restore verification/recovery APIs missing. |
| E25 | Post-fix re-audit | PARTIAL | Linked verification record displayed; automatic trigger and original-finding linkage absent. |
| I14 | Safety-gated execution | PARTIAL | Phase 6 violation gate preserved; unknown prechecks prevent writes. Server safety enforcement remains backend-owned. |
| I15 | Staged rollout | PARTIAL | Batch/state/events/halt display with failed/manual-recovery tests; per-target scope and stop/retry APIs absent. |
| I16 | Dual verification | PARTIAL | Control/service checks and VERIFIED+both-PASS gate tested; live service/evidence provenance still missing. |
| I17 | Residual risk measurement | PARTIAL | Backend baseline/residual values and missing calculation provenance shown; reproducible post-state calculation backend-owned. |
| I18 | Proof-of-Hardening dossier | PARTIAL | Linked manifest, supplied hashes/signer/time, missing-artifact and unverified states; full before/after evidence and signature verification absent. |

No end-to-end ID is marked DONE without backend/device evidence (PRD section 13.2).

## Verification gate

- corepack pnpm --dir apps/web type-check: PASS, exit 0.
- corepack pnpm --dir apps/web test: PASS, 117/117 tests, 11 files (7.24s).
- corepack pnpm --dir apps/web build: PASS, 2,656 modules (7.94s).
- git diff --check: PASS. Staged whitespace and ownership checked before commit.
- No lint script, ESLint configuration, Playwright or axe dependency/configuration
  exists in this repository; these checks were unavailable, not reported as passed.
- Existing React Router/Recharts test notices and Vite large-chunk warning remain.

The first focused run exposed incomplete fixture reset behavior; fixed before the
passing full run. No tests remain running. No real device, browser accessibility,
server authorization, independent signature or artifact retrieval audit is claimed.
Only apps/web and docs/frontend changed; no generated artifacts/shared contracts.

Checkpoint message: feat(frontend): implement BaselineGuard phase 7.
Commit/push hash is reported in chat after remote confirmation. Phase 8 starts only
after this checkpoint is verified and pushed.
