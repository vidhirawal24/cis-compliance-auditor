# BaselineGuard Phase 8 review

## Sequential checkpoint and authoritative sources

Phase 8 began only after Phase 7 passed its gate and was pushed as
cc7dcf927b17d945153e352d459afa4bb156d9e6. git ls-remote confirmed that exact
origin/feat/apoorva-web hash, upstream tracking and a clean tree. Phase 6 starting
checkpoint was 1854d403c6ed4f6c2362e6a0e85b658375f313bf, also verified.

Read all three user-supplied PDFs from C:/Users/HP/Downloads:
CISGuard_360_Apoorva_Parallel_Development_Guide.pdf,
CISGuard_360_Complete_PRD_v1.pdf and CISGuard_360_Final_Tech_Stack_v3.pdf.
Authoritative references: guide pages 3-4 (19 families) and 9 (Phase 8); PRD
pages 7-9 (M38, E05-E07, E19, E26-E30), section 10 (privacy/tenant/storage),
section 13.2 (evidence required for DONE); Tech Stack sections 12-15.
The PDFs specify behavior, not evidence that any backend already exists. The
user's branch/ownership/separate-commit instructions govern this workflow.

## Implementation and changed files

New files:
- apps/web/src/features/phase8/ReportAccess.tsx: supplied-URL retrieval, expiry
  checks at display/click/response time, live expiry update, pending/error/denied
  states, abort/timeout and temporary object-URL revocation. DEMO URLs cannot be fetched.
- apps/web/src/features/phase8/ExecutiveSummary.tsx: typed scans/assets/findings/
  risk/trend reads, separate backend compliance and coverage, explicit range,
  freshness, missing metadata, Recharts tooltip/legend and exact-value table.
- apps/web/src/features/phase8/SnapshotHistory.tsx: asset-scoped references from
  supplied drift history; no invented snapshot, encryption or integrity claim.
- apps/web/src/components/common/ScreenDataBoundary.tsx: route-family inventory,
  async DEMO preflight, safe loading/empty/error/401/403 states and explicit
  production unsupported boundaries for fixture-only/unbound legacy workflows.
- apps/web/src/fixtures/phase8Data.ts: typed, explicitly synthetic delivery examples.
- apps/web/src/test/phase8.test.tsx: 78 new focused tests.
- docs/frontend/phase8-review.md: this evidence and limitations record.

Updated files:
- apps/web/src/routes/shells/16_ReportsHistoryShell.tsx: report formats/filtering,
  metadata/access, drift timeline/filtering, executive summary and generation limits.
- apps/web/src/routes/shells/17_NotificationsTicketsShell.tsx: unsupported real
  integration state, DEMO status examples, no sending/ticket creation/retry claims.
- apps/web/src/routes/shells/18_AdminSecurityShell.tsx: current context/RBAC,
  explicit unsupported member/role/retention/key operations and filtered audit table.
- apps/web/src/routes/shells/05_AssetDetailShell.tsx: snapshot route/tab now shows
  supplied references instead of a hardcoded archive/hash/encryption assertion.
- apps/web/src/routes/shells/19_SystemStatesShell.tsx: clearly labeled DEMO gallery;
  removed an unsupported certification claim.
- apps/web/src/api/context.tsx: adapter identity keys prevent cross-adapter cache reuse.
- apps/web/src/features/phase6/model.ts and routes/shells/14_ApprovalsHardeningShell.tsx,
  routes/shells/15_VerificationProofShell.tsx: cache isolation only; safety gates retained.
- apps/web/src/components/common/ApiState.tsx: no retry for 401/403 or explicit
  retryable=false; no raw transport error/token echoed.
- apps/web/src/components/layout/AppLayout.tsx and routes/AppRouter.tsx: apply source
  boundaries, block real sessions with the DEMO-only adapter, honest offline message.
- apps/web/src/components/layout/MobileNav.tsx: Escape, focus containment and restore.
- apps/web/src/test/renderWorkspace.tsx: install role before mounting privileged views.
- apps/web/src/test/routes.test.tsx, assets_phase2.test.tsx, orgs_phase2.test.tsx,
  phase3.test.tsx, phase4.test.tsx, phase5.test.tsx: await asynchronous data readiness;
  all existing behavior assertions/test counts retained.
- apps/web/src/test/setup.ts: missing jsdom Canvas geometry methods for longer graph renders.
- docs/frontend/contract-questions.md: remaining integration contracts.

No packages, lockfile, shared wire contracts, backend, device engine or infrastructure
changed. Build output is ignored and not staged. Existing design primitives, table
wrapper, TanStack Query and Recharts were reused; no duplicate table stack added.

## Report access, privacy and provenance

Only existing GeneratedReport.download_url and signed_url_expires_at are consumed.
No generation/refresh endpoint or signed URL is constructed. Four format slots show
available records or explain missing artifacts. DEMO URLs are never retrieved.
For a real adapter, explicit user action fetches only the supplied HTTPS URL, with
credentials omitted, no referrer, no cache and redirects rejected. URLs containing
userinfo, missing/malformed expiry and expired URLs cannot be used. Expiry is checked
again before the browser save request; HTTP 401/403 and failures remain explicit.
The UI says artifact retrieved/save requested, never that the user's download completed.
Signed tokens are not displayed, logged, copied to local storage or put in link markup.

No browser-generated report is substituted for a backend artifact. The frontend
does not add actor emails, credentials or local context to exported bytes. Artifact
redaction, original authorization, canonical audit reconciliation, MIME/content
validation and secure storage are still backend responsibilities; PDF/HTML/CSV/JSON
content privacy/reconciliation has NOT been independently audited against a server.
Cross-tenant metadata responses are rejected before rendering. Audit display omits
IP addresses and emails and labels supplied hashes as unverified.

Executive compliance/coverage values are displayed verbatim from a completed scan.
Counts are labeled returned-record counts, not authoritative fleet totals. Trends
have no benchmark/tenant metadata in v1; that limitation is shown. Snapshot events
do not imply continuous monitoring or unauthorized change. Historical delta text is
shown as supplied; full artifacts, control IDs and hash/encryption checks remain unknown.

Notifications have no typed API methods. Production therefore shows unsupported,
not a fabricated delivery failure/receipt/ticket. Synthetic examples are DEMO only.
Member enumeration/role writes/retention/API-key operations also have no supported
methods and never report saved settings or newly created identities/keys.

## Actual 19-screen-family inventory and edge coverage

L/E/N/A below means loading, empty/missing, network/server and unauthorized/forbidden.
For legacy families these are route-boundary behaviors, not a claim that each old
widget has been converted to production API state. AuthGuard remains UX only; server
authorization is still required. Production adapters are not configured by this phase.

| Family | Actual primary route | State/source coverage and limits |
| --- | --- | --- |
| 01 Authentication | /auth/* | Existing form validation, submitting/auth failure/MFA/reset; no record-empty state applies. Tenant membership/invites and real-role integration still PARTIAL. |
| 02 Organizations | /orgs | DEMO preflight L/E/N/A; production fixture binding blocked. Empty workspace is explicit; no fabricated membership. |
| 03 Overview | /orgs/:orgId/overview | DEMO scan preflight L/E/N/A; existing charts/status assertions retained. Production fixture-only screen blocked. |
| 04 Assets | /orgs/:orgId/assets | DEMO inventory L/E/N/A and existing filters/forms. Production legacy store binding blocked. |
| 05 Asset detail | /orgs/:orgId/assets/:assetId | Scoped asset read/error gate, no rendering after missing requested asset; snapshot references L/E/N/A. Production legacy binding blocked. |
| 06 Scan center | /orgs/:orgId/scans | DEMO queue L/E/N/A; existing schedule/error/retry/read-only tests retained. Production legacy mutations blocked. |
| 07 Policies | /orgs/:orgId/policies | DEMO pack L/E/N/A; profile/override/version missing-state tests retained. Production legacy binding blocked. |
| 08 Exceptions/manual reviews | /orgs/:orgId/exceptions; /manual-reviews | DEMO scoped collections L/E/N/A; original FAIL-overlay/evidence/role tests retained. Production legacy binding blocked. |
| 09 Findings | /orgs/:orgId/findings | DEMO L/E/N/A; original expected/observed/evidence/filter tests retained. Production legacy binding blocked. |
| 10 Security graph | /orgs/:orgId/graph | DEMO graph L/E/N/A; interactive graph/table/filters remain. Production legacy binding blocked. |
| 11 Risk scenarios | /orgs/:orgId/risk-scenarios; /scenarios | DEMO L/E/N/A; original uncertainty/path tests retained. Production legacy binding blocked. |
| 12 Planner | /orgs/:orgId/planner | Phase 6 loading, empty, error, UNSAT and insufficient/unsupported data. Production plan/revision binding blocked; no synthetic default IDs requested. |
| 13 Simulator | /orgs/:orgId/simulator | Phase 6 typed states/contract gate retained. Production simulation binding blocked; no default DEMO IDs requested. |
| 14 Approvals/execution | /orgs/:orgId/approvals; /changes/:changeId | Phase 7 L/E/N/A, stale/precheck/violation blockers retained. Production submission/revision/execution binding blocked. |
| 15 Verification/proof | /orgs/:orgId/verifications; /proof-packages/:packageId | Phase 7 loading/error/denied/unknown/unsupported/missing proof states retained. Production verification resolution blocked. |
| 16 Reports/history | /orgs/:orgId/reports; /reports/drift; /reports/executive | Independent report/summary queries with L/E/N/A, expired/unavailable/retrieval errors, filtering and exact-value trend alternative. |
| 17 Notifications/tickets | /orgs/:orgId/notifications; /integrations | Production UNSUPPORTED with no fallback; network/loading/delivery responses cannot be invented without an endpoint. DEMO statuses show their source. |
| 18 Admin/security | /orgs/:orgId/admin/* | Current context, read-role guard and server audit L/E/N/A; unsupported settings/member/key operations explicit. |
| 19 System states | /orgs/:orgId/system-states | Explicitly synthetic gallery of loading/empty/error/denied/offline/unsupported/partial examples, not live outcome claims. |

The 19 smoke tests remain passing. Matrix tests additionally exercise all 10 legacy
families for loading/ready, network failure, 403, unsupported production source and
9 collection-empty cases (asset detail uses missing-resource errors). Four production
workflow guards are tested separately. This is not full browser/device acceptance.

Responsive/accessibility: reused horizontally scrolling semantic tables; wrapping
controls/grid layouts; named selects/inputs, pressed-state buttons, status/alert
announcements, chart tooltip/legend/exact-value table. Mobile navigation Escape and
Tab containment are tested. Automated contrast/viewport/real-browser keyboard and
screen-reader audits remain UNTESTED. No axe/Playwright package/config/script is
installed; the requested checks were unavailable, not claimed as passed.

## PRD feature mapping and evidence

| ID | Exact PRD feature | Status | Evidence and missing backend capability |
| --- | --- | --- | --- |
| M38 | Reports and scale | PARTIAL | Four supplied artifact format slots and retrieval/expiry/403 tests; report generation, real four-format reconciliation and scale testing unavailable. |
| E05 | Drift alerts | PARTIAL | Supplied snapshot deltas/filter/history/empty tests; detection and live delivery are backend-owned and unverified. |
| E06 | Configuration snapshots | PARTIAL | Per-asset historical snapshot references, removed fabricated archive/encryption claims; encrypted enumeration/retrieval/hash-check API missing. |
| E07 | Compliance trends | PARTIAL | Backend series, separate compliance/coverage chart and exact table, missing-series tests; benchmark-consistency metadata absent. |
| E19 | Application audit trail | PARTIAL | Typed scoped events/filter/403/minimized table; append-only integrity and complete event coverage not established. |
| E26 | Alerts/webhooks | PARTIAL | Truthful unsupported production UI plus synthetic status examples; delivery/configuration/test/retry API absent. |
| E27 | Ticket integrations | PARTIAL | Honest missing ticket/destination/receipt and disabled creation/retry; idempotent ticket API absent. |
| E28 | Executive reporting | PARTIAL | Backend scan scores/range/freshness/record counts and exact trends; technical-report reconciliation and summary endpoint missing. |
| E29 | Search/filter interface | PARTIAL | Report format/text, drift asset and audit action/target filters plus earlier asset/finding filters; persisted/secured saved filters absent. |
| E30 | External integration API | BLOCKED | No documented runtime API/key/rate-limit capabilities supplied; explicit unavailable settings only. Backend integration cannot be inferred from the client interface. |

No full backend-dependent feature is marked DONE for a UI or installed library alone.
Phase 6 I06-I15 limitations and Phase 7 production blockers remain in force.

## Verification gate

- corepack pnpm --dir apps/web type-check: PASS, exit 0.
- corepack pnpm --dir apps/web test: PASS, 195/195 tests across 12 files. Includes
  all 117 Phase 0-7 tests plus 78 Phase 8 tests; no tests remain running.
- corepack pnpm --dir apps/web build: PASS, exit 0; Vite build completed in 7.85s.
- git diff --check: PASS; new files and staged whitespace/ownership checked before commit.
- Lint: unavailable (no lint script/configuration/ESLint dependency).
- Playwright/axe: unavailable (no script/configuration/dependencies). No accessibility
  audit passed claim; only the documented jsdom semantics/keyboard assertions ran.

Initial regressions were asynchronous mount assumptions in older tests and missing
jsdom Canvas methods, plus a collection union type mismatch. Fixed before the final
passing commands. Original behavior assertions were retained, with helpers awaiting
loading completion. Existing Recharts zero-size/jsdom, React Router future-flag and
Vite large-chunk warnings remain non-failing. No real backend, device, external
delivery, artifact-content reconciliation or full security/accessibility audit ran.

Checkpoint message: feat(frontend): implement BaselineGuard phase 8. Commit hash,
push confirmation and clean tracking state are reported in chat after verification.
No main merge or Phase 9 work is included.
