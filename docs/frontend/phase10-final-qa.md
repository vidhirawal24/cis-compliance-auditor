# Phase 10 final frontend regression QA

Branch: `feat/apoorva-web`. Clean starting checkpoint: Phase 9
`459e24e38324497b5efb8916dd021de1cacb541e`, pushed and verified before this phase.
Its history contains Phase 7 `cc7dcf927b17d945153e352d459afa4bb156d9e6` and
Phase 8 `0d7b8e546dc92a204754f1bab40874c8aeaa0388`. Results below test the final
Phase 10 source on that parent; the resulting commit is recorded in Git history.
Phase 10 is the user's additional finalization phase, not a guide-defined phase.

## Completed checks

All final commands completed with exit 0 on Windows, Node 22/Corepack pnpm.

| Exact command | Actual result |
| --- | --- |
| `corepack pnpm --dir apps/web lint` | 0 errors, 0 warnings; source, browser tests and both browser configurations |
| `corepack pnpm --dir apps/web type-check` | PASS |
| `corepack pnpm --dir apps/web test` | 221 passed, 0 failed, 0 skipped; 14 files, including all earlier phase suites |
| `corepack pnpm --dir apps/web run test --reporter=json --outputFile=test-results/vitest-final.json` | Supplemental completed count capture: total 221, passed 221, failed 0, pending 0 |
| `corepack pnpm --dir apps/web build` | PASS, final rerun 10.29 seconds; no large-chunk warning |
| `corepack pnpm --dir apps/web test:e2e` | 28 discovered/passed, 0 failed/skipped; rerun after final sign-in text correction |
| `corepack pnpm --dir apps/web test:a11y` | 20 discovered/passed, 0 failed/skipped; final rerun 13.1 seconds; subset repeated separately |
| `corepack pnpm --dir apps/web test:production` | 3 discovered/passed, 0 failed/skipped; final rerun 6.3 seconds; built production preview |
| `git diff --check` | PASS; staged whitespace checked again before commit |

The 31 distinct browser cases comprise 28 DEMO cases (including 20 axe cases)
and three production-configuration cases. Do not add the dedicated repeated axe
run to the unique case count. No frontend suite was unavailable at the final gate.
Browser execution required permission for Chromium cache and child-process management;
both Vite servers shut down after completion. Generated reports/dist are ignored.
The first supplemental JSON invocation without `run` was rejected by pnpm's option
parser; the explicit `run test` invocation above completed successfully.

## Corrections and evidence

- `src/routes/AppRouter.tsx` loads all 19 screens lazily with an accessible loading
  status and error boundary. Previously eager imports pulled graph, flow and charts
  into the startup bundle. Main JS fell from 1,761.62 kB (gzip 509.05) to 425.02 kB
  (gzip 126.60). Largest chunk is graph 467.70 kB (gzip 148.75); chart chunk 370.28 kB,
  plan diagram 179.02 kB. All are below Vite's unchanged 500 kB warning threshold.
  Large features still download on demand; this is not a performance certification.
- `src/auth/SessionCacheBoundary.tsx` and `App.tsx` clear query caches before a
  changed user, tenant, role or adapter-auth scope renders. Logout clears local state
  even if remote sign-out fails, while Topbar/AuthShell disclose that remote failure.
  Authentication failures no longer render raw SDK diagnostics.
  Screenshot review also corrected the sign-in subtitle's unsupported claim of
  integrated tenant enforcement; it now states that server authorization and
  tenant membership integration are required. All checks were rerun afterward.
- `ScreenDataBoundary.tsx` rejects mismatched requested/returned asset identity.
  Phase 7 approval review rejects matching empty/invalid plan hashes as insufficient
  evidence; stale-plan checks remain intact. These are presentation safeguards,
  never proof of server enforcement.
- Reports and drift reads are independent in `16_ReportsHistoryShell.tsx`; missing
  drift or executive-summary support no longer hides an allowed report response.
  No new endpoint, report-generation operation or success claim was introduced.
- Findings filters have accessible names, result selection works with Enter/Space,
  and result/table scrolling is keyboard reachable. Shared table changes retain
  horizontal overflow on narrow layouts.
- `src/test/phase10.test.tsx` adds 14 safety cases: remote sign-out failure,
  diagnostic redaction, reset failure, unsupported real MFA/memberships, absent
  hashes, four non-verified execution states, asset mismatch, per-request expired
  session handling, cache isolation, public-only env placeholders and independent
  report reads. Existing phase suites still check 403, violations, bounded IDs,
  expired report access, unknown verification, unsupported operations and DEMO isolation.
- `e2e/regression.spec.ts` visits all 19 inventory families on desktop and mobile,
  exercises keyboard finding selection/filtering, and adds six axe-screen checks.
  Existing browser tests retain role denial, selected-plan violation blocking,
  report limitations and four other axe screens. `production.spec.ts` uses built
  output to verify disabled, missing and malformed configuration never grants a
  synthetic session. `playwright.production.config.ts` and package scripts isolate it
  from the explicitly DEMO development server.
- Legacy route-test helpers now await both lazy-screen and record loading. Cold
  transforms exceeded the old one-second RTL wait in an initial concurrent run;
  the shared five-second wait retains all assertions without skipping tests.
  Initial axe failures exposed unnamed filters and inaccessible scrolling; fixed
  in product code. An incorrect new fixture-title assertion was corrected to the
  actual fixture and strengthened with the one-result count. All final reruns pass.

Other changed frontend files: auth context, Topbar, AuthShell, shared table,
Phase 7 review helper; test setup and route helpers in assets/orgs/Phases 3-5;
browser capture guard in `qa.spec.ts`, package scripts and Playwright configuration.
Documentation changes: this report, README/checklist, feature matrix revalidation,
screenshot index and genuine production-disabled capture. No API, engine, infra or
shared-contract files changed. No assertions were removed to obtain a passing gate.

## Accessibility and responsive scope

Real Chromium ran desktop 1280x720 and iPhone 13 viewport 390x664. All 19 screen
families were reachable in DEMO at each size. Axe WCAG 2 A/AA and 2.1 A/AA found
no violations in the tested baseline states of overview, reports, simulator,
approvals, policies, findings, planner, verification, notifications and administration
at both sizes. The original four screens also assert no body horizontal overflow.
Findings keyboard interaction is exercised at both sizes. These checks do not cover
every dialog, focus transition, graph gesture or assistive technology.

[Screenshot index](screenshots/README.md) includes the genuine built-production
disabled-state capture and preserves the five Phase 9 DEMO captures. Screen-reader,
zoom, all dialog focus restoration and complete manual keyboard review remain open.
React Router future-flag and Recharts zero-size jsdom diagnostics remain non-failing;
they were not suppressed. No backend/device safety or accessibility certification is implied.

## Feature and integration acceptance

[Detailed immutable 88-feature matrix](feature-coverage.md): **82 PARTIAL, 3 BLOCKED,
3 UNTESTED, 0 DONE**. BLOCKED: E09, E10, E30. UNTESTED: M25, M28, M29. Every other
ID remains PARTIAL; frontend QA does not upgrade platform/engine acceptance.
The matrix links surfaces, evidence and missing acceptance requirements individually.

Only configured, runtime-validated same-origin `GET /reports` is HTTP-bound; it
requires a current session token and explicit read allowlisting. All other methods
remain unsupported outside DEMO. Real tenant memberships, role claims, MFA,
approval writes, optimization/simulation submission, execution/rollout/recovery,
dual device/service verification, proof integrity, report generation/redaction,
drift collection, notification delivery and administration writes require backend
contracts and authorized integration environments. Production has no silent fixture
fallback. No real approval, export contents, ticket delivery or device mutation was
verified. Supabase in unit tests is mocked, not a real authentication service test.

This is independent frontend verification, **not backend-integrated end-to-end
product verification**. Bounded UI gates do not replace server authorization.

## Reproduction and remaining manual work

Follow [setup and adapter configuration](README.md). Build before `test:production`;
ports 3000/3001 must be free. Browser installation command is
`corepack pnpm --dir apps/web exec playwright install chromium`.

1. With backend owners, confirm canonical report payload, tenancy and authorized
   token use; exercise actual 401/403/expiry and signed-artifact retrieval without
   copying signed URLs or credentials into logs/screenshots.
2. Integrate real organization claims and MFA challenge/factor operations before
   testing login, session refresh and cross-tenant navigation against real services.
3. Use authorized lab devices and approved changes to verify backup/dry-run,
   stale approvals, rollout/recovery, CIS plus service-health evidence and hashes.
   No frontend fixture can satisfy those acceptance gates.
4. Reconcile backend-redacted PDF/HTML/CSV/JSON contents and audit/integration delivery
   against actual evidence. Unsupported operations must remain blocked meanwhile.
5. Manually traverse all navigation/forms/dialogs with keyboard and a screen reader
   at desktop, mobile and zoomed layouts; test graph alternatives and focus return.

Final staged review must keep changes within `apps/web/` and `docs/frontend/`,
exclude generated outputs/secrets, pass cached whitespace checks, and preserve the
pushed Phase 9 parent. Commit/push confirmation is recorded by the final Git gate.
