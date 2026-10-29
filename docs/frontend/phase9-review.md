# Phase 9 - independent QA, freeze and integration handoff

Date: 2026-10-30, Asia/Calcutta. Starting HEAD:
0d7b8e546dc92a204754f1bab40874c8aeaa0388 (Phase 8); parent Phase 7
cc7dcf927b17d945153e352d459afa4bb156d9e6. Both matched origin history on
feat/apoorva-web; initial tree clean, correct remote, no AGENTS.md found.

All three supplied PDFs at C:/Users/HP/Downloads were read in the preceding
handover and rechecked for this phase: guide Phase 9/page 9 and screen-family
appendix, PRD 88-entry register and acceptance/security criteria, Tech Stack v3
frontend/testing/security sections. No document instruction overrides the user's
ownership/branch/commit scope. Phase 10 is user-requested, not a guide phase.

## Outcomes

- [Complete 88-feature audit](feature-coverage.md): 82 PARTIAL, 3 BLOCKED
  (E09/E10/E30), 3 UNTESTED (M25/M28/M29), zero DONE. Every immutable ID has a
  surface, evidence and explicit acceptance gap. Platform branding or a generic
  finding renderer does not prove control/vendor support. Corrected an NTP fixture
  incorrectly tagged M25 to M32; M25 remains default-deny, without dedicated tests.
- [Route inventory](routes.md) identifies planned vs actual mappings and links
  the actual 19-family audit. System States gained an owner/admin navigation link.
  Offline import and worker health remain missing, not renamed or dropped.
- [Setup/configuration/integration README and checklist](README.md) explains
  disabled-by-default runtime configuration, explicit DEMO and remaining bindings.
- Added runtime-config schema/startup loading and configurable typed client.
  Ordinary dev/production fails closed. Only explicitly approved GET /reports is
  bound to an agreed path and validated canonical response. Missing operations,
  401/403/500, malformed schemas, absent sessions and untrusted API origins never
  become fixtures. There are no write bindings or invented backend operations.
- Removed fake Supabase defaults, real-session owner/tenant assignment, password
  reset success on error/offline, and real-session local MFA-code acceptance.
  Real tenant claims/MFA integration is blocked explicitly. Synthetic persona,
  MFA example and password-reset preview remain DEMO-only.
- Added pinned ESLint/TypeScript ESLint, Playwright and axe tooling with existing
  pnpm lockfile. ESLint 10 is supported by the installed Node 22 runtime. No broad
  lint disables, test skips or type ignores were added. Fixed 14 actual lint
  findings (unused stub parameters/catch binding and equivalent empty interface).
- Browser axe found low-contrast slate text and white-on-blue buttons. Corrected
  muted-text/primary-action styles without disabling axe rules. Raw rendering
  errors are no longer displayed/logged by the error boundary; the test now also
  asserts that sensitive diagnostics are withheld.
- [Five real screenshots and index](screenshots/README.md) were captured from
  passing DEMO Chromium tests; no production-device screenshots are claimed.

## Exact verification commands and final results

| Command | Result |
| --- | --- |
| corepack pnpm --dir apps/web lint | PASS, exit 0, 0 errors/warnings |
| corepack pnpm --dir apps/web type-check | PASS, exit 0 |
| corepack pnpm --dir apps/web test | PASS, 207 discovered/passed, 0 failed/skipped; 13 files, 9.53s |
| corepack pnpm --dir apps/web build | PASS, exit 0; 2,663 modules, 11.33s |
| corepack pnpm --dir apps/web exec playwright install chromium | PASS after permission to write browser cache |
| corepack pnpm --dir apps/web test:e2e | PASS, 12 discovered/passed, 0 failed/skipped; desktop/mobile Chromium, 16.7s |
| corepack pnpm --dir apps/web test:a11y | PASS, 8 discovered/passed, 0 failed/skipped; 13.0s |
| git diff --check | PASS after removing an introduced empty EOF line |
| git diff --cached --check | Required staged gate before commit |

The 12 new Vitest tests cover adapter configuration, response validation, deny/error
behavior, absence of writes/fallback, real-session auth safety and matrix completeness.
Browser cases exercise plan selection, violating-plan approval blocks, role denial,
report limits, responsive overflow and WCAG A/AA on overview/reports/simulator/approvals.
Axe checks are automated evidence for these pages/viewports, not certification or
complete manual accessibility review. Existing 195 tests and all their suites remain.

Initial failures were investigated and fixed: pnpm store mismatch (reused existing
D:/.pnpm-store/v3 without reinstalling the project), lint errors, nullable auth client,
an unused catch/log reference, color contrast, and Windows sandboxed Vite teardown.
The first browser run was 6 failed/6 passed; failed contrast cases now pass. The
stuck test-only server was identified/stopped and direct Vite process startup plus
adequate process permissions produced a completed successful run. No test remains
running. Browser installation/download and pnpm dependency updates required permission;
no privileged application operation or message to another person was performed.

## Freeze limitations and production dependencies

The production bundle remains large: initial JS 1,761.62 kB (509.05 kB gzip), Vite
500 kB warning still present. All route shells eagerly import Cytoscape, React Flow
and Recharts. Phase 10 will investigate safe route splitting; no warning was hidden.
Existing React Router future-flag and Recharts/jsdom size notices remain non-failing.
Registry deprecation notices for existing Recharts/@types packages were not treated
as proof of a vulnerability or an excuse for a risky major-version migration.

No real backend, Supabase tenant-policy/MFA integration, device matrix, optimizer,
live simulation, approved execution, full evidence/signatures, notification delivery
or report-content reconciliation was verified. Live memberships/claims and remaining
shared contracts must be agreed by the backend owner. The read adapter is a bounded
integration seam, not a claim that legacy store-driven screens became production UI.
See [contract questions](contract-questions.md). No full feature is marked DONE.

All changes are restricted to apps/web and docs/frontend; no shared contract or
backend/device/infra file was touched. Generated dist, test reports and traces are
ignored; only the five explicitly indexed synthetic screenshots are handoff artifacts.
Full diff, new files, ownership and staged whitespace are reviewed before commit.
Commit message: feat(frontend): complete BaselineGuard phase 9 handoff.
The resulting hash and remote verification are reported in chat; Phase 10 starts
only after this checkpoint is committed, pushed and clean.
