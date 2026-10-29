# Genuine DEMO browser captures

Captured by `apps/web/e2e/qa.spec.ts` using Playwright Chromium after the corresponding
WCAG A/AA axe checks passed. They show synthetic fixtures, never production devices.
Reproduce with `corepack pnpm --dir apps/web test:e2e` (port 3000 must be free).

| File | Screen / viewport |
| --- | --- |
| phase9-overview-desktop-chromium.png | Overview, desktop 1280x720 |
| phase9-reports-desktop-chromium.png | Reports, desktop 1280x720 |
| phase9-simulator-desktop-chromium.png | Simulator, desktop 1280x720 |
| phase9-approvals-desktop-chromium.png | Approvals, desktop 1280x720 |
| phase9-reports-mobile-chromium.png | Reports, iPhone 13 viewport 390x664 |

These are visual evidence for these screens, not an all-screen accessibility or
production integration certification. Automated HTML reports and traces are ignored.

`phase10-production-disabled.png` is a separate genuine capture of the built
production app refusing DEMO sign-in with disabled configuration. Reproduce after
`build` with `corepack pnpm --dir apps/web test:production` on port 3001. It shows
an unavailable workflow, not a successful production integration. Phase 9 captures
are preserved rather than overwritten by subsequent regression runs.
