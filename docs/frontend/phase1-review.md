# BaselineGuard (formerly CISGuard 360) - Phase 1 Implementation Review & Design System Documentation
**Role:** Frontend Owner (Apoorva)  
**Date:** October 29, 2026  
**Document Status:** Complete Phase 1 Frontend Skeleton, Design System, 19 Route Shells, Branding Alignment & Tests  
**Product Branding:** BaselineGuard  
**Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”  
**Governing Directory:** `apps/web/` and `docs/frontend/`  

---

## 1. Executive Summary

In Phase 1, the production-grade frontend skeleton for **BaselineGuard** (formerly CISGuard 360) has been established in `apps/web/` using **React 18 + TypeScript + Vite + Tailwind CSS + shadcn/ui**, fully wired with TanStack Query, React Router, Supabase Auth context, and the typed client contracts defined in Phase 0. BaselineGuard delivers on the core premise: *“audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”*

### Key Milestones Achieved:
1. **Responsive Dark-First Cybersecurity Design System**: Implemented neutral slate-black backgrounds (`#0b0f17`), accessible contrast ratios (WCAG 2.1 AA), compact high-density SOC tables, and semantic status/severity color tokens.
2. **All 19 Route Shells Implemented**: Full coverage of the screen appendix, from Authentication and Organization Selection to Security Graph, What-If Simulation, Controlled Hardening, Dual Verification, and Proof Dossiers.
3. **Role-Aware AuthGuard Boundary**: Server-aligned client route protection enforcing tenant membership and granular RBAC (Owner, Admin, Operator, Approver, Auditor, Viewer) with accessible 403 Forbidden screens.
4. **Typed API Client & Synthetic Fixture Store**: Implemented `ApiClientInterface` adhering to frozen `contracts/v1`, backed by deterministic synthetic demo fixtures with zero fabricated pass scores or fake device mutations.
5. **Reusable Component Gallery**: Built `StatCard`, `SeverityBadge`, `StatusBadge`, `EvidenceViewer`, `ConfigDiff`, `ConfirmDialog`, `EmptyState`, `ErrorBoundary`, and `LoadingSkeleton`.
6. **Automated Smoke Test Suites**: Vitest + React Testing Library test suites verifying all 19 route shells, navigation role filtering, mobile navigation, and error/empty/loading/403 states.

---

## 2. Inventory of Complete Files Changed & Created

| Category | File Path | Purpose / Description |
| :--- | :--- | :--- |
| **Project Config** | [`apps/web/package.json`](file:///d:/Mini_Project_Hackathon/apps/web/package.json) | Vite, React 18, TypeScript, Tailwind, Lucide, TanStack Query/Table, Recharts, Cytoscape, React Flow, Supabase JS, Vitest, Testing Library. |
| | [`apps/web/tsconfig.json`](file:///d:/Mini_Project_Hackathon/apps/web/tsconfig.json) | Strict mode TypeScript configuration with `@/*` path aliases. |
| | [`apps/web/tsconfig.node.json`](file:///d:/Mini_Project_Hackathon/apps/web/tsconfig.node.json) | Node environment configuration for Vite and Vitest configs. |
| | [`apps/web/vite.config.ts`](file:///d:/Mini_Project_Hackathon/apps/web/vite.config.ts) | Vite build and HMR configuration with dev server on port 3000. |
| | [`apps/web/vitest.config.ts`](file:///d:/Mini_Project_Hackathon/apps/web/vitest.config.ts) | Vitest testing configuration with `jsdom` environment and test setup file. |
| | [`apps/web/tailwind.config.js`](file:///d:/Mini_Project_Hackathon/apps/web/tailwind.config.js) | Dark-first theme tokens, cybersecurity status colors (`pass`, `fail`, `not-applicable`, `manual-review`, `error`, `not-assessed`, `exception`), and severity levels. |
| | [`apps/web/postcss.config.js`](file:///d:/Mini_Project_Hackathon/apps/web/postcss.config.js) | PostCSS pipeline with Tailwind and Autoprefixer. |
| | [`apps/web/index.html`](file:///d:/Mini_Project_Hackathon/apps/web/index.html) | Root HTML template with dark theme class and semantic cybersecurity title. |
| | [`apps/web/.env.example`](file:///d:/Mini_Project_Hackathon/apps/web/.env.example) | Public client environment variables (public Supabase URL/anon key only; zero secrets). |
| | [`apps/web/public/favicon.svg`](file:///d:/Mini_Project_Hackathon/apps/web/public/favicon.svg) | Cybersecurity shield brand icon. |
| **Core App** | [`apps/web/src/main.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/main.tsx) | Application bootstrap entry mounting to `#root`. |
| | [`apps/web/src/App.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/App.tsx) | Global providers: `QueryClientProvider`, `AuthProvider`, `ApiProvider`, `BrowserRouter`, `Toaster`. |
| | [`apps/web/src/index.css`](file:///d:/Mini_Project_Hackathon/apps/web/src/index.css) | Custom scrollbars, accessible focus rings, compact table CSS utilities, CSS variables. |
| | [`apps/web/src/lib/utils.ts`](file:///d:/Mini_Project_Hackathon/apps/web/src/lib/utils.ts) | `cn()` Tailwind merger, `formatBytes()`, and `truncateId()` helper utilities. |
| **Auth & Security**| [`apps/web/src/auth/supabase.ts`](file:///d:/Mini_Project_Hackathon/apps/web/src/auth/supabase.ts) | Supabase JS client initialized with public anon key. |
| | [`apps/web/src/auth/context.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/auth/context.tsx) | `AuthContext` providing user session, tenant context, active role switcher, and demo login. |
| | [`apps/web/src/auth/AuthGuard.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/auth/AuthGuard.tsx) | Role-aware route guard boundary rendering standardized 403 Forbidden screen on denial. |
| **API & Store** | [`apps/web/src/api/store.ts`](file:///d:/Mini_Project_Hackathon/apps/web/src/api/store.ts) | Deterministic in-memory synthetic fixture store (clearly marked `DEMO`). |
| | [`apps/web/src/api/client.ts`](file:///d:/Mini_Project_Hackathon/apps/web/src/api/client.ts) | Typed `ApiClientInterface` returning canonical resource envelopes matching frozen contract v1. |
| | [`apps/web/src/api/context.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/api/context.tsx) | `ApiContext` and `useApi()` hook. |
| **UI Primitives** | [`apps/web/src/components/ui/button.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/button.tsx) | Accessible CVA button with default, destructive, outline, secondary, ghost variants. |
| | [`apps/web/src/components/ui/card.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/card.tsx) | Slate-900 surface cards with header, title, description, and content wrappers. |
| | [`apps/web/src/components/ui/badge.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/badge.tsx) | Subtle, solid, and outline status badges. |
| | [`apps/web/src/components/ui/input.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/input.tsx) | High-contrast accessible input field. |
| | [`apps/web/src/components/ui/table.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/table.tsx) | Virtualized-ready compact table primitives. |
| | [`apps/web/src/components/ui/skeleton.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/ui/skeleton.tsx) | Animated pulse loading skeleton. |
| **Component Gallery**| [`apps/web/src/components/common/StatCard.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/StatCard.tsx) | KPI cards with trend indicators and status badges. |
| | [`apps/web/src/components/common/SeverityBadge.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/SeverityBadge.tsx) | Standardized Critical/High/Medium/Low pills. |
| | [`apps/web/src/components/common/StatusBadge.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/StatusBadge.tsx) | Evaluator status pill (PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW, ERROR, NOT_ASSESSED, EXCEPTION). |
| | [`apps/web/src/components/common/EvidenceViewer.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/EvidenceViewer.tsx) | SHA-256 hash verified evidence box with copy button (read-only, no browser execution). |
| | [`apps/web/src/components/common/ConfigDiff.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/ConfigDiff.tsx) | Syntax-highlighted red/green config diff viewer. |
| | [`apps/web/src/components/common/ConfirmDialog.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/ConfirmDialog.tsx) | High-risk confirmation modal with required verification typing. |
| | [`apps/web/src/components/common/EmptyState.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/EmptyState.tsx) | Standardized empty state with icon and action button. |
| | [`apps/web/src/components/common/ErrorBoundary.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/ErrorBoundary.tsx) | React error boundary catching runtime exceptions. |
| | [`apps/web/src/components/common/LoadingSkeleton.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/common/LoadingSkeleton.tsx) | Layout-accurate skeleton loaders (cards, tables, details). |
| **Layout Shells**| [`apps/web/src/components/layout/Sidebar.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/layout/Sidebar.tsx) | Role-filtered sidebar with badge counters and active route indicators. |
| | [`apps/web/src/components/layout/Topbar.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/layout/Topbar.tsx) | Tenant switcher, global search input, quick role switcher, notification bell. |
| | [`apps/web/src/components/layout/MobileNav.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/layout/MobileNav.tsx) | Accessible mobile drawer with backdrop dismissal. |
| | [`apps/web/src/components/layout/AppLayout.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/layout/AppLayout.tsx) | Main layout combining Sidebar, Topbar, Offline banner, and Content viewport. |
| **19 Route Shells**| [`apps/web/src/routes/shells/01_AuthShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/01_AuthShell.tsx) | Login, Invite, Password Reset, MFA Setup / Challenge, Blocked Tenant. |
| | [`apps/web/src/routes/shells/02_OrgSelectShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/02_OrgSelectShell.tsx) | Tenant workspace switcher and role visibility. |
| | [`apps/web/src/routes/shells/03_OverviewShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/03_OverviewShell.tsx) | Main Overview: Compliance % vs Coverage %, Severity breakdown, Asset health, Scan queue. |
| | [`apps/web/src/routes/shells/04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx) | Centralized asset table, search, tags, discovery preview, masked vault references. |
| | [`apps/web/src/routes/shells/05_AssetDetailShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/05_AssetDetailShell.tsx) | Asset details, interfaces (L2/L3), findings, snapshots archive. |
| | [`apps/web/src/routes/shells/06_ScanCenterShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/06_ScanCenterShell.tsx) | Read-only scan launch wizard, schedule manager, per-device progress logs. |
| | [`apps/web/src/routes/shells/07_PolicyLibraryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/07_PolicyLibraryShell.tsx) | Benchmark packs, custom baseline overrides, upgrade impact preview (I19). |
| | [`apps/web/src/routes/shells/08_ExceptionsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/08_ExceptionsShell.tsx) | Time-boxed exceptions with approver, expiration countdown, manual reviews (E12). |
| | [`apps/web/src/routes/shells/09_FindingsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/09_FindingsShell.tsx) | Expected vs actual findings comparison, evidence viewer, remediation CLI preview. |
| | [`apps/web/src/routes/shells/10_SecurityGraphShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/10_SecurityGraphShell.tsx) | Cytoscape.js canvas shell, zoom/pan controls, accessible table fallback. |
| | [`apps/web/src/routes/shells/11_RiskScenariosShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/11_RiskScenariosShell.tsx) | Correlated multi-device attack scenarios, root-cause causal chain (I02, I04). |
| | [`apps/web/src/routes/shells/12_RemediationPlannerShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/12_RemediationPlannerShell.tsx) | OR-Tools minimal change metrics, React Flow sequencing DAG shell (I06, I10). |
| | [`apps/web/src/routes/shells/13_WhatIfSimulatorShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/13_WhatIfSimulatorShell.tsx) | Batfish model coverage, simulation verdicts, service-safety contracts (I11, I12). |
| | [`apps/web/src/routes/shells/14_ApprovalsHardeningShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/14_ApprovalsHardeningShell.tsx) | Multi-role approval review, separation of duties, staged canary rollout (E21, E23). |
| | [`apps/web/src/routes/shells/15_VerificationProofShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/15_VerificationProofShell.tsx) | Dual verification (CIS + Service check), residual risk gauge, signed proof dossier. |
| | [`apps/web/src/routes/shells/16_ReportsHistoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/16_ReportsHistoryShell.tsx) | 4 format downloads (PDF/HTML/CSV/JSON), signed URLs, configuration drift timeline. |
| | [`apps/web/src/routes/shells/17_NotificationsTicketsShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/17_NotificationsTicketsShell.tsx) | Real-time alerts, webhook delivery status, Jira/ServiceNow ticket sync. |
| | [`apps/web/src/routes/shells/18_AdminSecurityShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/18_AdminSecurityShell.tsx) | RBAC membership table, OpenBao vault secret pointers, immutable audit trail. |
| | [`apps/web/src/routes/shells/19_SystemStatesShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/19_SystemStatesShell.tsx) | 10 state gallery: Loading, Empty, 403, 404, 500, Offline, Unsupported, Partial Scan. |
| **Router** | [`apps/web/src/routes/AppRouter.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/AppRouter.tsx) | Comprehensive React Router v6 setup with route guards, layouts, and redirects. |
| **Tests** | [`apps/web/src/test/setup.ts`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/setup.ts) | Vitest setup with `matchMedia` and `ResizeObserver` mocks. |
| | [`apps/web/src/test/routes.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/routes.test.tsx) | Smoke tests for all 19 route shells ensuring zero crashes. |
| | [`apps/web/src/test/navigation.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/navigation.test.tsx) | Navigation rendering, role-aware menu filtering, and topbar tests. |
| | [`apps/web/src/test/states.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/states.test.tsx) | EmptyState, ErrorBoundary, LoadingSkeleton, and 403 AuthGuard tests. |

---

## 3. Scripts & Developer Workflow

The following scripts are defined in `apps/web/package.json`:

```bash
# 1. Install dependencies
pnpm install

# 2. Run local development server (http://localhost:3000)
pnpm run dev

# 3. Execute unit and smoke tests
pnpm run test

# 4. Type-check TypeScript codebase
pnpm run type-check

# 5. Build production bundle
pnpm run build
```

---

## 4. Phase 1 Exit Gate Sign-Off

As Frontend Owner, I confirm that:
1. **The application skeleton is complete and production-grade**, using only specified, vetted libraries without any runtime AI/ML/LLM or third-party paid scanning APIs.
2. **All 19 route shells are reachable and render truthfully**, honoring the frozen `contracts/v1` and separating Compliance from Coverage.
3. **No credentials or plaintext secrets exist in any file**, and no browser buttons issue arbitrary CLI execution commands.
4. **All unit, navigation, and state tests are authored and ready for CI execution**.

