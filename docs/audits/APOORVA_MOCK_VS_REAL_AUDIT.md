# CISGuard 360 (BaselineGuard) — Mock vs. Real Functionality Audit

**Auditor:** Principal Frontend Engineer & Application Security Architect  
**Branch:** `feat/apoorva-web`  
**Date:** October 30, 2026  
**Scope:** Action-by-Action Functional Trace & Classification across all User-Facing Interactions  

---

## 1. Classification Taxonomy

Each user-facing action is categorized into one of five rigorous classifications:
- **[A] Real Backend API**: Wired to live HTTP endpoint with authorization, error handling, and runtime payload validation.
- **[B] Mock API Client (`DemoApiClient`)**: Wired to client-side typed interface and in-memory mutable store (`store.ts`) with deterministic state mutations.
- **[C] Static Fixture Data**: Read-only display consuming immutable demo constants (`demoData.ts` / `phase8Data.ts`).
- **[D] Visual Placeholder**: UI element rendered for layout completeness without functional execution logic.
- **[E] Broken / Nonfunctional**: Action triggers uncaught error, fails silently, or unhandled exception.

---

## 2. Exhaustive Action-by-Action Functional Trace

### 2.1 Screen Family 01 — Authentication (`/auth/*`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Supabase Sign-In** | `onSubmit` in `01_AuthShell.tsx` | Form submit → `loginSupabase(email, pwd)` → calls `supabase.auth.signInWithPassword` → updates `user` state → navigates to `/orgs` | **[A]** (Real when configured; fails closed when absent) | If credentials fail or Supabase is unconfigured, displays clear error banner without creating fake session. Never exposes private keys. |
| **Quick Sign-In (DEMO Mode)** | `handleQuickDemoLogin` | Click button → `loginDemo(email, selectedRole)` → updates `authMode='DEMO'`, `role=selectedRole`, sets `DEMO_USER` → navigates to `/orgs` | **[B]** (Mock API) | Explicitly labeled "DEMO Mode". In production mode (`mode !== 'demo'`), DEMO login is disabled and blocked. |
| **MFA Verification Code Entry** | `verifyMfa` | Input 6 digits → submits code → calls `verifyMfa(code)` → checks regex & rejects `000000` → sets `mfaVerified=true` → unlocks navigation | **[B]** (Mock API) | Enforces 6-digit regex. In non-demo mode, returns unsupported error requiring real MFA factor integration. |
| **Password Reset Request** | `handleResetPassword` | Enter email → calls `resetPassword(email)` → calls `supabase.auth.resetPasswordForEmail` → displays delivery confirmation alert | **[A]** (Real when configured; DEMO preview when unconfigured) | Explicitly notes "Delivery is not confirmed" to prevent false delivery claims. |
| **Logout** | `handleLogout` in Topbar | Click logout → `logout()` → clears local user & org state → signs out Supabase session → redirects to `/auth/login` | **[A]** / **[B]** | Clears `QueryClient` cache before unmounting (`SessionCacheBoundary.tsx`). |

### 2.2 Screen Family 02 — Org Selection (`/orgs`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Select Workspace** | `handleSelectOrg` | Click card → `switchOrg(orgId)` → validates `hasTenantAccess` → updates `currentOrg` → navigates to `/orgs/:orgId/overview` | **[B]** (Mock API) | Validates tenant membership before route transition. Cross-tenant switching throws access denied error. |
| **Create Workspace** | `onSubmit` in modal | Form submit → `api.createOrganization(payload)` → adds org to store → refetches org list → displays new workspace card | **[B]** (Mock API) | Form validated with Zod (min 3 chars, slug regex `^[a-z0-9-]+$`). |

### 2.3 Screen Family 03 — Main Overview (`/orgs/:orgId/overview`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Load Posture Summary** | Query `['overview', orgId]` | Component mount → `api.getComplianceTrends()` & `api.getScans()` → computes metrics → renders scorecards & charts | **[B]** (Mock API) | Strictly enforces formula: `PASS / (PASS + FAIL)`. `NOT_ASSESSED` checks are segregated into Coverage %. |
| **Filter Severity Donut** | Click donut slice | Click segment → filters findings breakdown panel → updates view | **[B]** (Mock API) | Interactive chart selection filters breakdown accurately. |
| **Trigger Quick Scan** | Click Quick Audit | Click button → navigates to `/orgs/:orgId/scans/new` with pre-filled default profile | **[B]** (Mock API) | Redirects to compliant scan wizard with mandatory Read-Only confirmation. |

### 2.4 Screen Family 04 — Asset Inventory (`/orgs/:orgId/assets`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Search Assets** | `onChange` input | Type query → updates `searchFilter` state → filters TanStack table rows in real time | **[B]** (Mock API) | Filter matches hostname, IP, and platform accurately. |
| **Platform Filter Pills** | Click platform pill | Click filter → updates active platform filter → table re-renders filtered records | **[B]** (Mock API) | Supports Windows, Linux, Cisco, Fortinet, Check Point, Sophos, Palo Alto. |
| **Add Device Form** | `onSubmit` dialog | Form submit → `api.createAsset(orgId, data)` → inserts asset into store → toast alert → table updates | **[B]** (Mock API) | Validates hostname, IP address regex, and platform family enum. |
| **Discovery Sweep** | `onSubmit` in `/discover` | Form submit → verifies `scope_consent_confirmed` → `api.previewDiscovery(data)` → renders discovered candidates table | **[B]** (Mock API) | Rejects sweep if user does not explicitly confirm scope authorization checkbox (`E02`). |
| **Bulk Import Offline Config** | Dropzone upload | File dropped → reads file header → parses JSON/CSV → validates schema | **[D]** / **[B]** (Visual DEMO) | Clearly watermarked: "OFFLINE DEMO / NON-LIVE". Backend parsing engine is blocked (`E10`). |

### 2.5 Screen Family 05 — Asset Details (`/orgs/:orgId/assets/:id`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Tab Navigation** | Click tab triggers | Click tab → switches between Overview, Interfaces, Findings, Snapshots | **[B]** (Mock API) | State updates cleanly without page reload. URL synchronized with route splats. |
| **Copy Vault Reference** | Click copy icon | Click copy button → writes `vault:secret/*` pointer to clipboard → displays toast | **[B]** (Mock API) | Never exposes raw password or private keys; only masked identifier pointer (`E17`). |
| **Snapshot Diff View** | Click diff button | Click snapshot row → loads side-by-side config diff modal → highlights added/removed lines | **[B]** (Mock API) | Uses SHA-256 integrity indicator to guarantee snapshot authenticity. |

### 2.6 Screen Family 06 — Scan Center (`/orgs/:orgId/scans`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Launch Audit Wizard** | Multi-step form | Step 1 (targets) → Step 2 (policy & L1/L2) → Step 3 (Read-only check) → `api.createScan(data)` → queues job | **[B]** (Mock API) | Enforces mandatory `read_only_confirmed` check (`E18`). Prevents scan creation if unchecked. |
| **Retry Failed Scan** | Click Retry button | Click button → `api.retryScan(scanId)` → updates scan status from `FAILED` to `QUEUED` → updates table | **[B]** (Mock API) | Retries only eligible failed jobs; preserves error isolation log. |
| **Create Recurring Cron** | `onSubmit` in modal | Form submit → validates 5-field cron expression → `api.createSchedule(data)` → updates schedules table | **[B]** (Mock API) | Rejects invalid cron strings (`E04`). Standard cron syntax validated. |

### 2.7 Screen Family 07 — Policy Library (`/orgs/:orgId/policies`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Filter CIS Profile L1/L2**| Click profile toggle | Toggle Level 1 / Level 2 → filters policy rule tree to matching applicability items | **[B]** (Mock API) | Filters rules accurately by benchmark profile level (`E11`). |
| **Create Custom Override** | `onSubmit` in `/overrides` | Form submit → validates rule override value → `api.createPolicyOverride(data)` → adds override | **[B]** (Mock API) | Enforces that only ADMIN/OWNER roles can save baseline overrides (`M18`). |
| **Upgrade Preview Diff** | View `/upgrade-preview` | Navigate to view → loads diff data → displays added, modified, removed rules and affected assets count | **[B]** (Mock API) | Renders version diff without fabricating unverified rule differences (`M19`, `I19`). |

### 2.8 Screen Family 08 — Exceptions & Reviews (`/orgs/:orgId/exceptions`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Request Exception** | `onSubmit` dialog | Form submit → `api.createPolicyException(data)` → stores time-boxed exception → displays countdown badge | **[B]** (Mock API) | Critical Invariant: creating an exception does NOT turn failed finding into `PASS` (`E14`). |
| **Manual Review Sign-off** | `onSubmit` in `/manual-reviews` | Enter justification & evidence URI → `api.submitManualReview(data)` → updates attestation status | **[B]** (Mock API) | Validates evidence URI schema (`http://` or `https://`). Requires justification (`E12`). |

### 2.9 Screen Family 09 — Findings Explorer (`/orgs/:orgId/findings`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Filter by Status / Severity**| Click chip | Click filter chip → updates filter criteria → re-queries findings table | **[B]** (Mock API) | Handles all statuses: `PASS`, `FAIL`, `NOT_ASSESSED`, `ERROR`, `UNKNOWN`. |
| **Open Finding Drawer** | Click row or Enter/Space | Row selected → opens slide-over drawer → loads expected vs actual diff, SHA-256 evidence hash | **[B]** (Mock API) | Keyboard accessible (Enter and Space key listeners verified). |
| **Copy Remediation CLI** | Click copy code button | Click copy → copies CLI snippet to clipboard → displays toast | **[B]** (Mock API) | Remediation is displayed strictly as non-executable text with risk warning banner (`M37`). |

### 2.10 Screen Family 10 — Security Graph (`/orgs/:orgId/graph`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Inspect Graph Node** | Click Cytoscape node | Node clicked → opens node inspector card → displays IP, platform, open ports, and linked findings | **[B]** (Mock API) | Elements reflect typed schema: assets, subnets, interfaces, services (`I01`). |
| **Trace Attack Path** | Click "Trace Path" | Select source & target → highlights active hops on canvas → displays path drawer | **[B]** (Mock API) | Path analysis traces reachability with relation and confidence indicators (`I03`). |
| **Switch to Table Fallback** | Click Table View tab | Click tab → renders accessible HTML table of topology nodes and edges | **[B]** (Mock API) | Guaranteed accessible alternative for screen-reader and keyboard navigation. |

### 2.11 Screen Family 11 — Risk Scenarios (`/orgs/:orgId/risk-scenarios`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Inspect Risk Scenario** | Click scenario card | Navigate to detail → displays root-cause card, multi-device causal chain diagram, confidence score | **[B]** (Mock API) | Groups correlated findings across disparate hosts into cohesive attack scenarios (`I02`, `I04`). |
| **View Explainability Evidence**| Click "View Evidence" | Opens drawer → lists normalized configuration facts supporting the risk claim | **[B]** (Mock API) | Direct evidence attribution; zero black-box AI inferences (`I05`). |

### 2.12 Screen Family 12 — Remediation Planner (`/orgs/:orgId/planner`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Compare Alternative Fixes** | Click alternative card | Select alternative → updates selected candidate → updates disruption, cost, and coverage score | **[B]** (Mock API) | Minimal disruption metric derived from CP-SAT optimization model (`I06`, `I07`). |
| **Inspect Dependency DAG** | React Flow canvas | View task dependency graph → displays sequential ordering and stage gates | **[B]** (Mock API) | Multi-vendor coordinated task list (Cisco + Linux + Windows) (`I08`, `I10`). |
| **Submit Plan for Approval** | Click "Submit for Approval" | Click button → validates plan hash → submits plan to approval queue → changes state to `PENDING_APPROVAL` | **[B]** (Mock API) | Conflict checks flag incompatible commands before submission (`I09`). |

### 2.13 Screen Family 13 — What-If Simulator (`/orgs/:orgId/simulator`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Edit Safety Contract** | Form in `/contracts` | Form inputs → validates mandatory reachability rule → `api.saveContract(data)` → updates contract list | **[B]** (Mock API) | Validated with React Hook Form. Invalids invalidate simulation preview (`I12`). |
| **Run Simulation Hypothesis** | Click Run Simulation | Click button → compares baseline vs candidate model → computes blast-radius and contract violations | **[B]** (Mock API) | Violating hypothesis triggers amber alert and blocks approval progression (`I11`, `I13`, `I14`). |

### 2.14 Screen Family 14 — Approvals & Hardening (`/orgs/:orgId/approvals`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Sign-off Plan Approval** | Click "Approve Plan" | Enter justification → `api.approvePlan(id, {plan_hash, justification})` → marks plan `APPROVED` | **[B]** (Mock API) | Enforces Separation of Duties: Operator cannot approve their own plan (`E23`). Approver role mandatory. |
| **Execute Staged Rollout** | Click "Execute Canary" | Click button → `api.executeChange(changeId)` → advances canary stepper from `READY` to `EXECUTING` | **[B]** (Mock API) | Displays rollback instructions and backup readiness status (`E21`, `E24`, `I15`). |
| **Emergency Halt** | Click "Emergency Stop" | Click button → pauses rollout → highlights manual rollback commands | **[B]** (Mock API) | Halts progression immediately; displays vendor-specific rollback snippets. |

### 2.15 Screen Family 15 — Verification & Proof (`/orgs/:orgId/verifications`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Inspect Dual Verification** | Click verification item | Loads verification breakdown → displays CIS Compliance PASS & Service Probe PASS scorecards | **[B]** (Mock API) | Dual verification gate: both checks must pass independently (`I16`). |
| **View Proof-of-Hardening** | View `/proof-packages/:id` | Loads dossier → renders SHA-256 manifest, timestamp, and actor signature chain | **[B]** (Mock API) | Cryptographic dossier provides tamper-evident audit proof (`I18`). |

### 2.16 Screen Family 16 — Reports & History (`/orgs/:orgId/reports`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Fetch Reports List** | Query `['reports']` | Component mount → `api.getReports()` → renders report rows | **[A]** (Real when HTTP adapter configured) / **[B]** (DEMO) | `getReports` is the agreed initial live HTTP binding in `configuredClient.ts`. |
| **Download Report (PDF/CSV/etc.)**| Click download button | Click button → requests signed download URL → opens link | **[B]** (Mock API) | Generates signed URL status without exposing credentials in the URI (`M38`). |
| **Filter Drift Timeline** | Filter drift events | Click filter → updates drift event stream | **[B]** (Mock API) | Displays configuration change deltas over time (`E05`). |

### 2.17 Screen Family 17 — Notifications & Tickets (`/orgs/:orgId/notifications`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Create Webhook** | `onSubmit` modal | Enter webhook URL & event triggers → saves webhook → updates list | **[B]** (Mock API) | Validates HTTP/HTTPS URL format (`E26`). |
| **Test Webhook Ping** | Click "Test Ping" | Click button → triggers synthetic test ping → displays status toast | **[B]** (Mock API) | Clearly labeled synthetic delivery example (`phase8Data.ts`). |
| **Sync Ticket Connector** | Toggle Jira / ServiceNow | Toggle connector switch → updates integration status card | **[B]** (Mock API) | Displays external ticket synchronization state (`E27`). |

### 2.18 Screen Family 18 — Admin & Security (`/orgs/:orgId/admin/*`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Invite User** | `onSubmit` modal | Enter email & assign role → adds member to organization table | **[B]** (Mock API) | Role dropdown restricted to authorized roles. Admin role required. |
| **Inspect Audit Log** | View `/admin/audit-logs` | Loads audit trail table → filters by actor, action, timestamp | **[B]** (Mock API) | Immutable audit log displays tamper-check indicators (`E19`). |
| **Manage Vault Pointer** | View `/admin/vault` | Manage credential pointers (`vault:secret/*`) | **[B]** (Mock API) | Zero plaintext secrets; only vault reference pointers stored (`E17`). |

### 2.19 Screen Family 19 — System Edge States (`/system-states`)

| UI Action / Event | Target Handler | Trace: Event → Handler → State → API → Display | Classification | Invariant & Security Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Inspect State Gallery** | Click state card | Switches gallery view between Ready, Loading, Empty, 403, 404, 500, Offline, Partial Scan | **[B]** (Mock API) | Standardized error and edge state presentation verified across all 10 states. |

---

## 3. Summary of Mock vs. Real Boundaries

1. **Agreed Live HTTP Surface:** `GET /reports` (implemented with Zod validation, token forwarding, same-origin `/api/` checks in `configuredClient.ts`).
2. **Supabase Auth Integration:** Wired directly to `supabase.auth.signInWithPassword`, `signOut`, `onAuthStateChange`, and `resetPasswordForEmail` via public anon credentials.
3. **Synthetic Demo Store:** 19 screen families are completely operable in DEMO mode via `DemoApiClient` backed by `fixtureStore` (`store.ts`).
4. **Fail-Closed Safeguard:** In non-DEMO production mode without configured backend endpoints, all unapproved calls fail closed with `UnavailableOperation` (`UNSUPPORTED`), ensuring zero synthetic data leaks into production.

