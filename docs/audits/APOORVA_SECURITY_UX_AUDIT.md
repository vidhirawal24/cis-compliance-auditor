# CISGuard 360 (BaselineGuard) — Application Security & UI/UX Audit

**Auditor:** Principal Frontend Security Engineer & Lead Accessibility Specialist  
**Branch:** `feat/apoorva-web`  
**Date:** October 30, 2026  
**Scope:** Security Architecture, Secret Management, Tenant Isolation, XSS Protection, WCAG 2.1 Accessibility & Responsive UX  

---

## 1. Security Architecture & Threat Model Audit

### 1.1 Secret Exposure & Browser Safety Audit
- **Rule Verification:** "Never place Supabase service-role keys, device passwords, private keys, or privileged tokens in the browser."
- **Audit Finding:** **PASS - ZERO PRIVILEGED SECRETS DETECTED.**
  - `src/auth/supabase.ts` strictly references `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`.
  - `.env.example` explicitly specifies:
    ```bash
    # Public browser Supabase configuration only. Replace placeholders for integration.
    # Never supply a service-role key, device credential or private key.
    VITE_SUPABASE_URL=https://your-project.supabase.co
    VITE_SUPABASE_ANON_KEY=your-public-anon-key
    ```
  - Git history and working tree were scanned; zero `.env` with production secrets exist in the repository.
  - Credential Vault references (`E17`) render masked string pointers (`vault:secret/*`) rather than plaintext secrets.

### 1.2 Multi-Tenant Isolation & RBAC Route Guarding
- **Audit Finding:** **PASS - STRICT CLIENT BOUNDARIES ENFORCED.**
  - `src/auth/AuthGuard.tsx` enforces tenant boundaries via `hasTenantAccess(orgId)`.
  - If a user attempts to access an unauthorized tenant URL, a dedicated **ERROR 403 - TENANT ISOLATION** screen is rendered, completely preventing data exposure.
  - Role hierarchy (`OWNER` > `ADMIN` > `OPERATOR` > `AUDITOR` > `VIEWER`) is checked on every protected route.
  - Downgrading a user role in DEMO session instantly updates the navigation sidebar, hiding privileged administrative and execution controls.
  - `SessionCacheBoundary.tsx` clears TanStack Query cache on user/tenant/role transitions, preventing cross-tenant cached data leakage.

### 1.3 Cross-Site Scripting (XSS) & Unsafe HTML Rendering
- **Audit Finding:** **PASS - ZERO `dangerouslySetInnerHTML` DETECTED.**
  - The codebase was audited for unsafe React patterns.
  - Cytoscape, React Flow, and Recharts canvases render sanitized SVGs and canvas primitives without DOM injection vulnerabilities.
  - CLI remediation code blocks in `09_FindingsShell.tsx` render as plain text within `<pre><code>` blocks, neutralizing command injection and script execution vectors.

### 1.4 Input Validation & Defensive File Uploads
- **Audit Finding:** **PASS - ROBUST ZOD SCHEMAS & SCOPE CHECKS.**
  - Organization creation, custom policy overrides, and manual review attestations validate inputs using Zod schemas and React Hook Form.
  - Discovery sweep requires explicit boolean acknowledgment of scope boundary consent before invoking the network probe.
  - Attestation evidence upload enforces valid `http://` or `https://` URI schemes.

### 1.5 Fail-Closed Production Behavior
- **Audit Finding:** **PASS - TESTED FAIL-CLOSED GUARANTEE.**
  - `src/api/config.ts` and `apps/web/public/baselineguard-config.json` default `mode` to `"disabled"`.
  - When running in non-demo mode without valid backend configuration, the app fails closed immediately and refuses to load synthetic demo records.
  - E2E production suite (`production.spec.ts`) verifies that disabled, missing, or malformed configurations never grant a synthetic session.

---

## 2. UI/UX & Responsive Design Audit

### 2.1 Viewport Breakpoint Testing

| Viewport Profile | Target Dimensions | Visual Layout Behavior | Overflow Status | Navigation Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop High-Res** | 1920 × 1080 | Multi-column grid, persistent 240px sidebar, expanded KPI stat cards, Cytoscape graph at full width | **Zero horizontal overflow** | Fixed sidebar with grouped sections |
| **Desktop Standard** | 1280 × 720 | Standard layout, responsive flex containers, Recharts auto-adjusting aspect ratios | **Zero horizontal overflow** | Fixed sidebar with scrollable navigation list |
| **Tablet Viewport** | 768 × 1024 | 2-column card layouts, tables maintain horizontal scroll containers, Topbar switches to compact | **Contained within tables** | Sidebar collapsible via hamburger trigger |
| **Mobile Viewport** | 390 × 664 (iPhone 13) | 1-column stacked cards, full-width buttons, compact typography, sticky topbar with sheet menu | **Zero body horizontal overflow** | `MobileNav` sheet drawer with focus trap |

### 2.2 Standardized State Taxonomy

All 19 screen families implement the 10 canonical UI states:
1. **Ready State:** High contrast `#0b0f17` background with slate/sky cards and clear typography.
2. **Loading State:** `LoadingSkeleton.tsx` provides shimmering skeletons matching target card and table geometry (eliminating cumulative layout shifts).
3. **Empty State:** `EmptyState.tsx` displays contextual Lucide icons, descriptive help text, and explicit call-to-action buttons.
4. **Error State:** `ApiState.tsx` renders amber/red alert callouts with error code and retry triggers.
5. **403 Forbidden State:** Explicit permission denial card explaining user's active role and how to request elevation.
6. **404 Not Found State:** Cybersecurity-themed missing resource screen with one-click return to `/overview`.
7. **500 Server Error State:** `ErrorBoundary.tsx` catches runtime rendering errors without full application crashes.
8. **Offline State:** Sticky warning banner at the top of the viewport when `navigator.onLine === false`.
9. **Unsupported Device State:** Advisory modal disclosing platform/firmware limitations with link to supported matrix.
10. **Partial Scan State:** Amber notification banner informing user that specific checks were skipped due to credential or timeout limits.

---

## 3. Accessibility (A11y) & WCAG 2.1 Compliance

### 3.1 Automated & Component Checks
- **Color Contrast:** All body text meets WCAG AA contrast ratio (> 4.5:1) against `#0b0f17` and `#0f172a` backgrounds.
- **Keyboard Navigation:**
  - Table rows in Findings Explorer support `Enter` and `Space` keyboard activation to open inspection drawers.
  - Tab navigation cycles through interactive buttons, inputs, and tab triggers in logical DOM order.
  - Modals and drawers implement focus traps and close on `Escape`.
- **Screen Reader Support:**
  - ARIA attributes: `role="status"` on loading indicators, `role="alert"` on error banners, `aria-expanded` on collapsible sections.
  - Skeletons and decorative icons use `aria-hidden="true"`.
  - Interactive charts include accessible text tables as accessible alternatives.
- **Table Accessibility:** Tables include `<caption>` or `aria-label`, `<th scope="col">`, and scrollable wrappers marked with `tabIndex={0}` and `aria-label="Scrollable data table"`.

