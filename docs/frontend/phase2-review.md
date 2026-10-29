# BaselineGuard - Phase 2 Implementation Review & Feature Handoff Matrix
**Role:** Frontend Owner (Apoorva)
**Date:** October 29, 2026
**Document Status:** Complete Phase 2 Implementation Review
**Product Branding:** BaselineGuard
**Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”
**Governing Directory:** `apps/web/` and `docs/frontend/`

---

## 1. Executive Summary

Phase 2 establishes the core authentication, multi-tenant workspace shell, and end-to-end asset lifecycle management for **BaselineGuard** in `apps/web/`. All workflows adhere to the frozen `contracts/v1`, enforcing strict multi-tenant boundary checks, zero-plaintext credential masking with OpenBao, deterministic form validation with React Hook Form + Zod, and full visual separation between production Supabase authentication and synthetic lab simulation.

### Key Deliverables Completed:
1. **Authentication (Supabase Auth + MFA + Password Recovery)**:
   - Full standard Supabase Auth integration (`signInWithPassword`, `signOut`, `resetPasswordForEmail`, `mfa.enroll`, `mfa.challengeAndVerify`).
   - Clean, unmistakable UI distinction between production authentication and synthetic lab simulation (`[DEMO MODE: Synthetic Lab Only]`).
   - Dedicated password recovery and MFA setup/challenge flows with form-level validation.
2. **Organization Shell & Tenant Isolation (M34)**:
   - Tenant selection dashboard displaying assigned workspaces, platform baselines, and active roles.
   - Tenant creation wizard with Zod validation (`name`, `slug`).
   - Runtime `AuthGuard` tenant isolation boundary blocking unauthorized tenant URL navigation with standardized 403 Cross-Tenant Isolation screens.
3. **Asset Inventory & Management (E01, E02, E03, E15, E18)**:
   - High-density SOC asset table with multi-parameter filtering (hostname/IP search, platform family, environment, and custom tag pills).
   - Device Onboarding Wizard (E18): 4-step wizard validating specifications, site risk, OpenBao vault secret path pointers, and read-only capability pre-checks.
   - Authorized Subnet Discovery Sweep (E02): CIDR input, probe port selector, mandatory scope consent checkbox, and candidate device preview.
   - Complete Asset Detail View: collector facts, supported vs. unsupported CIS capabilities, network interface table (M11), edit modal, and safe retirement workflow.
4. **Zero-Plaintext Secret Masking (E15)**:
   - Only registered OpenBao secret path pointers (`vault://...`) are accepted and displayed; browser never holds or prompts for raw device passwords or private keys.

---

## 2. Feature-to-Screen Handoff Mapping (M34, E01–E03, E15–E18)

| Feature ID | Feature Name | Primary Route / Component | UI Implementation & Security Controls |
| :--- | :--- | :--- | :--- |
| **M34** | Multi-Tenant RBAC & Tenant Isolation | `/orgs`<br>`/orgs/:orgId/*`<br>[`AuthGuard.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/auth/AuthGuard.tsx)<br>[`02_OrgSelectShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/02_OrgSelectShell.tsx) | Tenant switcher with membership check. Unauthorized `:orgId` access renders 403 Cross-Tenant Isolation screen preventing cross-tenant leakage. |
| **E01** | Network Device Asset Inventory | `/orgs/:orgId/assets`<br>[`04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx) | High-density asset table covering Cisco IOS, Fortinet, Check Point, Sophos, Palo Alto, Linux, and Windows targets. |
| **E02** | Automated Subnet / Range Asset Discovery | `/orgs/:orgId/assets/discover`<br>[`04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx) | CIDR sweep modal with mandatory scope authorization consent checkbox; renders unassessed candidate hosts with "Onboard" action. |
| **E03** | Custom Device Grouping & Tagging | `/orgs/:orgId/assets`<br>[`04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx)<br>[`05_AssetDetailShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/05_AssetDetailShell.tsx) | Interactive tag filter pills (`#core`, `#dmz`, `#pci`, `#perimeter`); inline tag editing in asset modification dialog. |
| **E15** | Centralized Credential Vault Integration (OpenBao) | `/orgs/:orgId/assets`<br>[`04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx)<br>[`05_AssetDetailShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/05_AssetDetailShell.tsx) | Strictly masked vault path pointers (`vault://secret/infra/...`); explicit warning preventing raw plaintext credential entry. |
| **E16** | Role-Based Access Control Granular Permissions | `/auth/login`<br>[`Topbar.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/components/layout/Topbar.tsx)<br>[`AuthGuard.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/auth/AuthGuard.tsx) | Granular permission hierarchy (Owner, Admin, Approver, Operator, Auditor, Viewer) dynamically filtering navigation menus and restricting mutations. |
| **E17** | Dual-Sign-Off Workflow & Approvals | `/orgs/:orgId/approvals`<br>[`05_AssetDetailShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/05_AssetDetailShell.tsx) | Destructive/mutating actions (asset retirement) require explicit confirmation dialogs with audit trail logging. |
| **E18** | Device Onboarding Wizard | `/orgs/:orgId/assets/import`<br>[`04_AssetInventoryShell.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/routes/shells/04_AssetInventoryShell.tsx) | 4-step wizard: Device Identity $\rightarrow$ Site & Risk $\rightarrow$ OpenBao Pointer $\rightarrow$ Read-Only Capability Pre-Check. |

---

## 3. Architecture & Security Invariants

### 3.1 Strict Separation of Demo vs. Production Authentication
The application supports real Supabase Auth (`supabase.auth.signInWithPassword`, TOTP challenge, password reset link) while simultaneously allowing local deterministic demo verification. The demo mode is strictly demarcated with clear UI labels (`[DEMO MODE: Synthetic Lab Only]`) and topbar indicators to ensure synthetic testing is never conflated with production authentication.

### 3.2 Tenant Isolation Boundary (M34)
The `AuthGuard` component inspects the route parameter `:orgId`. If the logged-in user does not belong to the requested tenant, access is immediately blocked with an `ERROR 403 - TENANT ISOLATION (M34)` screen, preventing cross-tenant URL traversal.

### 3.3 Zero-Plaintext Secret Architecture (E15)
The frontend never stores, prompts for, or handles plaintext passwords, private SSH keys, or SNMP communities. All credentials are bound via immutable OpenBao secret path pointers (`vault://...`).

---

## 4. Test Verification Matrix

All unit and integration test suites run via Vitest and React Testing Library:

| Test Suite | File Path | Focus / Scenarios Tested |
| :--- | :--- | :--- |
| **Authentication** | [`src/test/auth_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/auth_phase2.test.tsx) | Form validation (invalid email, short password), password recovery flow, MFA TOTP challenge, demo persona role switching. |
| **Organizations & Tenant Isolation** | [`src/test/orgs_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/orgs_phase2.test.tsx) | Tenant listing, active tenant switching, cross-tenant 403 isolation screen (M34), workspace creation validation. |
| **Asset Management** | [`src/test/assets_phase2.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/assets_phase2.test.tsx) | Inventory table, search/filter, tag pills (E03), onboarding wizard (E18), discovery sweep with scope consent (E02), detail view, edit & retire flows. |
| **Route Smoke Tests** | [`src/test/routes.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/routes.test.tsx) | All 19 route shells rendering correctly. |
| **Navigation & RBAC** | [`src/test/navigation.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/navigation.test.tsx) | Role filtering between Owner, Operator, Auditor, and Viewer personas. |
| **System States** | [`src/test/states.test.tsx`](file:///d:/Mini_Project_Hackathon/apps/web/src/test/states.test.tsx) | Empty states, loading skeletons, error boundary panics, 403 forbidden states. |
