# BaselineGuard (formerly CISGuard 360) - Phase 0 Master Review & Architecture Alignment
**Role:** Frontend Owner (Apoorva)  
**Date:** October 29, 2026  
**Document Status:** Complete Phase 0 Audit & Engineering Baseline  
**Product Branding:** BaselineGuard  
**Tagline:** “audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”  
**Governing Documents:**
- `CISGuard_360_Complete_PRD_v1.pdf` (PRD v1.0)
- `CISGuard_360_Final_Tech_Stack_v3.pdf` (Tech Stack v3.0)
- `Apoorva - Parallel Development Playbook` (Playbook v1.0)

---

## 1. Executive Summary & Frontend Mission

As the Frontend Owner (Apoorva) of **BaselineGuard** (formerly CISGuard 360), my mission is to deliver a rock-solid, production-grade cybersecurity management interface covering all **88 planned features** (38 Mandatory PS entries `M01-M38`, 30 Industry Extras `E01-E30`, and 20 Differentiating Innovations `I01-I20`) without compromising architectural integrity, security boundaries, or scoring truthfulness.

BaselineGuard is built upon the product promise:
> *“audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.”*

$$\text{Audit} \longrightarrow \text{Understand} \longrightarrow \text{Plan} \longrightarrow \text{Simulate} \longrightarrow \text{Harden} \longrightarrow \text{Verify} \longrightarrow \text{Prove} \longrightarrow \text{Monitor}$$

The frontend is an **active participant** in enforcing security hygiene, truthful reporting, and separation of duties. Under no circumstances will the frontend fabricate results, mask failures, bypass backend authorizations, execute unvalidated client-side commands, or invoke black-box AI/ML models.

---

## 2. Team Split, Directory Boundaries & Parallel Work Mode

To enable unblocked parallel development alongside Mandar (Backend Lead) and Vidhi (Device Engine Lead), the repository enforces strict single-owner directory ownership:

| Member | Exclusive Directory Boundaries | Core Responsibilities |
| :--- | :--- | :--- |
| **Apoorva (Frontend)** | `apps/web/`<br>`docs/frontend/` | UI/UX, responsive layouts, data visualizations (Cytoscape, React Flow, Recharts), TanStack Query/Table, Supabase Auth integration, client-side contract validation, UI mock/fixtures, unit/integration/a11y tests. |
| **Mandar (Backend)** | `apps/api/`<br>`packages/contracts/`<br>`infra/`<br>`docs/core/` | FastAPI REST/WebSocket endpoints, Supabase DB migrations & RLS policies, custom CIS rule engine, OR-Tools CP-SAT optimizer, NetworkX risk graph backend, Celery task queue, WeasyPrint reporting. |
| **Vidhi (Device Engine)** | `services/device-engine/`<br>`docs/device/` | Platform collectors (Windows, Linux, Cisco, Fortinet, Check Point, Sophos, Palo Alto), Batfish network simulation models, Ansible Runner hardening playbooks, dual-verification service probes. |

### Working Rules for Apoorva:
1. **Directory Boundary**: Work *exclusively* in `apps/web/` and `docs/frontend/`. Never touch `apps/api/`, `packages/contracts/`, `services/device-engine/`, or `infra/`.
2. **Contract-Driven Decoupling**: Consume only frozen `contracts/v1`. While the backend API is in development, the frontend runs against typed client schemas and deterministic synthetic fixtures clearly marked `DEMO`.
3. **No Assumed API Changes**: Any missing endpoint or field required by the frontend must be proposed via `docs/frontend/contract-questions.md` and agreed upon before integration.
4. **Stable Feature ID Tagging**: Every screen, view, route, dialog, data hook, and test suite must be tagged with its corresponding `Mxx`, `Exx`, or `Ixx` identifier.

---

## 3. Immutable Technical Constraints & Non-Negotiables

### 3.1 Zero Runtime LLM / AI / ML
- The runtime application contains **zero** dependencies on OpenAI, Anthropic, Gemini, local LLMs, LangChain, or heuristic ML classifiers.
- Misconfiguration detection is strictly deterministic, executing versioned CIS rules with Boolean, regex, range, CIDR containment, and ordered ACL evaluators.
- Cross-device correlation and root-cause analysis run deterministic graph algorithms (NetworkX on backend, Cytoscape on frontend).
- Remediation planning uses constraint satisfaction (Google OR-Tools CP-SAT).
- What-if analysis uses formal network emulation and reachability models (Batfish).

### 3.2 Read-Only by Default & Controlled Mutation
- Scans and inventory discovery are strictly read-only (`collect(read_only=True)`).
- The browser **never** issues arbitrary shell commands or vendor CLI strings.
- Hardening actions are bounded, vetted remediation IDs executed through a multi-stage approval workflow with strict separation of duties (approver cannot be operator).

### 3.3 Scoring Invariants & Anti-Fabrication Rules
- **Canonical Scoring Formula**:
  $$\text{Assessed Compliance \%} = \frac{\text{PASS}}{\text{PASS} + \text{FAIL}} \times 100$$
- **Assessment Coverage**:
  $$\text{Assessment Coverage \%} = \frac{\text{PASS} + \text{FAIL}}{\text{TOTAL APPLICABLE CONTROLS}} \times 100$$
- **Status Enum Truthfulness**:
  - `PASS`: Control evaluated and met expected condition.
  - `FAIL`: Control evaluated and failed condition.
  - `NOT_APPLICABLE`: Excluded from denominator.
  - `MANUAL_REVIEW`: Requires human evidence; excluded from automated denominator until validated.
  - `ERROR`: Assessment attempt failed; **never** counted as PASS.
  - `NOT_ASSESSED`: No collector or missing evidence; **never** counted as PASS.
  - `EXCEPTION`: Time-bound policy override; **never** overwrites technical FAIL to PASS. Rendered as an overlay badge with expiry and approver.

### 3.4 Security & Privacy Guardrails
- Device passwords, SNMP community strings, private SSH keys, and API tokens **never** reach the frontend browser client.
- The UI displays only masked credential references (e.g., `vault:secret/cisco-core-01`).
- Supabase Auth provides JWT Bearer tokens; FastAPI validates claims, tenant membership, and granular RBAC.

---

## 4. Frontend Technology Stack & Library Selection

The frontend stack has been selected in full compliance with Tech Stack v3.0:

| Category | Library / Tool | Version / Standard | Architectural Purpose |
| :--- | :--- | :--- | :--- |
| **Framework & Core** | React 18 / 19 | LTS | Component architecture, Concurrent Mode, Suspense boundaries |
| **Language** | TypeScript | Strict Mode (`5.x`) | End-to-end type safety, exhaustive union discrimination |
| **Build Tool** | Vite | `6.x` / `5.x` | ESM build, fast HMR, optimized production bundles |
| **Styling & System** | Tailwind CSS | `3.4+` | Utility-first, dark-first cybersecurity palette, neutral slate backgrounds |
| **UI Components** | shadcn/ui + Radix UI | Accessible primitives | Dialogs, Popovers, Tabs, Accordions, Dropdowns, Tooltips, Toasts |
| **Icons** | Lucide React | Current | Lightweight, semantically rich cybersecurity and system icons |
| **Routing** | React Router | `v6.x` | Declarative route hierarchy, nested layouts, protected route guards |
| **Server State** | TanStack Query | `v5.x` | Server state caching, optimistic updates, background polling, retry logic |
| **Data Tables** | TanStack Table | `v8.x` | Headless, virtualized, filterable, sortable asset and findings tables |
| **Forms & Schemas** | React Hook Form + Zod | Modern standard | High-performance forms, client-side runtime validation matching v1 contracts |
| **Charts & Metrics** | Recharts | Current | Compliance donuts, severity bars, trend lines, stacked asset distributions |
| **Risk Graph** | Cytoscape.js + react-cytoscapejs | Current | Interactive cross-device network topology and risk attack paths |
| **Workflow DAG** | @xyflow/react (React Flow) | `v12+` | Remediation sequence planning, stage gates, dependency conflict visualization |
| **Auth & Client** | `@supabase/supabase-js` | `v2.x` | Supabase Auth sessions, TOTP MFA challenge, Realtime subscriptions |
| **Date & Time** | date-fns | `3.x` | ISO 8601 formatting, duration calculation, relative timestamps |
| **Notifications** | Sonner | Current | Accessible toast notifications for system events and job alerts |
| **Testing** | Vitest + React Testing Library | Modern standard | Unit tests, component behavior tests, hook mocking |
| **E2E & A11y** | Playwright + axe-core | Current | Browser-driven integration tests, WCAG 2.1 AA accessibility checks |

---

## 5. Scope & Requirements Traceability Matrix (All 88 Features)

Below is the exhaustive mapping of all 88 features defined in PRD v1.0, identifying Apoorva's frontend implementation responsibilities:

### 5.1 Mandatory PS Entries (M01 – M38)
- `M01` (Windows 11): Asset badges, Windows-specific finding inspect view, CIS Windows 11 Enterprise/Standalone baseline selection.
- `M02` (Windows Server 2019): Server-specific findings, GPO/Registry/secedit evidence visualizer.
- `M03` (Ubuntu 20.04/22.04): OpenSCAP/systemd/auditd/sshd evidence tabs, distro version badge, LTS indicator.
- `M04` (RHEL 8/9): SELinux status indicator, firewalld/audit rule inspection view.
- `M05` (Fortinet Firewall): FortiOS policy view, interface binding card, FortiGate finding details.
- `M06` (Cisco Firewall - ASA/FTD): Family-specific mode badge (ASA CLI vs FTD FMC), ACL rule inspection.
- `M07` (Check Point Firewall): Gaia management API vs gateway view, policy rulebase viewer.
- `M08` (Sophos Firewall): SFOS XML/API finding viewer, zone-based firewall display.
- `M09` (Palo Alto Firewall): PAN-OS committed vs candidate config diff, security rule inspection.
- `M10` (Cisco Router): IOS/IOS-XE routing policy, VTY/SSH configuration display.
- `M11` (Cisco Switch): L2 switchport view, VLAN configuration, port security status.
- `M12` (Live Collection): Audit execution progress view, collection metadata (method, timestamp, SHA256 hash).
- `M13` (Central Multi-Target Audits): Multi-target scan launcher wizard, heterogeneous asset selector, unified job status.
- `M14` (OS Collectors): System facts overview (kernel, packages, services, listening ports) with explicit missing data flags.
- `M15` (Network Collectors): Running vs startup configuration viewer, sanitized evidence references.
- `M16` (Deterministic Rule Engine): Rule inspector showing rule logic, operator, parameters, and deterministic execution trace.
- `M17` (Modular Structured Rule Files): Policy pack explorer supporting YAML/JSON/XML rule definition trees.
- `M18` (Custom Baselines): Baseline editor with threshold sliders, rule toggles, and override diff history.
- `M19` (Benchmark Update Maintenance): Benchmark version selector, upgrade impact diff view, deprecation warnings.
- `M20` (Management Plane Security): High-severity callout badge for Telnet/HTTP/unencrypted services in overview and finding details.
- `M21` (SSHv2 / Key Auth / Timeout): SSH hardening card with protocol version, cipher suites, and idle timeout indicator.
- `M22` (Over-Permissive ACLs): Visual ACL table highlighting `permit ip any any` and broad subnets with warning badges.
- `M23` (Sensitive Port Exposure): Inbound exposure matrix for ports 22, 3389, 445, and custom high-risk ports.
- `M24` (Shadowed Rules): Shadowed rule detector showing conflicting rule index and unreachable traffic warning.
- `M25` (Default-Deny Policy): Firewall rulebase final-rule checker displaying default-deny posture and exceptions.
- `M26` (Unused Switch Ports): Port matrix card highlighting active unused ports requiring administrative shutdown.
- `M27` (Port Security / MAC Binding): Switchport security modal showing maximum MAC limits and violation actions.
- `M28` (DHCP Snooping): VLAN-to-DHCP snooping status table with trusted uplink vs untrusted access port badges.
- `M29` (Dynamic ARP Inspection): DAI protection badge with trust boundary indicator per VLAN.
- `M30` (VLAN 1 Management Traffic): Management VLAN badge flagging native VLAN 1 usage with risk advisory.
- `M31` (Syslog Forwarding): Remote logging status table showing destination IP, port, transport, and facility levels.
- `M32` (NTP Synchronization): Time source sync card showing stratum, offset, reachability, and unauthenticated warnings.
- `M33` (SNMP Security): SNMP security posture card flagging default public/private community strings and SNMPv3 USM status.
- `M34` (Central GUI Dashboard - PRIMARY): Unified navigation shell, dark-theme cybersecurity dashboard, search bar, status widgets.
- `M35` (Compliance/Severity Breakdown - PRIMARY): Dual compliance vs coverage KPI widgets, Critical/High/Medium/Low donut chart.
- `M36` (Expected vs Actual Findings - PRIMARY): Side-by-side comparison panel showing rule standard vs observed state with evidence links.
- `M37` (Actionable Remediation): Read-only vendor CLI/API snippet box with copy button, safety prerequisites, and risk advisory.
- `M38` (Reports and Scale): Export modal supporting PDF, HTML, CSV, JSON formats, download progress bar, signed link generator.

### 5.2 Industry Extras (E01 – E30)
- `E01` (Asset Inventory): Searchable, paginated asset registry with platform badges, IP/hostname, owner, and status.
- `E02` (Authorized Discovery): Discovery scan wizard with approved subnet boundary inputs and scope validation alerts.
- `E03` (Tag/Group Assets): Tag management component, multi-tag filter bar, and asset grouping hierarchy.
- `E04` (Scheduled Scans): Cron/calendar scheduling modal with cadence selector, target grouping, and active schedule table.
- `E05` (Configuration Drift Alerts): Drift timeline card showing snapshot comparison, diff highlighting, and alert badges.
- `E06` (Configuration Snapshots): Encrypted snapshot archive with SHA256 integrity check and side-by-side diff viewer.
- `E07` (Compliance Trends): Historical line chart tracking compliance % and coverage % over 30/60/90 days.
- `E08` (Selective Audits): Target selector allowing subset execution by asset group, individual host, or rule category.
- `E09` (Distributed Workers): Worker health dashboard showing queue depth, worker node location, and latency.
- `E10` (Offline Config Assessment): Drag-and-drop config file uploader with "OFFLINE DEMO / NON-LIVE" watermarks.
- `E11` (CIS Profile Selection): Level 1 vs Level 2 profile toggle switch on audit launch and policy views.
- `E12` (Manual Review Workflow): Human attestation modal for manual controls with evidence file attachment and reviewer sign-off.
- `E13` (Risk-Based Prioritization): Risk score badges calculated from severity, asset criticality, and network exposure.
- `E14` (Policy Exceptions): Exception request dialog with expiration date picker, business justification, and approval status.
- `E15` (Role-Based Authorization): Role-aware UI elements (disabled buttons, hidden tabs, permission-denied views for Viewer/Operator/Approver).
- `E16` (Multi-Factor Authentication): Supabase TOTP enrollment QR code screen, challenge prompt, and recovery codes dialog.
- `E17` (Device Credential Vault): OpenBao secret reference selector showing key IDs without revealing secret values.
- `E18` (Read-Only Audit Mode): Prominent "READ-ONLY MODE" badge across audit screens ensuring zero device mutations.
- `E19` (Application Audit Trail): Immutable security activity log table with actor, timestamp, action, and IP filtering.
- `E20` (Policy Version History): Policy pack version history drawer with rollback and version comparison diffs.
- `E21` (Approved Auto-Remediation): Bounded remediation trigger dialog with approval token confirmation.
- `E22` (Dry-Run Preview): Side-by-side diff viewer showing proposed config changes and prerequisite checklist.
- `E23` (Approval Workflow): Dual-key approval dashboard where designated approver reviews and signs off on plans.
- `E24` (Backup/Recovery): Pre-change backup status card and manual recovery instruction accordion for irreversible actions.
- `E25` (Post-Fix Re-Audit): Automated verification card linking the remediation execution directly to the new audit scan.
- `E26` (Alerts/Webhooks): Webhook configuration screen with test ping button, retry policy, and payload preview.
- `E27` (Ticket Integrations): Jira/ServiceNow integration cards with sync status, ticket creation modal, and external link.
- `E28` (Executive Reporting): Executive summary dashboard view with high-level KPI cards and exportable C-level PDF layout.
- `E29` (Search/Filter Interface - PRIMARY): Global search input with syntax parsing, multi-faceted filter drawer, and saved filter chips.
- `E30` (External Integration API): API documentation viewer and tenant API key management interface.

### 5.3 Proposed Differentiating Innovations (I01 – I20)
- `I01` (Infrastructure Relationship Graph): Interactive Cytoscape.js canvas showing assets, subnets, interfaces, and services.
- `I02` (Cross-Device Correlation): Multi-device scenario drawer linking related misconfigurations across firewalls and hosts.
- `I03` (Config-Based Path Analysis): Path simulation view highlighting reachability between source and destination nodes.
- `I04` (Root-Cause Reasoning): Grouped findings card displaying shared root-cause misconfigurations.
- `I05` (Evidence-Backed Risk Explanation): Contextual explanation panel displaying exact normalized facts and confidence ratings.
- `I06` (Minimal-Change Optimization): OR-Tools CP-SAT plan selector showing minimal change impact scores.
- `I07` (Alternative Fix Comparison): Side-by-side candidate comparison cards with disruption score, cost, and prerequisites.
- `I08` (Cross-Vendor Remediation Planning): Multi-vendor change plan card coordinating Cisco, Linux, and Windows tasks.
- `I09` (Remediation Conflict Checks): Safety alert banner showing detected policy and operational conflicts.
- `I10` (Change Sequencing): React Flow DAG displaying ordered execution steps to prevent management lockout.
- `I11` (Cross-Layer What-If Simulation): Interactive what-if simulator toggle showing baseline vs candidate reachability.
- `I12` (Service-Safety Contracts): Service contract editor and violation badge table (e.g. "Preserve Admin SSH on 10.0.0.0/24").
- `I13` (Blast-Radius Estimation): Impact radius visualization highlighting all endpoints and services affected by a plan.
- `I14` (Safety-Gated Execution): Approval blocker UI preventing execution when mandatory safety contracts are violated.
- `I15` (Staged Hardening Rollout): Batch rollout monitor displaying canary stage health and automatic halt triggers.
- `I16` (Dual Verification): Verification results card displaying dual checkmarks: CIS configuration PASS + Live service PASS.
- `I17` (Residual Risk Measurement): Before-vs-after risk gauge displaying predicted residual risk post-hardening.
- `I18` (Proof-of-Hardening Dossier): Comprehensive dossier viewer with cryptographically signed before/after hashes and audit chain.
- `I19` (Benchmark Upgrade Impact Preview): Visual diff viewer illustrating which rules would trigger new failures upon upgrade.
- `I20` (Explainable Coverage Decisions): Detailed coverage breakdown panel explaining unassessed checks, parser limitations, and evidence gaps.

---

## 6. Phase 0 Verification & Readiness Gate

As Frontend Owner, I confirm:
1. **Source References Mastered**: Both `CISGuard_360_Complete_PRD_v1.pdf` and `CISGuard_360_Final_Tech_Stack_v3.pdf` have been reviewed end-to-end.
2. **Immutable Scope Preserved**: All 88 features are accounted for in the frontend architectural model.
3. **No AI/ML or Fake Results**: The frontend design operates on deterministic data, explicit status states, and typed schemas.
4. **Deliverables Ready**:
   - `docs/frontend/phase0-review.md` (this document)
   - `docs/frontend/routes.md` (route map and 88-feature screen matrix)
   - `docs/frontend/component-plan.md` (component taxonomy, design tokens, graph & DAG plans)
   - `docs/frontend/contract-questions.md` (formal contract review and questions for Mandar & Vidhi)
   - `apps/web/src/contracts/v1/` (typed client schemas & Zod validators)
   - `apps/web/src/fixtures/` (deterministic synthetic DEMO fixtures)

