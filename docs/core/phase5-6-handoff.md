# Phase 5 & 6: Compliance Findings, Multi-Format Reports, and Cross-Layer Security Graph

Prepared 29–30 October 2026.
Scope: M35–M38, E06–E07, E26–E30 (Phase 5) & E13, I01–I05, I17, I20 (Phase 6).
Read this document alongside `docs/core/phase5-6-validation.md` and `docs/core/phase5-6-openapi.json`.

---

## Part 1: Phase 5 Implemented Architecture

### 1. Canonical Findings Persistence & Unified Data Pipeline (M36, E29, I20)
- **Scans -> Results -> Findings Hierarchy**:
  - Scan execution produces immutable `cisguard.audit_results` linked to `cisguard.audit_evidence`.
  - For each assessed control, a `cisguard.findings` row is persisted with severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and remediation pointers.
  - Multi-table joins dynamically reconcile finding severity, asset metadata, policy pack releases, expected/observed states, and cryptographic evidence hashes into a single canonical dictionary.
- **REST API Endpoints**:
  - `GET /api/v1/findings`: Paginated list supporting query filters: `severity`, `status`, `asset_id`, `scan_id`, and `control_id`.
  - `GET /api/v1/findings/{id}`: Detailed finding record joined with full evidence reference and historical remediation notes.
  - `GET /api/v1/dashboard/overview`: High-level aggregated statistics (total assets, recent scans, overall compliance score, and finding breakdown by severity).
  - `GET /api/v1/trends`: Historical compliance score progression and finding severity trends over time.

### 2. Multi-Format Report Generator with Guaranteed Outcome Consistency (M38, E28)
- **Single Source of Truth (`get_canonical_report_data`)**:
  - All report formats—JSON, RFC 4180 CSV, HTML, and PDF—consume the exact same parsed and verified report data structure.
  - **Identical Outcome Totals Guarantee**: Every format reflects identical counts for `pass_count`, `fail_count`, `not_applicable_count`, `manual_review_count`, `error_count`, `assessed_compliance_pct`, and `total_findings`. Verified by `test_all_four_export_formats_identical_totals`.
- **Format Engines**:
  - **JSON (`export_json`)**: Canonical indented JSON representation conforming to `Report` contracts.
  - **CSV (`export_csv`)**: Standard RFC 4180 CSV including headers: `control_id`, `title`, `asset_name`, `target`, `status`, `severity`, `expected`, `observed`, `remediation`, `evidence_ref`.
  - **HTML (`export_html`)**: Jinja2-rendered clean, print-optimized stylesheet with responsive grid cards for compliance %, coverage %, and severity breakdowns.
  - **PDF (`export_pdf`)**: High-fidelity PDF generation using WeasyPrint when system GTK libraries are present, with an automated pure-Python ReportLab fallback (`pageCompression=0`) ensuring seamless operation across standard Windows development environments and Linux containers alike.
- **Audience Views**:
  - `TECHNICAL`: Full itemized audit log with control IDs, observed values, and detailed remediation guidance.
  - `EXECUTIVE`: High-level summary metrics, compliance posture, high/critical severity focus, and risk indicators.

### 3. Authorized Signed Artifact Downloads & Evidence Archiving (M38)
- **Immutable Evidence Storage (`store_report_artifact`)**:
  - Generated report artifacts are hashed (SHA-256) and cataloged in `cisguard.audit_evidence` under `private://reports/{report_id}_{format}`.
  - Recorded in `cisguard.reports` linked to the originating `scan_id`.
- **HMAC-Protected Signed Downloads (`generate_download_link`)**:
  - Time-limited (1-hour expiration) HMAC-SHA256 signature tokens protect artifact URLs: `GET /api/v1/reports/{id}/download-file?sig={hash}&expires={timestamp}`.
  - Direct downloads require valid signatures matching `org_id:report_id:expires_ts:content_sha256`.

### 4. Enterprise Ticketing Adapters & Webhook Dispatcher (E05, E26–E28, E30)
- **Extensible Ticket Adapter Interface (`TicketAdapter`)**:
  - `JiraTicketAdapter`: Transforms canonical findings into Jira issue payloads with priority mapping (`CRITICAL` -> `Highest`, etc.) and structured descriptions.
  - `ServiceNowTicketAdapter`: Formats findings into ServiceNow Incident/Security Incident tables with assignment groups and impact calculations.
  - `GenericWebhookTicketAdapter`: Standardized JSON event payloads for custom internal ticketing pipelines.
- **Reliable Webhook Delivery (`WebhookDispatcher`)**:
  - Payload signing with HMAC-SHA256 headers (`X-CISGuard-Signature: sha256={digest}`).
  - Exponential backoff retry header calculation (`min(300, 2 ** attempt)`).
  - Outbox audit trail tracking in `cisguard.notifications` linked to `cisguard.audit_events`.

---

## Part 2: Phase 6 Implemented Architecture

### 1. NetworkX Security Graph Builder (I01, I03)
- **Multi-Layer Directed Graph (`SecurityGraphBuilder`)**:
  - Construct an in-memory NetworkX `MultiDiGraph` capturing the enterprise security topology.
  - **Nodes**:
    - `asset`: Host identity, platform, family, and criticality rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
    - `interface`: Network interface names, IP addresses, and MAC identifiers.
    - `network` / `subnet`: CIDR network blocks (e.g., `10.50.1.0/24`).
    - `route`: Next-hop routing entries.
    - `rule`: Firewall and access-control list definitions with explicit `action` (`allows` or `denies`), source/destination subnets, and destination ports.
    - `service`: Exposed network listening services.
    - `finding`: Non-compliant CIS findings linked to their parent asset.
  - **Typed Edges**:
    - `hosted_on`: Interface or service running on an asset.
    - `attached_to`: Interface connected to a subnet.
    - `routes_to`: Subnet or gateway next-hop routing.
    - `allows` / `denies`: Firewall rule access policy.
    - `depends_on`: Service or component dependencies.
    - `violates`: Finding linked to a specific asset or service.
- **Deterministic Response Serialization**:
  - Node and edge dictionaries are strictly sorted by node ID, type, and source-target keys, ensuring identical JSON serialization across calls.

### 2. Network Reachability & Topology Incompleteness (I02, I05)
- **Path Traversal (`ReachabilityEvaluator.evaluate_path`)**:
  - Traverses paths between source and destination assets via attached subnets and routing nodes.
  - Inspects all intermediate firewall rules between subnets for port and protocol permissions.
  - Returns `reachable: True` only when a contiguous valid path exists and no intermediate rule denies access.
- **Topology Missingness Detection**:
  - Detects incomplete evidence when assets have missing interface definitions, unresolved next-hops, or ambiguous routes.
  - Explicitly flags `incomplete_evidence: True` with diagnostic warnings rather than assuming reachability.

### 3. Deterministic Risk Scenario Correlator & Root Cause (E13, I02, I04, I05)
- **Verifiable Correlation Engine (`RiskScenarioCorrelator`)**:
  - Evaluates multi-device risk scenarios combining related CIS benchmark failures:
    - **Lateral Movement Scenario**: A perimeter or DMZ asset with critical misconfigurations that has verified network reachability to an internal critical asset that also exhibits security findings.
    - **Perimeter Exposure Scenario**: Publicly exposed assets hosting vulnerable services with CIS firewall or daemon failures.
    - **Shared Subnet Blast Radius**: Multiple assets co-located on the same broadcast domain sharing unpatched protocol findings.
- **Strict False Correlation Prevention**:
  - **Negative Security Invariant**: If firewall rules deny traffic between two subnets or if routing is unverifiable, lateral movement correlation is **strictly rejected**. Even if both assets have critical findings, they are not grouped into a lateral movement scenario unless network reachability is mathematically proven by graph traversal.
- **Explainability Chains & Criticality Ranking**:
  - Every risk scenario produces an explainability chain containing `source_finding_ids`, `evidence_refs`, traversed node IDs, and explicit natural-language rationale.
  - Scenario risk scoring factors both finding severity and destination asset criticality (e.g., assets flagged `CRITICAL` carry heavier risk weights).

### 4. REST Endpoints (I01, I04)
- `GET /api/v1/graph`: Returns the complete serialized network security graph for the organization.
- `POST /api/v1/graph/paths`: Evaluates reachability and intermediate firewall decisions between two specified assets and a target port.
- `GET /api/v1/risk-scenarios`: Returns deterministically ordered, correlated multi-host risk scenarios with explainability chains.
- `GET /api/v1/risk-scenarios/{scenario_id}`: Retrieves individual risk scenario details.

---

## Part 3: Test Verification Summary

- **Unit & Contract Tests**:
  - `apps/api/tests/test_phase5_reports.py`: 12 tests verifying multi-format consistency, CSV headers, PDF structure, HMAC downloads, WeasyPrint/ReportLab fallback, Jira/ServiceNow adapters, and Webhook signatures.
  - `apps/api/tests/test_phase6_graph.py`: Verifying NetworkX graph builder, reachable vs denied paths, false correlation prevention, missing topology detection, and deterministic serialization.
- **Live Supabase PostgreSQL End-to-End Test**:
  - `apps/api/tests/test_live_phase5_6.py`: Live execution against Supabase testing scan execution, findings generation, multi-format report export, database persistence, artifact storage, HMAC downloads, webhook recording, and graph correlation with real assets, followed by complete transaction rollback/cleanup.
- **Comprehensive Regression Suite**:
  - 299 tests passing across Phases 0, 1, 2, 3, 4, 5, and 6. Zero failures.

