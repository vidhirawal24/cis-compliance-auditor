# BaselineGuard (formerly CISGuard 360) - Contract v1 Review & Integration Questions
**Role:** Frontend Owner (Apoorva)  
**To:** Mandar (Backend Lead), Vidhi (Device Engine Lead)  
**Date:** October 29, 2026  
**Document Status:** Pending Cross-Team Agreement Before Phase 1 Code Freeze  
**Reference:** Playbook Section 4 & 5; PRD Section 11; Tech Stack Section 2 & 13  

---

## 1. Context & Review Objective

As Frontend Owner, I have conducted a rigorous audit of the frozen `contracts/v1` specification from the Playbook and PRD. In accordance with Rule 3 ("All production payloads use contracts/v1; do not introduce parallel schemas") and Rule 4 ("Contract changes: propose schema diff, review with all three, publish a minor version and only then update consumers"), I have prepared this document to resolve discrepancies, clarify payload structures, and propose the necessary additions required to faithfully render all **88 features**.

---

## 2. Critical Discrepancies & Clarifications

### Question 1: Endpoint Naming Discrepancy — `/scans` vs `/audits`
- **Issue**: The Playbook (Section 4, Page 6) defines the scan queue family as:
  `/scans`, `/scans/{id}`, `/scans/{id}/assets`, `/scans/schedules`
  However, PRD Section 11.2 (Page 17) lists:
  `POST /api/v1/audits`, `GET /api/v1/audits/{id}`
- **Frontend Recommendation**: Standardize on **`/scans`** throughout the REST API to avoid ambiguity with audit logs (`/audit-events`).
  - `POST /api/v1/scans` (launch scan)
  - `GET /api/v1/scans` (list scans)
  - `GET /api/v1/scans/{id}` (scan status and progress)
  - `GET /api/v1/scans/{id}/assets` (per-target scan results)
  - `GET / POST /api/v1/scans/schedules` (recurring scan schedules)

---

### Question 2: Transition from Plan to Approved Change (`/plans` vs `/approvals` vs `/changes`)
- **Issue**: PRD 11.2 lists `POST /plans/{id}/approve` and `POST /plans/{id}/execute`.
  The Playbook lists `/approvals`, `/changes`, `/changes/{id}`, `/changes/{id}/events`.
- **Clarification Needed**: What is the canonical entity lifecycle?
- **Proposed Flow**:
  1. Operator generates remediation plan via `POST /api/v1/plans` (returns `plan_id` in `DRAFT` or `SIMULATED` state).
  2. Approver queries pending approvals at `GET /api/v1/approvals`.
  3. Approver signs off via `POST /api/v1/plans/{plan_id}/approve` with payload `{ plan_hash: string, justification: string }`.
  4. Backend creates an approved change entity (`change_id`) in `APPROVED` state.
  5. Operator triggers execution via `POST /api/v1/changes/{change_id}/execute`.
  6. Frontend tracks live progress and stage rollouts at `GET /api/v1/changes/{change_id}` and `GET /api/v1/changes/{change_id}/events`.
- **Question**: Mandar, does this state transition match your SQLAlchemy / Celery orchestrator design?

---

### Question 3: Standard Paginated Collection Envelope
- **Issue**: Playbook Page 5 states: `Pagination: cursor + limit; filters in query params.`
  Canonical resource envelope is: `{ schema_version: '1.0.0', data, meta: { request_id } }`.
- **Proposed Schema for Collections**:
  ```json
  {
    "schema_version": "1.0.0",
    "data": [ ... ],
    "meta": {
      "request_id": "uuid",
      "cursor": {
        "next": "eyJpZCI6...==",
        "prev": null,
        "has_more": true,
        "total_count": 254
      }
    }
  }
  ```
- **Question**: Can we confirm whether `total_count` will be returned in `meta.cursor` to support TanStack Table pagination controls?

---

### Question 4: Cytoscape Graph Payload Schema (`/api/v1/graph`)
- **Issue**: Cytoscape.js requires typed elements (nodes and edges). Feature `I01` requires linking assets, interfaces, subnets, services, and controls.
- **Proposed Contract**:
  ```typescript
  interface GraphElementNode {
    data: {
      id: string;
      label: string;
      type: 'asset' | 'interface' | 'subnet' | 'service' | 'finding';
      platform?: string;
      ip_address?: string;
      cidr?: string;
      port?: number;
      severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      status?: 'PASS' | 'FAIL' | 'UNKNOWN';
    };
  }

  interface GraphElementEdge {
    data: {
      id: string;
      source: string;
      target: string;
      relation: 'hosted_on' | 'attached_to' | 'routes_to' | 'allows' | 'denies' | 'violates';
      evidence_ref?: string;
      confidence: 'CONFIRMED' | 'SUSPECTED';
    };
  }

  interface SecurityGraphData {
    nodes: GraphElementNode[];
    edges: GraphElementEdge[];
    meta: {
      total_nodes: number;
      total_edges: number;
      coverage_completeness_pct: number;
    };
  }
  ```
- **Question**: Does this structure match Vidhi's network model output and Mandar's NetworkX export?

---

### Question 5: Offline Configuration Assessment Endpoint (`E10`)
- **Issue**: Feature `E10` requires auditing uploaded/sanitized device configuration snapshots, with results clearly marked as non-live.
- **Proposed Contract**:
  - `POST /api/v1/assets/offline-import`:
    - Content-Type: `multipart/form-data`
    - Form fields: `platform: PlatformEnum`, `device_name: string`, `file: File`
    - Response: `{ asset_id: string, is_offline: true, snapshot_id: string }`
  - `POST /api/v1/scans`:
    - Payload accepts `target_asset_ids: [asset_id]` and runs the audit in offline mode, producing findings labeled `offline: true`.

---

### Question 6: Manual Review Attestation Endpoint (`E12`)
- **Issue**: Controls requiring human validation need an auditable attestation workflow.
- **Proposed Contract**:
  - `GET /api/v1/manual-reviews?status=PENDING`
  - `POST /api/v1/manual-reviews/{review_id}/attest`:
    - Payload:
      ```json
      {
        "verdict": "PASS" | "FAIL",
        "justification": "Verified physical console lock configuration in Server Room B",
        "evidence_file_ids": ["uuid-1", "uuid-2"]
      }
      ```

---

### Question 7: Benchmark Upgrade Impact Preview Endpoint (`I19`)
- **Issue**: Feature `I19` requires comparing applicability and evaluation changes across two policy versions before upgrading.
- **Proposed Contract**:
  - `GET /api/v1/policies/{policy_id}/upgrade-preview?target_version=2.0.0`
  - Returns:
    ```json
    {
      "current_version": "1.0.0",
      "target_version": "2.0.0",
      "added_rules_count": 14,
      "removed_rules_count": 2,
      "modified_rules_count": 8,
      "affected_assets_count": 42,
      "estimated_compliance_delta_pct": -4.2,
      "rule_diffs": [ ... ]
    }
    ```

---

### Question 8: Service-Safety Contracts CRUD (`I12`, `I14`)
- **Issue**: What is the canonical endpoint for managing service-safety contracts?
- **Proposed Contract**:
  - `GET /api/v1/safety-contracts`
  - `POST /api/v1/safety-contracts`
  - `DELETE /api/v1/safety-contracts/{id}`
  - Schema:
    ```typescript
    interface SafetyContract {
      id: string;
      name: string;
      description: string;
      source_cidr: string;
      destination_cidr: string;
      port_range: string;
      protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
      mandatory: boolean; // if true, violation blocks hardening approval (I14)
      created_at: string;
    }
    ```

---

### Question 9: Proof-of-Hardening Dossier & Hash Manifest (`I18`)
- **Issue**: Third-party verification of the dossier requires verifying cryptographic signatures and before/after hashes.
- **Proposed Contract**:
  - `GET /api/v1/proof-packages/{package_id}` returns:
    - `change_id`, `plan_id`, `verification_id`
    - `operator_id`, `approver_id`, `approval_timestamp`
    - `pre_hardening_config_hash` (SHA256)
    - `post_hardening_config_hash` (SHA256)
    - `execution_log_hash` (SHA256)
    - `digital_signature`: string
    - `manifest_verified`: boolean
    - `download_urls`: `{ pdf: string, json: string }`

---

## 3. Immediate Action Items Before Proceeding to Phase 1

1. Mandar to review Questions 1, 2, 3, 7, 8, 9 and confirm endpoint names.
2. Vidhi to review Question 4 (Graph elements) and Question 5 (Offline config format).
3. Once agreed, Mandar will publish minor update to `packages/contracts/v1/`.
4. In the meantime, Apoorva has implemented typed client schemas and deterministic synthetic DEMO fixtures in `apps/web/src/contracts/v1/` and `apps/web/src/fixtures/` following these exact proposed schemas.

