# CISGuard 360 (BaselineGuard) — Frontend-to-Backend API Contract Integration Guide

**Auditor / Frontend Architect:** Principal Frontend Engineer  
**Recipient:** Mandar (Backend Lead) & Vidhi (Device Engine Lead)  
**Branch:** `feat/apoorva-web`  
**Date:** October 30, 2026  
**Document Status:** Pre-Integration Interface Specification & Frozen Contract Compatibility  

---

## 1. Overview & Integration Philosophy

This document details every REST API endpoint expected by Apoorva's frontend implementation. It specifies:
1. Calling page and shell component.
2. HTTP method and relative path.
3. Request headers, query parameters, and payload body.
4. Response schema wrapped in the canonical envelope (`schema_version: "1.0.0"`).
5. Error response codes and retry semantics.
6. Current implementation status in `apps/web`.

Where Mandar's backend contract is not yet frozen, the endpoint is explicitly marked **COMPATIBILITY UNVERIFIED**.

---

## 2. Canonical Payload Envelope Standard

In adherence to Rule 3 ("All production payloads use contracts/v1; do not introduce parallel schemas"):

### 2.1 Single Resource Envelope
```typescript
interface CanonicalResourceEnvelope<T> {
  schema_version: '1.0.0';
  data: T;
  meta: {
    request_id: string; // e.g. "req-abc12345"
  };
}
```

### 2.2 Paginated Collection Envelope
```typescript
interface CanonicalCollectionEnvelope<T> {
  schema_version: '1.0.0';
  data: T[];
  meta: {
    request_id: string;
    cursor: {
      next: string | null;     // Base64 opaque cursor
      prev: string | null;
      has_more: boolean;
      total_count: number;     // Mandatory for TanStack table pagination calculations
    };
  };
}
```

---

## 3. Exhaustive Endpoint Integration Inventory

### 3.1 Organization & Tenant Management

#### 3.1.1 List Organizations
- **Calling Component:** `02_OrgSelectShell.tsx`
- **Method & Path:** `GET /api/v1/organizations`
- **Headers:** `Authorization: Bearer <supabase_access_token>`, `Accept: application/json`
- **Query Params:** None
- **Response:** `CanonicalCollectionEnvelope<Organization>`
- **Current Status:** [B] Mock API in `DemoApiClient.getOrganizations()`; [A] Throws `UNSUPPORTED` in `HttpApiClient`.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED** (Awaiting Mandar's tenant membership integration).

#### 3.1.2 Create Organization
- **Calling Component:** `02_OrgSelectShell.tsx` (Create Workspace Modal)
- **Method & Path:** `POST /api/v1/organizations`
- **Payload:**
  ```json
  {
    "name": "Acme Financial SecOps",
    "slug": "acme-financial-secops"
  }
  ```
- **Response:** `CanonicalResourceEnvelope<Organization>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.2 Asset Inventory & Discovery

#### 3.2.1 List Assets
- **Calling Component:** `04_AssetInventoryShell.tsx`
- **Method & Path:** `GET /api/v1/organizations/{org_id}/assets`
- **Query Params:** `platform?: string`, `tag?: string`, `search?: string`, `limit?: number`, `cursor?: string`
- **Response:** `CanonicalCollectionEnvelope<Asset>`
- **Expected Item Schema:**
  ```typescript
  interface Asset {
    asset_id: string;
    org_id: string;
    hostname: string;
    ip_address: string;
    platform: PlatformFamily; // 'WINDOWS_11' | 'UBUNTU_22' | 'CISCO_IOS' | etc.
    os_version: string;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    status: 'ACTIVE' | 'OFFLINE' | 'UNREACHABLE';
    tags: string[];
    vault_secret_ref?: string; // e.g. "vault:secret/corp-cisco-gw"
    created_at: string;
    last_scanned_at?: string;
  }
  ```
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.2.2 Create Asset
- **Calling Component:** `04_AssetInventoryShell.tsx` (Add Device Dialog)
- **Method & Path:** `POST /api/v1/organizations/{org_id}/assets`
- **Payload:**
  ```json
  {
    "hostname": "W11-FINANCE-02",
    "ip_address": "192.168.10.45",
    "platform": "WINDOWS_11",
    "os_version": "23H2 (Build 22631)",
    "criticality": "HIGH",
    "tags": ["finance", "endpoint"]
  }
  ```
- **Response:** `CanonicalResourceEnvelope<Asset>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.2.3 Preview Discovery Sweep
- **Calling Component:** `04_AssetInventoryShell.tsx` (`/assets/discover`)
- **Method & Path:** `POST /api/v1/organizations/{org_id}/discovery/preview`
- **Payload:**
  ```json
  {
    "cidr_ranges": ["192.168.10.0/24"],
    "ports_to_probe": [22, 80, 443, 3389],
    "scope_consent_confirmed": true
  }
  ```
- **Response:** `CanonicalCollectionEnvelope<DiscoveredCandidate>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.3 Scan Center & Execution

#### 3.3.1 List Scans
- **Calling Component:** `06_ScanCenterShell.tsx`
- **Method & Path:** `GET /api/v1/organizations/{org_id}/scans`
- **Response:** `CanonicalCollectionEnvelope<ScanJob>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED** (Notice discrepancy in `contract-questions.md`: `/scans` vs PRD `/audits`).

#### 3.3.2 Launch Scan Job
- **Calling Component:** `06_ScanCenterShell.tsx` (`/scans/new`)
- **Method & Path:** `POST /api/v1/organizations/{org_id}/scans`
- **Payload:**
  ```json
  {
    "target_asset_ids": ["a01-win11-corp-01", "a02-cisco-core-sw01"],
    "policy_pack_id": "cis-win11-v3.0.0",
    "profile_level": "LEVEL_1",
    "read_only_confirmed": true
  }
  ```
- **Response:** `CanonicalResourceEnvelope<ScanJob>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.3.3 Retry Failed Scan
- **Calling Component:** `06_ScanCenterShell.tsx`
- **Method & Path:** `POST /api/v1/scans/{scan_id}/retry`
- **Response:** `CanonicalResourceEnvelope<ScanJob>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.4 Findings Explorer

#### 3.4.1 List Findings
- **Calling Component:** `09_FindingsShell.tsx`
- **Method & Path:** `GET /api/v1/organizations/{org_id}/findings`
- **Query Params:** `asset_id?: string`, `severity?: string`, `status?: string`, `benchmark_id?: string`
- **Response:** `CanonicalCollectionEnvelope<Finding>`
- **Expected Item Schema:**
  ```typescript
  interface Finding {
    finding_id: string;
    org_id: string;
    asset_id: string;
    control_id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    status: 'PASS' | 'FAIL' | 'NOT_ASSESSED' | 'ERROR' | 'UNKNOWN';
    expected_state: string;
    observed_state: string;
    evidence_hash: string; // SHA-256
    remediation_guidance: string;
    remediation_cli: string;
    created_at: string;
  }
  ```
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.5 Security Graph & Risk Scenarios

#### 3.5.1 Fetch Security Graph Topology
- **Calling Component:** `10_SecurityGraphShell.tsx`
- **Method & Path:** `GET /api/v1/organizations/{org_id}/graph`
- **Response:** `CanonicalResourceEnvelope<SecurityGraphData>`
- **Schema:**
  ```typescript
  interface SecurityGraphData {
    nodes: Array<{
      data: {
        id: string;
        label: string;
        type: 'asset' | 'interface' | 'subnet' | 'service';
        ip_address?: string;
        status?: string;
      };
    }>;
    edges: Array<{
      data: {
        id: string;
        source: string;
        target: string;
        relation: 'routes_to' | 'attached_to' | 'allows' | 'denies';
        confidence: 'CONFIRMED' | 'SUSPECTED';
      };
    }>;
  }
  ```
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.5.2 List Correlated Risk Scenarios
- **Calling Component:** `11_RiskScenariosShell.tsx`
- **Method & Path:** `GET /api/v1/organizations/{org_id}/risk-scenarios`
- **Response:** `CanonicalCollectionEnvelope<RiskScenario>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.6 Remediation Planning, Simulation & Approvals

#### 3.6.1 Fetch Remediation Plan
- **Calling Component:** `12_RemediationPlannerShell.tsx`
- **Method & Path:** `GET /api/v1/plans/{plan_id}`
- **Response:** `CanonicalResourceEnvelope<RemediationPlan>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.6.2 Submit Plan Approval
- **Calling Component:** `14_ApprovalsHardeningShell.tsx`
- **Method & Path:** `POST /api/v1/plans/{plan_id}/approve`
- **Payload:**
  ```json
  {
    "plan_hash": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "justification": "Approved hardening maintenance window for Cisco Switch VLAN security."
  }
  ```
- **Response:** `CanonicalResourceEnvelope<ApprovalRecord>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

#### 3.6.3 Execute Hardening Change
- **Calling Component:** `14_ApprovalsHardeningShell.tsx`
- **Method & Path:** `POST /api/v1/changes/{change_id}/execute`
- **Response:** `CanonicalResourceEnvelope<HardeningChange>`
- **Current Status:** [B] Mock API.
- **Backend Compatibility:** **COMPATIBILITY UNVERIFIED**.

---

### 3.7 Reports & Signed Artifacts (CURRENTLY AGREED REAL HTTP SURFACE)

#### 3.7.1 List Reports
- **Calling Component:** `16_ReportsHistoryShell.tsx`
- **Method & Path:** `GET /api/v1/reports`
- **Headers:** `Authorization: Bearer <token>`, `Accept: application/json`
- **Security Constraints:** Must be same-origin `/api/` path; redirects and anonymous calls refused.
- **Response Validation Schema (Zod):**
  ```typescript
  const reportSchema = z.object({
    report_id: z.string().min(1),
    org_id: z.string().min(1),
    title: z.string(),
    format: z.nativeEnum(ReportFormat),
    file_size_bytes: z.number().finite().nonnegative(),
    download_url: z.string(),
    signed_url_expires_at: z.string(),
    created_at: z.string(),
  });
  ```
- **Current Status:** **[A] LIVE HTTP ADAPTER IMPLEMENTED** in `apps/web/src/api/configuredClient.ts`.
- **Backend Compatibility:** **VERIFIED READY** pending Mandar's implementation of GET `/api/v1/reports`.

---

## 4. Unresolved Contract Questions for Mandar

As noted in `docs/frontend/contract-questions.md`:
1. **Endpoint Naming:** Standardize on `/scans` throughout (vs PRD `/audits`) to prevent collision with application audit events (`/audit-events`).
2. **Lifecycle Transition:** Confirm whether plan transition follows `POST /plans` → `POST /plans/{id}/approve` → `POST /changes/{id}/execute`.
3. **Pagination Total Count:** Ensure `meta.cursor.total_count` is included in all collection responses for TanStack Table pagination.
4. **WebSocket/Realtime Event Streams:** Confirm whether scan progress ticker uses Supabase Realtime Channels or Server-Sent Events (SSE).

