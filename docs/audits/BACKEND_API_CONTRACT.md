# CISGuard 360 — Backend API & Worker Integration Contract (v1.0.0)

**Target Collaborators:** Apoorva (`apps/web`), Vidhi (`services/device-engine`)  
**Backend Lead:** Mandar (`apps/api`)  
**Specification Version:** `1.0.0` (FROZEN)  
**OpenAPI Specification:** `docs/core/phase7-9-openapi.json` and `packages/contracts/v1/openapi.yaml`

---

## 1. Global Wire Invariants & Protocol Conventions

### 1.1 Base URL & Security Headers
* **Base URL:** `http://localhost:8000/api/v1`
* **Authentication:** Every request (except health probes) requires:
  * `Authorization: Bearer <supabase_jwt_access_token>`
  * `X-Org-Id: <uuid_of_active_organization>`
* **MFA Elevation:** Endpoints performing privileged state mutations (Approvals, Change Execution) enforce that the JWT contains:
  * `aal: "aal2"` (Authenticator Assurance Level 2)

### 1.2 Standard Success Response Envelope
All API endpoints return JSON enclosed in the standard resource envelope:
```json
{
  "schema_version": "1.0.0",
  "data": { ... },
  "meta": {
    "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
  }
}
```

### 1.3 Standard Error Response Envelope
HTTP error responses (4xx / 5xx) follow this canonical structure:
```json
{
  "code": "PERMISSION_DENIED",
  "message": "User does not possess 'change.approve' permission in this organization.",
  "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "details": {},
  "retryable": false
}
```

### 1.4 Cursor Pagination
List endpoints accept `cursor` (UUID string) and `limit` (integer, 1–100, default 20) query parameters and return:
```json
{
  "items": [ ... ],
  "next_cursor": "550e8400-e29b-41d4-a716-446655440000",
  "has_more": true
}
```

---

## 2. API Routes Inventory by Family

### 2.1 Authentication & Organization Management
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `GET` | `/api/v1/auth/session` | Inspect active identity, role, and MFA state | Any authenticated user |
| `POST` | `/api/v1/organizations` | Create a new tenant organization | Authenticated user |
| `GET` | `/api/v1/organizations` | List user's tenant organizations | Authenticated user |
| `GET` | `/api/v1/organizations/{id}/members` | List members in organization | Member of organization |
| `POST` | `/api/v1/organizations/{id}/invitations` | Invite a new user to organization | `owner`, `security_admin` |
| `POST` | `/api/v1/organizations/invitations/accept` | Accept pending invitation | Authenticated user matching email |

### 2.2 Asset Inventory & Scopes (M13, E01–E04)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/assets` | Register an asset into tenant inventory | `operator` (`asset.write`) |
| `GET` | `/api/v1/assets` | List registered assets with pagination | `audit.read` |
| `GET` | `/api/v1/assets/{id}` | Retrieve asset details and capabilities | `audit.read` |
| `POST` | `/api/v1/scopes` | Create CIDR discovery authorization scope | `security_admin` (`scope.write`) |
| `POST` | `/api/v1/credentials` | Register OpenBao vault secret reference | `security_admin` (`credential.write`) |

### 2.3 CIS Policy Management (M16–M19, E11–E14)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `GET` | `/api/v1/policies` | List available versioned CIS benchmark packs | `audit.read` |
| `GET` | `/api/v1/policies/{id}/rules` | List deterministic CIS rules in pack | `audit.read` |
| `POST` | `/api/v1/policies/overrides` | Register custom benchmark baseline override | `security_admin` (`policy.write`) |
| `POST` | `/api/v1/exceptions` | Register an approved policy exception | `security_admin` (`policy.write`) |

### 2.4 Audit Scans & Scheduling (M13, E04, E08–E09)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/scans` | Dispatch a multi-target audit scan job | `operator` (`audit.scan`) |
| `GET` | `/api/v1/scans/{id}` | Inspect scan progress and score | `audit.read` |
| `GET` | `/api/v1/scans/{id}/targets` | Inspect target-by-target scan statuses | `audit.read` |
| `POST` | `/api/v1/schedules` | Configure periodic scheduled audit | `operator` (`audit.scan`) |

### 2.5 Compliance Findings & Reports (M35–M38, E06–E07, E26–E30)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `GET` | `/api/v1/findings` | Query canonical findings with severity filters | `audit.read` |
| `GET` | `/api/v1/findings/{id}` | Retrieve finding expected vs actual evidence | `audit.read` |
| `POST` | `/api/v1/reports` | Generate report (PDF, HTML, CSV, JSON) | `auditor` (`report.export`) |
| `GET` | `/api/v1/reports/{id}/download` | Generate signed download URL | `auditor` (`report.export`) |

### 2.6 Security Graph & Risk Scenarios (Phase 6, I01–I05)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `GET` | `/api/v1/graph` | Export NetworkX topology and finding graph | `audit.read` |
| `GET` | `/api/v1/risk-scenarios` | Retrieve correlated multi-device risk paths | `audit.read` |
| `GET` | `/api/v1/risk-scenarios/{id}` | Inspect root cause and explainability chain | `audit.read` |

### 2.7 Remediation Optimizer & Plans (Phase 7, I06–I10)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/plans` | Generate CP-SAT minimal-change plan | `operator` (`plan.write`) |
| `GET` | `/api/v1/plans/{id}` | Retrieve generated remediation plan | `operator`, `approver`, `auditor` |
| `GET` | `/api/v1/plans/{id}/alternatives`| List ranked trade-off alternatives | `operator`, `approver`, `auditor` |

### 2.8 Approvals, Changes & Verification (Phase 8, E21–E25, I14–I16)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/simulations` | Simulate plan against safety contracts | `operator` (`change.execute`) |
| `POST` | `/api/v1/approvals` | Record approver decision (MFA AAL2 required) | `approver` (`change.approve`) |
| `POST` | `/api/v1/changes` | Create change ticket bound to approved plan | `operator` (`change.execute`) |
| `POST` | `/api/v1/changes/{id}/advance` | Advance state machine (EXECUTE, VERIFY) | `operator` (`change.execute`) |

### 2.9 Proof Dossier & Drift Events (Phase 9, E05, E19, I17–I20)
| Method | Endpoint | Description | Required Role / Permission |
|---|---|---|---|
| `POST` | `/api/v1/proofs` | Generate Ed25519 signed proof dossier | `auditor` (`report.export`) |
| `POST` | `/api/v1/proofs/verify` | Verify Ed25519 digital signature of dossier | Public / Any authenticated role |
| `GET` | `/api/v1/drift-events` | Query detected compliance drift events | `auditor`, `security_admin` |

---

## 3. Worker & Device Engine Interface (For Vidhi)

The interface between Mandar's Celery workers and Vidhi's device collectors is defined in [`cisguard_api/device_port.py`](file:///c:/Users/sawan/OneDrive/Desktop/miniproject%20hack%20!!/apps/api/cisguard_api/device_port.py):

### 3.1 Collector Contract: `collect_device_facts(asset) -> NormalizedEvidence`
Vidhi's `services/device-engine` will provide:
```python
class NormalizedEvidence(BaseModel):
    schema_version: str = "1.0.0"
    org_id: UUID
    asset_id: UUID
    platform: str                    # e.g. "ubuntu", "cisco_ios", "fortios"
    vendor: str                      # e.g. "Canonical", "Cisco", "Fortinet"
    model: str                       # e.g. "22.04", "ISR4431", "FortiGate-60F"
    os_or_firmware_version: str
    collector_version: str
    collection_method: str           # "ssh", "netconf", "restconf", "offline_fixture"
    collected_at: datetime
    facts: dict[str, Any]            # Normalized system and network configuration facts
    evidence_refs: list[EvidenceRef] # SHA-256 digests and command provenance
    supported_capabilities: list[str]
    unsupported_capabilities: list[str]
    errors: list[str]
```

### 3.2 Hardening Execution Contract
Approved action IDs are dispatched to Vidhi's execution engine:
- Never accept arbitrary CLI command strings from the browser.
- Only dispatch registered, immutable `action_id` references from approved plans.
- Every action must specify a validated rollback command.

---

## 4. Required Environment Variables

All variables are defined with defaults in `apps/api/.env.example`:
```ini
# FastAPI Service
APP_ENV=development
API_HOST=127.0.0.1
API_PORT=8000

# Supabase PostgreSQL Database (Requires Postgres 17+ with RLS)
DATABASE_URL=postgresql+psycopg://postgres:<secret>@db.<supabase_ref>.supabase.co:5432/postgres

# Supabase Auth
SUPABASE_URL=https://<supabase_ref>.supabase.co
SUPABASE_ANON_KEY=<secret>
SUPABASE_JWT_SECRET=<secret>

# Redis & Celery
REDIS_URL=redis://127.0.0.1:6380/0
CELERY_RESULT_BACKEND=redis://127.0.0.1:6380/1

# OpenBao Secrets Vault
OPENBAO_ADDR=http://127.0.0.1:8201
OPENBAO_KV_MOUNT=secret
OPENBAO_ROLE_ID=<secret>
OPENBAO_SECRET_ID=<secret>

# Device Engine Integration
ENABLE_SYNTHETIC_FIXTURES=true
MOCK_ENGINE_URL=http://127.0.0.1:8090
```

