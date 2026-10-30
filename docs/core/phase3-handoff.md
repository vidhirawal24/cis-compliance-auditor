# Phase 3: Asset Inventory, Scheduling, and Job Orchestration

Prepared 29 October 2026. Scope: M13, E01–E04, E08–E09, E30. Read this document alongside `docs/core/phase3-validation.md` and `docs/core/phase3-openapi.json`.

## Implemented

- **Asset Inventory & Lifecycle (E01, E30)**:
  - Full CRUD endpoints (`/api/v1/assets`, `/api/v1/assets/{id}`) with tenant scoping, pagination, and unique target validation.
  - Soft-retirement via `DELETE /api/v1/assets/{id}` setting `retired = true`, preserving historical scan jobs, findings, and evidence references.
  - Granular RBAC: `inventory.write` required for asset registration and retirement; `audit.read` for asset queries.

- **Device Capability Registry & Synthetic v1 Port (M01, M11, I20)**:
  - Family-specific capability querying (`GET /api/v1/assets/{id}/capabilities`) supporting five core device families: `windows`, `linux`, `firewall`, `router`, and `switch`.
  - Compatibility status tracking (`FIXTURE_TESTED`), reporting supported inspection primitives (e.g., `registry.policy`, `sshd.config`, `firewall.policies`) and unsupported actions.
  - Synthetic device collection port (`collect_device_facts`) in `device_port.py` implementing read-only facts collection, SHA-256 fingerprinting, collection provenance tracking, and encrypted artifact references (`private://config-snapshots/...`). No plaintext passwords or SSH private keys are ever stored or exposed.

- **Authorized Discovery & SSRF Mitigation (E02)**:
  - Discovery queuing endpoint (`POST /api/v1/assets/discover`) requiring `inventory.write` and MFA step-up (`aal2`).
  - Strict CIDR validation (`validate_discovery_cidr`) blocking loopback addresses (`127.0.0.0/8`), AWS/cloud metadata services (`169.254.169.254`), link-local subnets (`169.254.0.0/16`), and multicast spaces (`224.0.0.0/4`).

- **Multi-Target Scan Orchestration & Per-Target Failure Isolation (M13, E08, E09)**:
  - Scan creation (`POST /api/v1/scans`) and inspection (`GET /api/v1/scans/{id}`, `GET /api/v1/scans/{id}/assets`).
  - Background execution engine (`execute_scan_job` in `worker.py`): executes multi-target inspection batches.
  - **M13 Failure Isolation Guarantee**: If an individual target experiences a timeout, authentication failure, or unreachable host, the failure is isolated entirely to that target's `ScanTarget` record (with typed error codes such as `TIMEOUT`, `AUTH_FAILED`, or `DEVICE_UNAVAILABLE`). Remaining targets continue execution to completion.
  - Aggregate scan job status transitions dynamically:
    - `SUCCEEDED` when all targets complete without errors.
    - `PARTIAL` when some targets succeed and some fail.
    - `FAILED` when all targets fail.
  - Emits transactional `OutboxEvent` records (`cisguard.scan.completed`) and append-only `AuditEvent` records.

- **Scan Scheduling (E04)**:
  - Schedule management endpoints (`GET /api/v1/scans/schedules`, `POST /api/v1/scans/schedules`, `DELETE /api/v1/scans/schedules/{id}`).
  - Standard 5-part cron validation (`CRON_REGEX`), backed by `cisguard.schedules`.
  - Fixed route registration precedence before `/scans/{scan_id}` to prevent path parsing collisions.

- **Celery Worker & Redis Broker**:
  - Celery application in `worker.py` configured with Redis broker (`task_serializer="json"`, `worker_prefetch_multiplier=1`, `task_time_limit=300`).
  - Background tasks: `cisguard.foundation_ping` and `cisguard.run_scan`.

## Endpoints

| Method | Route | Permission Required | Description |
|---|---|---|---|
| GET | `/api/v1/assets` | `audit.read` | List organization assets with pagination and filters |
| POST | `/api/v1/assets` | `inventory.write` | Register new asset in scope |
| GET | `/api/v1/assets/{id}` | `audit.read` | Fetch asset metadata |
| PUT | `/api/v1/assets/{id}` | `inventory.write` | Update asset configuration |
| DELETE | `/api/v1/assets/{id}` | `inventory.write` | Soft-retire asset (preserves history) |
| GET | `/api/v1/assets/{id}/capabilities` | `audit.read` | Query device capability registry |
| POST | `/api/v1/assets/discover` | `inventory.write` (MFA `aal2`) | Queue discovery job with SSRF-validated CIDRs |
| GET | `/api/v1/scans/schedules` | `audit.read` | List recurring scan schedules |
| POST | `/api/v1/scans/schedules` | `audit.scan` | Create recurring scan schedule with cron expression |
| DELETE | `/api/v1/scans/schedules/{id}` | `audit.scan` | Delete scan schedule |
| POST | `/api/v1/scans` | `audit.scan` | Launch multi-target scan job |
| GET | `/api/v1/scans/{id}` | `audit.read` | Get scan job status and progress |
| GET | `/api/v1/scans/{id}/assets` | `audit.read` | Get per-target execution details and errors |

All tenant endpoints require the `X-Org-ID` header. All responses are encapsulated in standard envelopes (`envelope()` and `error()`).

## Database and Migrations

- **Revision**: `0004_orchestration` (head), applied to live PostgreSQL.
- Grants DML permissions to restricted runtime role `cisguard_api` on:
  - `cisguard.assets`, `cisguard.asset_groups`, `cisguard.asset_group_members`
  - `cisguard.scan_jobs`, `cisguard.scan_targets`
  - `cisguard.schedules`
  - `cisguard.outbox_events`
  - `cisguard.authorization_scopes`
  - `cisguard.benchmark_packs`
  - `cisguard.audit_results`
  - `cisguard.config_snapshots`
  - `cisguard.audit_evidence`
- All queries strictly enforce tenant isolation and backend tenant checks (`cisguard.is_member(org_id)`).

## Run and Test

```powershell
# Run all Phase 3 unit tests
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests/test_phase3_jobs.py

# Run live PostgreSQL integration tests (M13 multi-target isolation)
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests/test_live_phase3.py

# Run full test suite across all phases (257 tests)
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

