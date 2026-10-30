# Phase 3 Validation

29 October 2026, Python 3.12 on Windows.

- **Supabase Connectivity & Live PostgreSQL Orchestration**: Verified against live Supabase PostgreSQL database.
- **Alembic Head**: Migration revision `0004_orchestration` applied; database at head.
- **Total Test Results**: **257 passed** (254 unit/contract/HTTP tests + 3 live database integration tests). One upstream Starlette/httpx deprecation warning. Zero failures.
- **M13 Failure Isolation (Live Verified)**: Multi-target scan execution tested with 3 concurrent targets on live database (Linux target, simulated timeout firewall target, Windows target). The timeout target was successfully isolated in `cisguard.scan_targets` with error code `TIMEOUT`, while the remaining two targets completed successfully to `SUCCEEDED`. ScanJob aggregate status transitioned to `PARTIAL`, completed assets reached 3/3, config snapshots and audit evidence were stored without secret leakage, outbox event `cisguard.scan.completed` was published, and all synthetic test fixtures were cleanly rolled back.
- **Device Capability Registry**: Verified for 5 families (`windows`, `linux`, `firewall`, `router`, `switch`) in `test_capabilities_registry_by_family`.
- **SSRF Mitigation (E02)**: Verified in `test_discovery_cidr_validation` and `test_discovery_ssrf_mitigation_http`. CIDR validator blocks AWS metadata `169.254.169.254/32`, link-local `169.254.0.0/16`, loopback `127.0.0.1/32`, and multicast addresses.
- **Asset CRUD & Soft-Retirement (E01)**: Verified in `test_asset_crud_and_retirement`. Assets are created, queried, updated, and soft-retired with `retired = true`, retaining historical records.
- **Scheduling & Cron Validation (E04)**: Verified in `test_scan_schedules_crud_http`. Enforces standard 5-part cron syntax and avoids route matching collisions.
- **RBAC Enforcement (E30)**: Verified in `test_rbac_job_permissions`. Auditor role lacks `inventory.write` and `audit.scan`, correctly receiving 403 Forbidden.

Run all tests including live database tests:

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

**Exit Gate Status**: Phase 3 deliverables verified. Device engine synthetic port provides strict isolation and provenance tracking until Vidhi's device engine module merges.

