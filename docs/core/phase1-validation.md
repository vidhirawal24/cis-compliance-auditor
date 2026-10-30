# Phase 1 validation

29 October 2026, Python 3.12 on Windows.

- Supabase connectivity: passed, encrypted connection, secrets omitted from output.
- Alembic `0001_foundation` upgrade: completed successfully.
- Existing contract suite plus foundation tests: **212 passed**. One upstream Starlette/httpx deprecation warning.
- Explicitly opted-in live Supabase tenant-isolation test: **1 passed**. Two synthetic organizations/members/groups were created inside one rolled-back transaction. Own-tenant reads succeeded; foreign-tenant reads/inserts and forged tenant context were denied.
- Python compilation: passed.
- Docker: unavailable on host; container execution not tested.
- CI: workflow template prepared under infra; not installed or run in GitHub.

Repeat live isolation only intentionally:

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q apps/api/tests/test_live_isolation.py
```

This is foundation evidence, not proof of 88 implemented product features. Full authenticated user/MFA integration needs real test identities; broader per-table mutation workflows, recovery and deployment remain future validation work.
