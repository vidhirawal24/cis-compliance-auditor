# Phase 1 foundation handoff

The supplied Supabase database connected successfully. Alembic revision `0001_foundation` was applied to the dedicated `cisguard` schema. Credentials live only in ignored `apps/api/.env`; the service-role key remains unset. Do not publish that file or include it in container images. Because the database password was shared in chat, rotate it before production use.

Implemented: packaged FastAPI/Uvicorn service, HTTPX Supabase Auth verification, tenant-scoped session endpoint, canonical errors/request IDs, SQLAlchemy/psycopg models, Alembic migration, restricted NOLOGIN runtime role, membership-based RLS, composite tenant foreign keys, timestamps, retention metadata/indexes, read-only Celery foundation task, mock health service and Docker Compose. Models cover all requested Phase 1 entity families. Migration metadata is frozen in `migrations/schema_v0001.py` so future model changes cannot rewrite this revision.

## Run

From the workspace root, with the existing Python environment:

```powershell
& infra/.venv-phase0/Scripts/python.exe -m uvicorn cisguard_api.main:app --host 127.0.0.1 --port 8000
& infra/.venv-phase0/Scripts/python.exe -m alembic -c apps/api/alembic.ini current
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests
```

For a fresh environment install `infra/phase1-requirements.lock.txt`, then `pip install --no-deps -e packages/contracts -e apps/api`. Docker command: `docker compose -f infra/docker-compose.yml up --build`. The optional `local-db` profile provides PostgreSQL only, not a complete Supabase Auth/Storage installation. Configure local connection values explicitly before using that profile.

`infra/ci.yml` is a prepared GitHub Actions workflow template. It is not active until installed in the shared `.github/workflows/` directory; that directory is outside Mandar's ownership boundary. No Docker executable is available on this host, so container startup is unverified.

## Security boundary and remaining work

The database URL is an administrator connection. API transactions immediately switch to `cisguard_api`, which only has SELECT privileges in this foundation. It has no table ownership or RLS bypass. Browser Supabase roles receive no grants to this private schema. Session context is transaction-local for compatibility with transaction pooling. Administrator/migration access inherently bypasses RLS; keep it backend-only and provision a separate least-privilege login before production deployment.

Initial organizations/members must be provisioned through a reviewed administrative bootstrap; no public membership-creation endpoint exists. Business CRUD, scanning, device adapters, full RBAC workflows, retention deletion, signed audit chains, outbox delivery and hardening are later implementation. Retention fields do not imply an automatic purge service. Audit events currently have no runtime write grant. The mock does not produce compliance results.

The Phase 0 contract remains PROPOSED and unchanged; the user explicitly authorized starting Phase 1. This implementation does not manufacture teammate sign-off. No feature is claimed complete solely because its table exists.

Connection handling follows [Supabase pooling guidance](https://supabase.com/docs/guides/database/connecting-to-postgres): prepared statements are disabled and migrations use the session connection. RLS ownership limitations follow [PostgreSQL documentation](https://www.postgresql.org/docs/17/ddl-rowsecurity.html).
