# CISGuard 360 — Environment Configuration Guide

This guide documents the authoritative environment variables for the CISGuard 360 backend, their typing, validation rules, and environment boundaries.

---

## 1. Environment Variable Reference

| Variable Name | Type | Required | Default | Purpose & Rules |
|---|---|:---:|---|---|
| `ENVIRONMENT` | `str` | Yes | `development` | Runtime environment: `development`, `staging`, or `production`. |
| `DATABASE_URL` | `SecretStr` | Yes | — | PostgreSQL connection string for API operations. Uses connection pooler on port 6543 (`NullPool`). |
| `MIGRATION_DATABASE_URL` | `SecretStr` | Yes | — | Direct/session PostgreSQL connection string on port 5432 for Alembic DDL migrations. |
| `DATABASE_ROLE` | `str` | Yes | `cisguard_api` | Enforces runtime role switching. Validator strictly rejects any value other than `cisguard_api`. |
| `DATABASE_SSLMODE` | `str` | Yes | `require` | SSL connection mode for PostgreSQL (`require` or `verify-full`). |
| `SUPABASE_URL` | `str` | Yes | — | HTTPS origin of the Supabase project. Rejects non-HTTPS schemes or URL paths. |
| `SUPABASE_ANON_KEY` | `SecretStr` | Yes | — | Supabase public anonymous API key for public token validation. |
| `SUPABASE_SERVICE_ROLE_KEY` | `SecretStr` | No | `""` | Deliberately optional; never exposed to API endpoints or frontend clients. |
| `REDIS_URL` | `SecretStr` | Yes | `redis://127.0.0.1:6380/0` | Redis connection URL for caching and default messaging. |
| `CELERY_BROKER_URL` | `SecretStr` | Yes | `redis://127.0.0.1:6380/0` | Celery task queue broker (Redis DB 0). |
| `CELERY_RESULT_BACKEND` | `SecretStr` | Yes | `redis://127.0.0.1:6380/1` | Celery task result backend (Redis DB 1). |
| `OPENBAO_ADDR` | `str` | Yes | `http://127.0.0.1:8201` | OpenBao API address. HTTP permitted only on `localhost`/`127.0.0.1`; HTTPS required elsewhere. |
| `OPENBAO_ROLE_ID` | `SecretStr` | Yes | — | AppRole Role ID for the `cisguard-worker` role. |
| `OPENBAO_SECRET_ID` | `SecretStr` | Yes | — | AppRole Secret ID for the `cisguard-worker` role. |
| `OPENBAO_KV_MOUNT` | `str` | Yes | `secret` | Vault mount path for KV v2 secrets. |
| `CURSOR_SIGNING_KEY` | `SecretStr` | Yes | — | HMAC key for signed opaque pagination cursors (`secrets.token_urlsafe(48)`). |
| `DEVICE_ENGINE_URL` | `str` | No | `http://mock-device-engine:8090` | Internal URL for Vidhi's device engine service (Phase 4+ integration). |

---

## 2. Security Boundaries & Masking

1. **Pydantic SecretStr**: All passwords, API keys, connection strings, and tokens are parsed as `SecretStr`. Printing, logging, or dumping settings masks them as `**********`.
2. **Never Commit `.env`**: Both root `.gitignore` and `apps/api/.gitignore` strictly ignore `.env` and `.env.*`.
3. **No Root Token**: OpenBao integration operates strictly via AppRole authentication with short-lived tokens. The OpenBao root token must never be placed in `.env`.
4. **Host vs. Container Networking**:
   - When running the backend on the Windows host with Docker Desktop containers:
     - Redis: `127.0.0.1:6380`
     - OpenBao: `127.0.0.1:8201`
   - When running the backend inside a Docker container within the same Docker network:
     - Use Docker service names: `redis:6379` and `openbao:8200`.

---

## 3. Template Configuration (`apps/api/.env.example`)

```dotenv
# Copy to apps/api/.env; never commit real values. All values are backend-only.
ENVIRONMENT=development
DATABASE_URL=postgresql+psycopg://postgres.PROJECT_REF:URL_ENCODED_PASSWORD@POOLER_HOST:6543/postgres
# Direct/session connection for Alembic; transaction pooling has prepared-statement limitations.
MIGRATION_DATABASE_URL=postgresql+psycopg://postgres.PROJECT_REF:URL_ENCODED_PASSWORD@POOLER_HOST:5432/postgres
DATABASE_SSLMODE=require
DATABASE_ROLE=cisguard_api
SUPABASE_URL=https://PROJECT_REF.supabase.co
SUPABASE_ANON_KEY=YOUR_PUBLIC_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY=
REDIS_URL=redis://127.0.0.1:6380/0
CELERY_BROKER_URL=redis://127.0.0.1:6380/0
CELERY_RESULT_BACKEND=redis://127.0.0.1:6380/1
# OpenBao AppRole integration for device secrets (KV v2)
OPENBAO_ADDR=http://127.0.0.1:8201
OPENBAO_ROLE_ID=REPLACE_WITH_OPENBAO_ROLE_ID
OPENBAO_SECRET_ID=REPLACE_WITH_OPENBAO_SECRET_ID
OPENBAO_KV_MOUNT=secret
# Generate with Python secrets.token_urlsafe(48); required for cursor integrity.
CURSOR_SIGNING_KEY=REPLACE_WITH_RANDOM_BACKEND_SECRET
DEVICE_ENGINE_URL=http://localhost:8090
```

