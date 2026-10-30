# CISGuard 360 — Redis & OpenBao Live Integration Audit

**Audit Timestamp**: 29 October 2026  
**Auditor**: Lead Backend, Security & DevOps Engineer (Mandar Workstream)  
**Host**: Local Windows 11 host with Docker Desktop  
**Redis Endpoint**: `127.0.0.1:6380` (Container: `cisguard-redis`)  
**OpenBao Endpoint**: `http://127.0.0.1:8201` (Container: `cisguard-openbao`, v2.7.2)

---

## 1. Redis & Celery Live Verification

### A. Environment Configuration
- `REDIS_URL`: `redis://127.0.0.1:6380/0`
- `CELERY_BROKER_URL`: `redis://127.0.0.1:6380/0`
- `CELERY_RESULT_BACKEND`: `redis://127.0.0.1:6380/1`

### B. Redis Database Partitioning
1. **Database 0 (Broker)**:
   - Live PING: `True` (Latency < 2ms).
   - Write/Read Probe: Key `audit:probe:0` written and verified.
   - Celery Queue: `celery` list initialized; Kombu routing keys active.
2. **Database 1 (Result Backend)**:
   - Live PING: `True` (Latency < 2ms).
   - Write/Read Probe: Key `audit:probe:1` written and verified.
   - Result expiration configured: 3600 seconds.

### C. Celery Worker Execution
- **Task Registration**:
  - `cisguard.foundation_ping`: Baseline probe returning `{"status": "ready", "device_operations": "UNSUPPORTED"}`.
  - `cisguard.run_scan`: Scan execution entry point invoking `execute_scan_job(org_id, scan_id)`.
- **Windows Platform Compatibility**:
  - Default Celery prefork execution pool (`billiard`) raises `WinError 5` / `WinError 6` on Windows.
  - Worker configured to execute with `-P solo` pool on Windows hosts.
- **End-to-End Task Lifecycle Verified**:
  1. Task dispatched asynchronously: `async_result = foundation_ping.delay()`.
  2. Task ID generated: UUID registered in Redis DB 0 queue.
  3. Worker picked up task from queue.
  4. Task executed.
  5. Result stored in Redis DB 1.
  6. Client retrieved result via `async_result.get(timeout=8)`:
     ```json
     {"status": "ready", "device_operations": "UNSUPPORTED"}
     ```
- **Redis & Celery Status**: **PASS (100% Live Verified)**.

---

## 2. OpenBao Live Verification

### A. Environment & Mount Configuration
- `OPENBAO_ADDR`: `http://127.0.0.1:8201`
- `OPENBAO_KV_MOUNT`: `secret`
- `OPENBAO_ROLE_ID`: Masked UUID in `apps/api/.env`
- `OPENBAO_SECRET_ID`: Masked UUID in `apps/api/.env`

### B. AppRole Authentication
- **Endpoint**: `POST /v1/auth/approle/login`
- **Payload**: `{"role_id": "...", "secret_id": "..."}`
- **Response**: HTTP 200 OK.
- **Client Token**: Short-lived, restricted token generated and returned. Token is wrapped in `SecretStr` at the boundary and never logged or serialized to JSON responses.

### C. KV v2 Secret Retrieval
- **Test Secret Path**: `secret/data/cisguard/devices/lab-router`
- **Method**: `OpenBao.read_kv_secret("cisguard/devices/lab-router", token)`
- **Response**: HTTP 200 OK.
- **Retrieved Fields**:
  - `username`: `"demo"`
  - `password`: `"dummy-only"`
- **Secret Masking**:
  - `str(credentials)` and `repr(credentials)` verified: raw secret values are masked as `**********` by `SecretStr`.

### D. Negative Security Tests
1. **Root Listing Denied (Least Privilege)**:
   - Worker attempted to list KV root metadata (`LIST /v1/secret/metadata`).
   - OpenBao policy correctly rejected request with **HTTP 403 Forbidden**.
   - Client raised `PermissionError`.
2. **Missing Secret Path**:
   - Worker requested non-existent device secret `secret/data/cisguard/devices/missing-device-target`.
   - OpenBao returned **HTTP 404 Not Found**.
   - Client cleanly raised `KeyError`.
3. **Invalid AppRole Secret ID**:
   - Login attempted with corrupted Secret ID.
   - OpenBao returned **HTTP 400 Bad Request**.
   - Client raised `PermissionError`.
4. **Remote HTTP Prohibition**:
   - `OpenBao("http://bao.example.test")` rejected with `ValueError` (HTTP only permitted on loopback development).

### E. OpenBao Deployment Limitation Note
- The local OpenBao container currently operates with in-memory development storage. Container restarts will re-seal or re-initialize the vault unless persistent volume mounts are configured.
- **Production Requirement**: Production deployment requires persistent storage backend (e.g. Raft or PostgreSQL), TLS certificates (HTTPS), and automated AppRole secret ID rotation via HashiCorp/OpenBao agent.

- **OpenBao Status**: **PASS (100% Live Verified)**.

---

## 3. Automated Test Verification Command

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache apps/api/tests/test_live_infrastructure.py
```

Result: `3 passed in 21.51s` (0 failures).

