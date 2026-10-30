# CISGuard 360 — Redis, Celery & OpenBao Live Infrastructure Audit Report

**Audit Target:** Local Dockerized Services (`cisguard-redis` and `cisguard-openbao`)  
**Audit Scripts:** `infra/test_redis_celery_live.py`, `infra/test_openbao_live.py`  
**Execution Timestamp:** 2026-10-30T01:52:00+05:30  
**Overall Status:** **VERIFIED OPERATIONAL (100% PASS across live broker, worker, and vault calls)**

---

## 1. Redis Live Audit

### 1.1 Connection & Database Layout
* **Container Name:** `cisguard-redis`
* **Network Binding:** `127.0.0.1:6380` (Host) $\to$ `6379` (Container)
* **Version:** Redis 7.4 Alpine
* **Separation of Concerns:**
  * **Database 0 (Celery Task Broker):** `redis://127.0.0.1:6380/0`
  * **Database 1 (Celery Result Backend):** `redis://127.0.0.1:6380/1`

### 1.2 Verification Results
```
Connecting to Redis Broker at redis://127.0.0.1:6380/0...
  [PASS] Redis DB 0 connected, ping OK, set/get OK
Connecting to Redis Backend at redis://127.0.0.1:6380/1...
  [PASS] Redis DB 1 connected, ping OK, set/get OK
```

---

## 2. Celery Worker & Background Job Orchestration

### 2.1 Configuration
* **Module:** `apps/api/cisguard_api/worker.py`
* **App Instance:** `celery` (`Celery('cisguard')`)
* **Task Routing & Namespaces:**
  * `cisguard.run_scan`: Multi-target audit scan execution task.
  * `cisguard.foundation_ping`: Worker health probe.

### 2.2 Live Dispatch & Execution Test Evidence
A live subprocess worker (`celery -A cisguard_api.worker:celery worker --pool=solo --loglevel=warning`) was launched and tested:
1. **Task Dispatch:** Dispatched `cisguard.foundation_ping.delay()`. Task ID assigned: `1b301d6f-8519-427b-b4d8-3512f6273955`.
2. **Worker Processing:** Worker intercepted the message from Redis DB 0.
3. **Result Storage:** Output returned and persisted in Redis DB 1.
4. **Retrieval:** `AsyncResult.get(timeout=15)` returned:
   ```json
   {"status": "ready", "device_operations": "UNSUPPORTED"}
   ```
5. **Outcome:** Full end-to-end task round-trip verified.

### 2.3 Failure Isolation Guarantee
In `execute_scan_job`, audits iterate over multiple targets. If a target network connection fails or throws an exception, the worker catches the error, records `status="ERROR"` for that specific target in `cisguard.scan_targets`, and proceeds with the remaining targets. The master job transitions to `COMPLETED_WITH_ERRORS` without crashing the Celery process.

---

## 3. OpenBao Secrets Management & Device Credential Abstraction

### 3.1 Container & Instance Details
* **Container Name:** `cisguard-openbao`
* **Network Binding:** `http://127.0.0.1:8201` (Host) $\to$ `8200` (Container)
* **OpenBao Version:** 2.7.2
* **Storage Backend:** In-memory development mode (`-dev`).  
  > [!NOTE] OpenBao is currently running in local development mode. For production deployment, a persisted Raft / Consul storage backend must be mounted.
* **Authentication Method:** AppRole (`auth/approle`)
  * **Role Name:** `cisguard-worker`
  * **Policy Name:** `cisguard-worker`
  * **KV v2 Secret Engine Mount:** `secret`

### 3.2 Live Verification Test Evidence
* **Module Tested:** `apps/api/cisguard_api/bao.py` via `OpenBao` client.
1. **Configuration Loading:** `openbao_role_id` and `openbao_secret_id` loaded as Pydantic `SecretStr` instances. Plaintext values are never logged or exposed.
2. **AppRole Authentication:** Authenticated with OpenBao AppRole endpoint `/v1/auth/approle/login`. Received client token wrapped in `SecretStr`.
3. **Authorized Device Secret Read:**
   * Secret Path: `cisguard/devices/lab-router`
   * Retrieved Fields: `['username', 'password']`
   * Values Verified: `username == "demo"`, `password == "dummy-only"`
4. **Credential Masking in Memory:**
   * Verified: `"dummy-only" not in str(credentials)`
   * Verified: `"dummy-only" not in repr(credentials)`
   * Strings render as `**********`, preventing accidental leakage in log outputs or tracebacks.
5. **Non-Existent Secret Handling:**
   * Reading `cisguard/devices/nonexistent-device` correctly raised `KeyError("Secret not found at path ...")`.
6. **Access Restriction (Least Privilege):**
   * Attempting to list the root KV mount `/v1/secret/metadata` was denied with **HTTP 403 Forbidden** (`PermissionError`).
7. **Invalid Credential Rejection:**
   * Logging in with an invalid Secret ID was denied with **HTTP 400 Bad Request** (`PermissionError`).

---

## 4. Overall Infrastructure Health Matrix

| Component | Target URI | Test Method | Result | Production Readiness |
|---|---|---|---|---|
| **Redis DB 0** | `redis://127.0.0.1:6380/0` | Live Socket PING + Set/Get | **PASS** | Ready |
| **Redis DB 1** | `redis://127.0.0.1:6380/1` | Live Socket PING + Set/Get | **PASS** | Ready |
| **Celery Worker** | Background Worker Process | Real Task Dispatch & `.get()` | **PASS** | Ready |
| **OpenBao AppRole** | `http://127.0.0.1:8201` | AppRole Login & Token Issuance | **PASS** | Ready (dev mode) |
| **OpenBao KV Read** | `secret/data/cisguard/devices/*` | KV v2 Secret Read & Masking | **PASS** | Ready (dev mode) |
| **OpenBao Denials**| Root listing & invalid ID | HTTP 403 & 400 rejection | **PASS** | Ready |

