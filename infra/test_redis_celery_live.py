import subprocess
import sys
import time
import redis
from cisguard_api.settings import get_settings
from cisguard_api.worker import celery, foundation_ping

s = get_settings()
broker_url = (s.celery_broker_url or s.redis_url).get_secret_value()
backend_url = s.celery_result_backend.get_secret_value()

print("=== REDIS & CELERY LIVE INTEGRATION AUDIT ===")

# 1. Redis DB 0 (Broker)
print(f"Connecting to Redis Broker at {broker_url}...")
r0 = redis.Redis.from_url(broker_url, socket_timeout=5)
assert r0.ping() is True, "Redis DB 0 PING failed"
r0.set("audit:probe:0", "ok_broker", ex=30)
val0 = r0.get("audit:probe:0")
assert val0 == b"ok_broker", f"Unexpected value from DB 0: {val0}"
print("  [PASS] Redis DB 0 connected, ping OK, set/get OK")

# 2. Redis DB 1 (Result Backend)
print(f"Connecting to Redis Backend at {backend_url}...")
r1 = redis.Redis.from_url(backend_url, socket_timeout=5)
assert r1.ping() is True, "Redis DB 1 PING failed"
r1.set("audit:probe:1", "ok_backend", ex=30)
val1 = r1.get("audit:probe:1")
assert val1 == b"ok_backend", f"Unexpected value from DB 1: {val1}"
print("  [PASS] Redis DB 1 connected, ping OK, set/get OK")

# 3. Celery App & Task Registration
print("Checking Celery configuration...")
registered_tasks = list(celery.tasks.keys())
print("  Registered tasks:", [t for t in registered_tasks if not t.startswith("celery.")])
assert "cisguard.foundation_ping" in registered_tasks
assert "cisguard.run_scan" in registered_tasks
print("  [PASS] Tasks registered successfully in Celery")

# 4. Direct Task Execution
print("Executing foundation_ping directly...")
res_direct = foundation_ping()
print("  Direct execution result:", res_direct)
assert res_direct["status"] == "ready"
assert res_direct["device_operations"] == "UNSUPPORTED"
print("  [PASS] Direct task execution passed")

# 5. Celery Worker Subprocess Dispatch and Result Backend Retrieval
print("Starting real Celery worker subprocess on Windows with solo pool...")
cmd = [
    sys.executable,
    "-m",
    "celery",
    "-A",
    "cisguard_api.worker",
    "worker",
    "-P",
    "solo",
    "-l",
    "warning",
]
worker_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

try:
    # Allow worker 3 seconds to connect to Redis
    time.sleep(3)
    print("Dispatching task via Celery delay()...")
    async_res = foundation_ping.delay()
    print(f"  Task dispatched with ID: {async_res.id}")
    
    print("Retrieving result from Redis DB 1 via async_res.get()...")
    result = async_res.get(timeout=10)
    print(f"  Retrieved result: {result}")
    assert result["status"] == "ready"
    assert result["device_operations"] == "UNSUPPORTED"
    print("  [PASS] Async dispatch, worker processing, and Redis DB 1 result retrieval verified!")
finally:
    worker_proc.terminate()
    worker_proc.wait(timeout=5)

print("=== REDIS & CELERY AUDIT COMPLETE: ALL PASS ===")
