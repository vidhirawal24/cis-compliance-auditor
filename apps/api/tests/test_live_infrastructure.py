"""Live integration tests for Docker infrastructure: Redis, Celery, and OpenBao.

Requires $env:CISGUARD_LIVE_TESTS='1' and running Docker containers:
- Redis on 127.0.0.1:6380 (broker DB 0, backend DB 1)
- OpenBao on 127.0.0.1:8201 with AppRole credentials
"""

import os
import subprocess
import sys
import time
import pytest
import redis
from pydantic import SecretStr

from cisguard_api.bao import OpenBao
from cisguard_api.settings import get_settings
from cisguard_api.worker import celery, foundation_ping


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB/infra opt-in required")
def test_live_redis_broker_and_backend():
    settings = get_settings()
    broker_url = (settings.celery_broker_url or settings.redis_url).get_secret_value()
    backend_url = settings.celery_result_backend.get_secret_value()

    # DB 0 broker
    r0 = redis.Redis.from_url(broker_url, socket_timeout=3)
    assert r0.ping() is True
    r0.set("pytest:live:probe0", "val0", ex=10)
    assert r0.get("pytest:live:probe0") == b"val0"

    # DB 1 result backend
    r1 = redis.Redis.from_url(backend_url, socket_timeout=3)
    assert r1.ping() is True
    r1.set("pytest:live:probe1", "val1", ex=10)
    assert r1.get("pytest:live:probe1") == b"val1"


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB/infra opt-in required")
def test_live_celery_worker_dispatch_and_execution():
    settings = get_settings()
    assert "cisguard.foundation_ping" in celery.tasks
    assert "cisguard.run_scan" in celery.tasks

    # Verify direct task invocation
    direct_res = foundation_ping()
    assert direct_res["status"] == "ready"

    # Start transient Celery worker subprocess with solo pool
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
        time.sleep(4.0)
        async_res = foundation_ping.delay()
        result = async_res.get(timeout=15)
        assert result["status"] == "ready"
        assert result["device_operations"] == "UNSUPPORTED"
    finally:
        worker_proc.terminate()
        worker_proc.wait(timeout=5)


@pytest.mark.skipif(os.getenv("CISGUARD_LIVE_TESTS") != "1", reason="Explicit live DB/infra opt-in required")
def test_live_openbao_approle_and_secret_retrieval():
    settings = get_settings()
    bao = OpenBao(settings.openbao_addr)

    # 1. AppRole Authentication
    role_id = settings.openbao_role_id
    secret_id = settings.openbao_secret_id
    token = bao.login_approle(role_id, secret_id)
    assert isinstance(token, SecretStr)
    assert len(token.get_secret_value()) > 0

    # 2. Read KV v2 Device Secret
    creds = bao.read_kv_secret("cisguard/devices/lab-router", token, kv_mount=settings.openbao_kv_mount)
    assert "username" in creds
    assert "password" in creds
    assert creds["username"].get_secret_value() == "demo"
    assert creds["password"].get_secret_value() == "dummy-only"

    # Verify secret masking
    assert "dummy-only" not in str(creds)
    assert "dummy-only" not in repr(creds)

    # 3. Denied Root Listing
    with pytest.raises(PermissionError, match="Permission denied"):
        bao.list_kv_root(token, kv_mount=settings.openbao_kv_mount)

    # 4. Missing Secret 404
    with pytest.raises(KeyError):
        bao.read_kv_secret("cisguard/devices/missing-device-target", token, kv_mount=settings.openbao_kv_mount)

    # 5. Invalid Secret ID 400/401
    with pytest.raises(PermissionError):
        bao.login_approle(role_id, SecretStr("bad-secret-id-00000000"))

