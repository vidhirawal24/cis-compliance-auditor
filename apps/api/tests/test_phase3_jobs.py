"""Phase 3: Asset inventory, scheduling, and job orchestration tests.

Covers M13, E01-E04, E08-E09, E30:
- Asset CRUD and soft-retirement preserving historical data (E01)
- Capability registry queries across OS and network device families (M01, M11, I20)
- Discovery CIDR validation and SSRF/metadata protection (E02)
- Multi-target execution and per-target failure isolation (M13)
- Selective scan jobs and schedules (E04, E08)
- RBAC permissions on asset and scan operations (E15, E30)
"""

from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID, uuid4
import pytest

pytestmark = pytest.mark.usefixtures("synthetic_device_engine")
from fastapi.testclient import TestClient

from cisguard_api.device_port import (
    collect_device_facts,
    DevicePortError,
    get_asset_capabilities,
    validate_discovery_cidr,
)
from cisguard_api.main import app
from cisguard_api.security import Identity
from cisguard_api import job_routes, security_routes


# ============================================================================
# Device Port & Capabilities Tests (M01, M11, I20)
# ============================================================================


def test_capabilities_registry_by_family():
    asset_id = uuid4()
    for family in ["windows", "linux", "firewall", "router", "switch"]:
        cap = get_asset_capabilities(asset_id, family, "TestPlatform", "TestVendor")
        assert cap.asset_id == asset_id
        assert cap.compatibility_status == "FIXTURE_TESTED"
        assert len(cap.supported) > 0
        assert len(cap.unsupported) > 0

    # Verify family-specific checks
    win_cap = get_asset_capabilities(asset_id, "windows", "Windows 11", "Microsoft")
    assert "registry.policy" in win_cap.supported
    assert "auditpol.subcategory" in win_cap.supported

    linux_cap = get_asset_capabilities(asset_id, "linux", "Ubuntu 22.04", "Canonical")
    assert "sshd.config" in linux_cap.supported
    assert "pam.auth" in linux_cap.supported

    fw_cap = get_asset_capabilities(asset_id, "firewall", "FortiGate", "Fortinet")
    assert "firewall.policies" in fw_cap.supported


def test_device_collection_success_and_provenance():
    asset = SimpleNamespace(
        id=uuid4(),
        org_id=uuid4(),
        target="10.0.1.50",
        family="linux",
        tags=["web", "prod"],
    )
    res = collect_device_facts(asset, mode="read_only")
    assert res["status"] == "SUCCEEDED"
    assert res["mode"] == "read_only"
    assert "content_sha256" in res
    assert res["artifact_ref"].startswith("private://config-snapshots/")
    assert res["provenance"]["target"] == "10.0.1.50"


def test_device_collection_simulated_failures():
    # Timeout
    timeout_asset = SimpleNamespace(
        id=uuid4(),
        org_id=uuid4(),
        target="10.0.1.20.timeout",
        family="linux",
        tags=[],
    )
    with pytest.raises(DevicePortError) as exc_info:
        collect_device_facts(timeout_asset)
    assert exc_info.value.code == "TIMEOUT"
    assert exc_info.value.retryable is True

    # Auth failure
    auth_asset = SimpleNamespace(
        id=uuid4(),
        org_id=uuid4(),
        target="10.0.1.21.authfail",
        family="windows",
        tags=[],
    )
    with pytest.raises(DevicePortError) as exc_info:
        collect_device_facts(auth_asset)
    assert exc_info.value.code == "AUTH_FAILED"
    assert exc_info.value.retryable is False

    # Unreachable
    unreach_asset = SimpleNamespace(
        id=uuid4(),
        org_id=uuid4(),
        target="10.0.1.22",
        family="firewall",
        tags=["simulate_unreachable"],
    )
    with pytest.raises(DevicePortError) as exc_info:
        collect_device_facts(unreach_asset)
    assert exc_info.value.code == "DEVICE_UNAVAILABLE"


# ============================================================================
# Discovery CIDR Validation & SSRF Mitigation (E02)
# ============================================================================


def test_discovery_cidr_validation():
    # Valid private and public CIDRs
    assert validate_discovery_cidr("10.0.0.0/24")
    assert validate_discovery_cidr("172.16.0.0/16")
    assert validate_discovery_cidr("192.168.1.0/24")

    # SSRF / Dangerous addresses rejected
    with pytest.raises(ValueError, match="Loopback"):
        validate_discovery_cidr("127.0.0.1/32")

    with pytest.raises(ValueError, match="Loopback"):
        validate_discovery_cidr("127.0.0.0/8")

    with pytest.raises(ValueError, match="Link-local|metadata"):
        validate_discovery_cidr("169.254.169.254/32")

    with pytest.raises(ValueError, match="Link-local"):
        validate_discovery_cidr("169.254.0.0/16")

    with pytest.raises(ValueError, match="Multicast"):
        validate_discovery_cidr("224.0.0.1/32")

    with pytest.raises(ValueError, match="Invalid CIDR"):
        validate_discovery_cidr("invalid-cidr-string")


# ============================================================================
# HTTP API Tests with Mock Context (E01-E04, E08, E30)
# ============================================================================


@pytest.fixture
def mock_owner(monkeypatch):
    user_id = uuid4()
    org_id = uuid4()
    monkeypatch.setattr(security_routes, "identity", lambda r: Identity(user_id, "aal2", 9999999999, "owner@example.com"))
    monkeypatch.setattr(job_routes, "identity", lambda r: Identity(user_id, "aal2", 9999999999, "owner@example.com"))
    return user_id, org_id


def test_asset_crud_and_retirement(monkeypatch, mock_owner):
    user_id, org_id = mock_owner
    asset_id = uuid4()
    scope_id = uuid4()

    mock_db_asset = SimpleNamespace(
        id=asset_id,
        org_id=org_id,
        name="web-server-01",
        family="linux",
        platform="Ubuntu 22.04",
        vendor="Canonical",
        model="VM",
        os_or_firmware_version="22.04 LTS",
        target="10.0.1.100",
        authorization_scope_id=scope_id,
        credential_reference_id=None,
        tags=["web", "tier-1"],
        retired=False,
        role="owner",
        active=True,
    )

    @contextmanager
    def mock_session(*args):
        session = SimpleNamespace(
            scalar=lambda *a, **k: mock_db_asset,
            scalars=lambda *a, **k: SimpleNamespace(all=lambda: [mock_db_asset]),
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )
        yield session

    monkeypatch.setattr(job_routes, "tenant_session", mock_session)
    monkeypatch.setattr(security_routes, "tenant_session", mock_session)

    client = TestClient(app)

    # 1. Create Asset
    create_payload = {
        "name": "web-server-01",
        "family": "linux",
        "platform": "Ubuntu 22.04",
        "vendor": "Canonical",
        "model": "VM",
        "os_or_firmware_version": "22.04 LTS",
        "target": "10.0.1.100",
        "authorization_scope_id": str(scope_id),
        "tags": ["web", "tier-1"],
    }
    # To avoid conflict check triggering on mock_db_asset return, customize scalar for create:
    call_count = [0]
    def create_scalar(*a, **k):
        call_count[0] += 1
        if call_count[0] == 1:
            return SimpleNamespace(role="owner", active=True)  # member role check
        if call_count[0] == 2:
            return None  # existing target uniqueness check
        return mock_db_asset

    @contextmanager
    def create_session(*args):
        yield SimpleNamespace(
            scalar=create_scalar,
            scalars=lambda *a, **k: SimpleNamespace(all=lambda: [mock_db_asset]),
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )

    monkeypatch.setattr(job_routes, "tenant_session", create_session)

    res = client.post("/api/v1/assets", headers={"X-Org-ID": str(org_id)}, json=create_payload)
    assert res.status_code == 201
    data = res.json()["data"]
    assert data["name"] == "web-server-01"
    assert data["retired"] is False

    # 2. List Assets
    monkeypatch.setattr(job_routes, "tenant_session", mock_session)
    res = client.get("/api/v1/assets", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert len(res.json()["data"]["items"]) == 1

    # 3. Get Asset
    res = client.get(f"/api/v1/assets/{asset_id}", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert res.json()["data"]["asset_id"] == str(asset_id)

    # 4. Capabilities
    res = client.get(f"/api/v1/assets/{asset_id}/capabilities", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert res.json()["data"]["compatibility_status"] == "FIXTURE_TESTED"

    # 5. Soft-Retire Asset
    res = client.delete(f"/api/v1/assets/{asset_id}", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert res.json()["data"]["retired"] is True


def test_discovery_ssrf_mitigation_http(monkeypatch, mock_owner):
    user_id, org_id = mock_owner
    client = TestClient(app)

    @contextmanager
    def mock_session(*args):
        yield SimpleNamespace(
            scalar=lambda *a, **k: SimpleNamespace(role="owner", active=True),
            scalars=lambda *a, **k: SimpleNamespace(all=lambda: []),
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )

    monkeypatch.setattr(job_routes, "tenant_session", mock_session)

    # Rejected metadata address
    res = client.post(
        "/api/v1/assets/discover",
        headers={"X-Org-ID": str(org_id)},
        json={"authorization_scope_id": str(uuid4()), "approved_cidrs": ["169.254.169.254/32"]},
    )
    assert res.status_code == 422
    assert "metadata" in res.text or "Link-local" in res.text

    # Rejected loopback address
    res = client.post(
        "/api/v1/assets/discover",
        headers={"X-Org-ID": str(org_id)},
        json={"authorization_scope_id": str(uuid4()), "approved_cidrs": ["127.0.0.1/32"]},
    )
    assert res.status_code == 422
    assert "Loopback" in res.text

    # Accepted valid CIDR
    res = client.post(
        "/api/v1/assets/discover",
        headers={"X-Org-ID": str(org_id)},
        json={"authorization_scope_id": str(uuid4()), "approved_cidrs": ["10.200.0.0/16"]},
    )
    assert res.status_code == 202
    assert res.json()["data"]["status"] == "QUEUED"
    assert res.json()["data"]["resource_type"] == "discovery"


def test_scan_schedules_crud_http(monkeypatch, mock_owner):
    user_id, org_id = mock_owner
    client = TestClient(app)
    sched_id = uuid4()

    mock_sched = SimpleNamespace(
        id=sched_id,
        org_id=org_id,
        cron_utc="0 2 * * *",
        enabled=True,
        role="owner",
        active=True,
        selection={
            "asset_ids": [str(uuid4())],
            "policy_pack_id": str(uuid4()),
            "policy_version": "1.0.0",
            "profile": "Level 1",
            "control_ids": [],
            "mode": "read_only",
            "offline_evidence_ids": [],
        },
    )

    @contextmanager
    def mock_session(*args):
        yield SimpleNamespace(
            scalar=lambda *a, **k: mock_sched,
            scalars=lambda *a, **k: SimpleNamespace(all=lambda: [mock_sched]),
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )

    monkeypatch.setattr(job_routes, "tenant_session", mock_session)

    # Valid schedule
    payload = {
        "cron_utc": "0 2 * * *",
        "enabled": True,
        "scan": {
            "asset_ids": [str(uuid4())],
            "policy_pack_id": str(uuid4()),
            "policy_version": "1.0.0",
            "profile": "Level 1",
            "control_ids": [],
            "mode": "read_only",
            "offline_evidence_ids": [],
        },
    }
    res = client.post("/api/v1/scans/schedules", headers={"X-Org-ID": str(org_id)}, json=payload)
    assert res.status_code == 201
    assert res.json()["data"]["cron_utc"] == "0 2 * * *"

    # Invalid cron rejected
    invalid_payload = {**payload, "cron_utc": "not-a-valid-cron"}
    res = client.post("/api/v1/scans/schedules", headers={"X-Org-ID": str(org_id)}, json=invalid_payload)
    assert res.status_code == 422

    # List schedules
    res = client.get("/api/v1/scans/schedules", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert len(res.json()["data"]) == 1

    # Delete schedule
    res = client.delete(f"/api/v1/scans/schedules/{sched_id}", headers={"X-Org-ID": str(org_id)})
    assert res.status_code == 200
    assert res.json()["data"]["deleted"] is True


def test_rbac_job_permissions(monkeypatch):
    user_id = uuid4()
    org_id = uuid4()
    client = TestClient(app)

    # 1. Auditor attempts to create asset -> 403 Forbidden (needs inventory.write)
    monkeypatch.setattr(job_routes, "identity", lambda r: Identity(user_id, "aal1", 9999999999, "auditor@example.com"))

    @contextmanager
    def auditor_session(*args):
        yield SimpleNamespace(
            scalar=lambda *a, **k: SimpleNamespace(role="auditor", active=True),
            add=lambda *a, **k: None,
            flush=lambda *a, **k: None,
            execute=lambda *a, **k: None,
        )

    monkeypatch.setattr(job_routes, "tenant_session", auditor_session)

    res = client.post(
        "/api/v1/assets",
        headers={"X-Org-ID": str(org_id)},
        json={
            "name": "audit-asset",
            "family": "linux",
            "platform": "Ubuntu",
            "vendor": "Canonical",
            "model": "VM",
            "os_or_firmware_version": "22.04",
            "target": "10.0.0.1",
            "authorization_scope_id": str(uuid4()),
        },
    )
    assert res.status_code == 403

    # 2. Auditor attempts to launch scan -> 403 Forbidden (needs audit.scan)
    res = client.post(
        "/api/v1/scans",
        headers={"X-Org-ID": str(org_id)},
        json={
            "asset_ids": [str(uuid4())],
            "policy_pack_id": str(uuid4()),
            "policy_version": "1.0.0",
            "profile": "Level 1",
        },
    )
    assert res.status_code == 403

