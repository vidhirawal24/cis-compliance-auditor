from fastapi.testclient import TestClient
from cisguard_api.main import app
from cisguard_api.db_models import Base


def test_E15_missing_auth_rejected():
    with TestClient(app) as client:
        response = client.get('/api/v1/auth/session',headers={'X-Org-ID':'00000000-0000-0000-0000-000000000001'})
        assert response.status_code == 401
        assert response.json()['code'] == 'UNAUTHENTICATED'


def test_E30_health():
    assert TestClient(app).get('/health/live').json()['status'] == 'ok'


def test_E15_tenant_model_constraints():
    assert len(Base.metadata.tables) >= 30
    for table in Base.metadata.tables.values():
        if table.name == 'organizations':
            continue
        assert not table.c.org_id.nullable
        assert 'retention_until' in table.c
        for fk in table.foreign_key_constraints:
            if any(e.target_fullname.endswith('organizations.id') for e in fk.elements):
                continue
            assert 'org_id' in fk.column_keys
