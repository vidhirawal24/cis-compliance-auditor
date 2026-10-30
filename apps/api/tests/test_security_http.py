from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4
from fastapi.testclient import TestClient
from cisguard_api.main import app
from cisguard_api.security import Identity
from cisguard_api import security_routes as routes


def test_E15_path_tenant_mismatch_denied():
    result=TestClient(app).get(f'/api/v1/organizations/{uuid4()}/members',headers={'X-Org-ID':str(uuid4())})
    assert result.status_code==403


def test_E15_membership_required_even_with_verified_jwt(monkeypatch):
    monkeypatch.setattr(routes,'identity',lambda request:Identity(uuid4(),'aal2',9999999999,None))
    @contextmanager
    def session(*args):
        yield SimpleNamespace(execute=lambda *a,**k:None,scalar=lambda *a,**k:None)
    monkeypatch.setattr(routes,'tenant_session',session)
    result=TestClient(app).get('/api/v1/me',headers={'X-Org-ID':str(uuid4())})
    assert result.status_code==403


def test_E15_auditor_cannot_administer_members(monkeypatch):
    monkeypatch.setattr(routes,'identity',lambda request:Identity(uuid4(),'aal2',9999999999,None))
    @contextmanager
    def session(*args):
        yield SimpleNamespace(execute=lambda *a,**k:None,scalar=lambda *a,**k:SimpleNamespace(role='auditor'))
    monkeypatch.setattr(routes,'tenant_session',session)
    org=str(uuid4())
    result=TestClient(app).get(f'/api/v1/organizations/{org}/members',headers={'X-Org-ID':org})
    assert result.status_code==403


def test_E17_body_cannot_contain_secret():
    result=TestClient(app).post('/api/v1/credential-references',headers={'X-Org-ID':str(uuid4())},json={'label':'device','password':'synthetic'})
    assert result.status_code==422
    assert 'synthetic' not in result.text


def test_E16_mfa_status_available_before_step_up(monkeypatch):
    monkeypatch.setattr(routes,'identity',lambda request:Identity(uuid4(),'aal1',9999999999,None,True))
    @contextmanager
    def session(*args):
        yield SimpleNamespace(scalar=lambda *a,**k:SimpleNamespace(role='owner'))
    monkeypatch.setattr(routes,'tenant_session',session)
    result=TestClient(app).get('/api/v1/me/mfa',headers={'X-Org-ID':str(uuid4())})
    assert result.status_code==200
    assert result.json()['data']=={'enrolled':True,'aal':'aal1','required':True}
