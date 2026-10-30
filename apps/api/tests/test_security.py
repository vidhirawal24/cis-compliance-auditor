import json
import time
from uuid import uuid4
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from pydantic import SecretStr
from cisguard_api.settings import Settings
from cisguard_api.security import TokenVerifier, require_permission, require_independent_approver, MATRIX
from cisguard_api.bao import OpenBao, WorkerGrant
from cisguard_api.security_routes import InviteBody, ReferenceBody


@pytest.fixture
def auth():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid='first',alg='RS256',use='sig')
    user=uuid4()
    settings=Settings(_env_file=None,supabase_url='https://test.supabase.co')
    state={'keys':[public],'user':str(user),'status':200}
    def transport(request):
        if request.url.path.endswith('jwks.json'):
            return httpx.Response(200,json={'keys':state['keys']})
        return httpx.Response(state['status'],json={'id':state['user'],'email':'a@example.test','email_confirmed_at':'2026-01-01'})
    verifier=TokenVerifier(settings,httpx.MockTransport(transport))
    claims={'sub':str(user),'iss':settings.supabase_url+'/auth/v1','aud':'authenticated',
            'iat':int(time.time()),'exp':int(time.time())+300,'aal':'aal2','role':'authenticated'}
    return key,claims,verifier,state


def token(key,claims,kid='first'):
    return jwt.encode(claims,key,algorithm='RS256',headers={'kid':kid})


def test_E15_valid_signature(auth):
    key,claims,verifier,_=auth
    assert str(verifier.verify(token(key,claims)).user_id)==claims['sub']


@pytest.mark.parametrize('change',[{'iss':'https://evil.test'},{'aud':'anon'},{'exp':1},{'iat':9999999999},{'nbf':9999999999},{'role':'service_role'},{'aal':'aal3'},{'sub':'bad'}])
def test_E15_invalid_claims(auth,change):
    key,claims,verifier,_=auth
    with pytest.raises(HTTPException): verifier.verify(token(key,{**claims,**change}))


def test_E15_tampered_signature(auth):
    _,claims,verifier,_=auth
    wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    with pytest.raises(HTTPException): verifier.verify(token(wrong,claims))


def test_E15_rotation_removes_old_key(auth):
    key,claims,verifier,state=auth
    verifier.verify(token(key,claims))
    new=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(new.public_key())); public.update(kid='second',alg='RS256')
    state['keys']=[public]; verifier.loaded_at=0
    assert verifier.verify(token(new,claims,'second'))
    with pytest.raises(HTTPException): verifier.verify(token(key,claims))


def test_E15_unknown_kid_and_revocation(auth):
    key,claims,verifier,state=auth
    with pytest.raises(HTTPException): verifier.verify(token(key,claims,'missing'))
    state['status']=401
    with pytest.raises(HTTPException): verifier.verify(token(key,claims))


@pytest.mark.parametrize('role',list(MATRIX['roles']))
def test_E15_seed_roles_deny_unlisted_permission(role):
    with pytest.raises(HTTPException): require_permission(role,'invented.permission','aal2')


@pytest.mark.parametrize('role',['owner','security_admin','operator','approver'])
def test_E16_privileged_mfa(role):
    with pytest.raises(HTTPException): require_permission(role,'session.read','aal1')


def test_E15_no_owner_approval_superuser():
    with pytest.raises(HTTPException): require_permission('owner','change.approve','aal2')


def test_E18_independent_approver():
    a,b,c=uuid4(),uuid4(),uuid4()
    require_independent_approver(a,b,c)
    for author,operator in [(a,c),(b,a)]:
        with pytest.raises(HTTPException): require_independent_approver(a,author,operator)


def test_E17_bao_exact_scope_and_redaction():
    org,ref=uuid4(),uuid4()
    grant=WorkerGrant(org,ref,SecretStr('test-only-worker-token'))
    def response(request):
        assert request.url.path==f'/v1/device-secrets/data/{org}/{ref}'
        return httpx.Response(200,json={'data':{'data':{'password':'synthetic-only'}}})
    bao=OpenBao('https://bao.example.test',httpx.MockTransport(response))
    value=bao.read(grant,org,ref)
    assert 'synthetic-only' not in repr(value)
    with pytest.raises(PermissionError): bao.read(grant,uuid4(),ref)
    with pytest.raises(PermissionError): bao.read(grant,org,uuid4())
    with pytest.raises(ValueError): OpenBao('http://bao.example.test')


def test_E17_browser_cannot_submit_device_secret():
    with pytest.raises(ValueError): ReferenceBody(label='device',password='synthetic')
    with pytest.raises(ValueError): ReferenceBody(label='device',vault_reference='../escape')


def test_E15_invite_normalized_and_role_allowlisted():
    assert InviteBody(email=' A@Example.test ',role='auditor').email=='a@example.test'
    with pytest.raises(ValueError): InviteBody(email='a@example.test',role='superuser')


def test_E15_cursor_tenant_and_integrity():
    from cisguard_api.pagination import encode_cursor,decode_cursor
    org,last=uuid4(),uuid4()
    value=encode_cursor(org,last,'synthetic-cursor-key')
    assert decode_cursor(value,org,'synthetic-cursor-key')==last
    for tenant,key in [(uuid4(),'synthetic-cursor-key'),(org,'wrong-key')]:
        with pytest.raises(HTTPException): decode_cursor(value,tenant,key)


def test_E15_es256_signature():
    from cryptography.hazmat.primitives.asymmetric import ec
    key=ec.generate_private_key(ec.SECP256R1())
    public=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    public.update(kid='ec',alg='ES256')
    user=str(uuid4())
    settings=Settings(_env_file=None,supabase_url='https://test.supabase.co')
    def response(request):
        return httpx.Response(200,json={'keys':[public]} if request.url.path.endswith('jwks.json') else {'id':user})
    claims={'sub':user,'iss':settings.supabase_url+'/auth/v1','aud':'authenticated','role':'authenticated','iat':int(time.time()),'exp':int(time.time())+300}
    value=jwt.encode(claims,key,algorithm='ES256',headers={'kid':'ec'})
    assert str(TokenVerifier(settings,httpx.MockTransport(response)).verify(value).user_id)==user
