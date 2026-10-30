"""E15-E19: real PostgreSQL policies/functions; all fixtures and grants roll back."""
import hashlib
import os
from uuid import uuid4
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from cisguard_api.database import engine


@pytest.mark.skipif(os.getenv('CISGUARD_LIVE_TESTS')!='1',reason='Explicit live database opt-in required')
def test_E15_E19_live_security_boundaries():
    db=engine(migration=True)
    org,other,owner,auditor,new_user,invite,ref=[str(uuid4()) for _ in range(7)]
    digest=hashlib.sha256(b'synthetic-invitation-token').hexdigest()
    approver,plan=str(uuid4()),str(uuid4())
    with db.connect() as c:
        tx=c.begin()
        def run(sql,**params):
            return c.execute(text(sql),params)
        def ctx(user,tenant=org,aal='aal2',email=''):
            run("SELECT set_config('app.user_id',:u,true),set_config('app.org_id',:o,true),set_config('app.aal',:a,true),set_config('app.email',:e,true)",u=user,o=tenant,a=aal,e=email)
        def denied(sql,**params):
            with pytest.raises(DBAPIError),c.begin_nested():
                run(sql,**params)
        try:
            for tenant in [org,other]:
                run('INSERT INTO cisguard.organizations(id,name) VALUES(:o,\'Synthetic security test\')',o=tenant)
            for user,role in [(owner,'owner'),(auditor,'auditor'),(approver,'approver')]:
                run('INSERT INTO cisguard.organization_members(id,org_id,user_id,role) VALUES(:i,:o,:u,:r)',i=str(uuid4()),o=org,u=user,r=role)
            run("INSERT INTO cisguard.remediation_plans(id,org_id,author_id,plan_sha256,outcome,violated_constraints) VALUES(:i,:o,:u,:h,'FEASIBLE','[]')",i=plan,o=org,u=owner,h='1'*64)
            run('SET LOCAL ROLE cisguard_api')
            ctx(owner)
            run("INSERT INTO cisguard.invitations(id,org_id,email,role,token_hash,invited_by,expires_at) VALUES(:i,:o,'new@example.test','auditor',:h,:u,now()+interval '1 hour')",i=invite,o=org,h=digest,u=owner)
            run('INSERT INTO cisguard.credential_references(id,org_id,label,vault_reference) VALUES(:i,:o,\'Synthetic\',:v)',i=ref,o=org,v=f'device-secrets/data/{org}/{ref}')
            # A low-assurance owner cannot create privileged references.
            ctx(owner,aal='aal1')
            denied('INSERT INTO cisguard.credential_references(id,org_id,label,vault_reference) VALUES(:i,:o,\'Denied\',\'pointer\')',i=str(uuid4()),o=org)
            ctx(auditor)
            assert not run('SELECT id FROM cisguard.credential_references WHERE org_id=:o',o=org).all()
            assert run("UPDATE cisguard.organization_members SET role='owner' WHERE org_id=:o AND user_id=:u",o=org,u=auditor).rowcount==0
            assert not run('SELECT id FROM cisguard.invitations').all()
            # Valid token alone cannot bypass verified-email or tenant binding.
            ctx(new_user,email='wrong@example.test')
            denied('SELECT cisguard.accept_invitation(:i,:h,:m)',i=invite,h=digest,m=str(uuid4()))
            ctx(new_user,tenant=other,email='new@example.test')
            denied('SELECT cisguard.accept_invitation(:i,:h,:m)',i=invite,h=digest,m=str(uuid4()))
            ctx(new_user,email='new@example.test')
            run('SELECT cisguard.accept_invitation(:i,:h,:m)',i=invite,h=digest,m=str(uuid4()))
            denied('SELECT cisguard.accept_invitation(:i,:h,:m)',i=invite,h=digest,m=str(uuid4()))
            # Audit INSERT requires actual actor; runtime cannot UPDATE or DELETE events.
            denied("INSERT INTO cisguard.audit_events(id,org_id,actor_id,request_id,event_type,resource_id,details) VALUES(:i,:o,:a,:r,'spoof',:i,'{}')",i=str(uuid4()),o=org,a=owner,r=str(uuid4()))
            denied('DELETE FROM cisguard.audit_events WHERE org_id=:o',o=org)
            ctx(approver)
            approval_sql="INSERT INTO cisguard.approvals(id,org_id,plan_id,plan_sha256,approver_id,plan_author_id,decision,reason,expires_at) VALUES(:i,:o,:p,:h,:a,:u,'APPROVED','Synthetic',now()+interval '1 hour')"
            denied(approval_sql,i=str(uuid4()),o=org,p=plan,h='1'*64,a=approver,u=auditor)
            denied(approval_sql,i=str(uuid4()),o=org,p=plan,h='1'*64,a=owner,u=owner)
            ctx(approver,aal='aal1')
            denied(approval_sql,i=str(uuid4()),o=org,p=plan,h='1'*64,a=approver,u=owner)
            ctx(approver)
            run(approval_sql,i=str(uuid4()),o=org,p=plan,h='1'*64,a=approver,u=owner)
            bucket=hashlib.sha256(uuid4().bytes).hexdigest()
            attempts=run('SELECT cisguard.consume_rate(:b) FROM generate_series(1,61)',b=bucket).scalars().all()
            assert attempts[:60]==[True]*60 and attempts[60] is False
            run("SELECT cisguard.log_denial(:r,'AUTH_DENIED')",r=str(uuid4()))
            denied('SELECT * FROM cisguard.access_denials')
            # Supabase authenticated browser role can read only its own active membership.
            run('RESET ROLE')
            browser=run("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated')").scalar()
            if browser:
                run('SET LOCAL ROLE authenticated')
                run("SELECT set_config('request.jwt.claim.sub',:u,true)",u=auditor)
                assert run('SELECT user_id::text FROM cisguard.organization_members').scalars().all()==[auditor]
                denied('SELECT * FROM cisguard.credential_references')
                denied("UPDATE cisguard.organization_members SET role='owner'")
        finally:
            tx.rollback()
    db.dispose()
