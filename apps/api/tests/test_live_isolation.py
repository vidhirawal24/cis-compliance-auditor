"""Explicitly opted-in Supabase checks; all synthetic fixtures roll back."""
import os
from uuid import uuid4
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from cisguard_api.database import engine


@pytest.mark.skipif(os.getenv('CISGUARD_LIVE_TESTS') != '1', reason='Explicit live DB opt-in required')
def test_E15_live_tenant_isolation():
    db = engine(migration=True)
    org_a, org_b, user_a, user_b = [str(uuid4()) for _ in range(4)]
    with db.connect() as c:
        tx = c.begin()
        try:
            for org,user in [(org_a,user_a),(org_b,user_b)]:
                c.execute(text('INSERT INTO cisguard.organizations(id,name) VALUES (:o,:n)'),{'o':org,'n':'Synthetic rollback fixture'})
                c.execute(text("INSERT INTO cisguard.organization_members(id,org_id,user_id,role) VALUES (:i,:o,:u,'auditor')"),{'i':str(uuid4()),'o':org,'u':user})
                c.execute(text('INSERT INTO cisguard.asset_groups(id,org_id,name) VALUES (:i,:o,:n)'),{'i':str(uuid4()),'o':org,'n':'Synthetic rollback group'})
            c.execute(text('GRANT INSERT ON cisguard.asset_groups TO cisguard_api'))
            c.execute(text('SET LOCAL ROLE cisguard_api'))
            c.execute(text("SELECT set_config('app.user_id',:u,true),set_config('app.org_id',:o,true)"),{'u':user_a,'o':org_a})
            assert c.execute(text('SELECT org_id::text FROM cisguard.asset_groups')).scalars().all() == [org_a]
            with pytest.raises(DBAPIError), c.begin_nested():
                c.execute(text('INSERT INTO cisguard.asset_groups(id,org_id,name) VALUES (:i,:o,:n)'),{'i':str(uuid4()),'o':org_b,'n':'Forbidden'})
            c.execute(text("SELECT set_config('app.org_id',:o,true)"),{'o':org_b})
            assert not c.execute(text('SELECT id FROM cisguard.asset_groups')).all()
            c.execute(text("SELECT set_config('app.user_id',:u,true)"),{'u':user_b})
            assert c.execute(text('SELECT org_id::text FROM cisguard.asset_groups')).scalars().all() == [org_b]
        finally:
            tx.rollback()
    db.dispose()
