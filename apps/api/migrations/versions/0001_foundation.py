"""Tenant foundation and restricted runtime role."""
from alembic import op
from pathlib import Path
import importlib.util
_spec = importlib.util.spec_from_file_location("schema_v0001", Path(__file__).parents[1] / "schema_v0001.py")
_schema = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_schema)
Base = _schema.Base

revision = '0001_foundation'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute('CREATE SCHEMA cisguard')
    op.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cisguard_api') THEN CREATE ROLE cisguard_api NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$")
    op.execute('GRANT cisguard_api TO CURRENT_USER')
    Base.metadata.create_all(op.get_bind())
    op.execute('REVOKE ALL ON SCHEMA cisguard FROM PUBLIC')
    op.execute('GRANT USAGE ON SCHEMA cisguard TO cisguard_api')
    op.execute('GRANT SELECT ON ALL TABLES IN SCHEMA cisguard TO cisguard_api')
    op.execute("""CREATE FUNCTION cisguard.is_member(tenant uuid) RETURNS boolean
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, cisguard AS $$
      SELECT tenant = nullif(current_setting('app.org_id',true),'')::uuid AND EXISTS
      (SELECT 1 FROM cisguard.organization_members WHERE org_id=tenant AND active
       AND user_id=nullif(current_setting('app.user_id',true),'')::uuid) $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.is_member(uuid) FROM PUBLIC')
    op.execute('GRANT EXECUTE ON FUNCTION cisguard.is_member(uuid) TO cisguard_api')
    for table in Base.metadata.sorted_tables:
        column = 'id' if table.name == 'organizations' else 'org_id'
        op.execute(f'ALTER TABLE cisguard.{table.name} ENABLE ROW LEVEL SECURITY')
        op.execute(f'CREATE POLICY tenant_isolation ON cisguard.{table.name} TO cisguard_api USING (cisguard.is_member({column})) WITH CHECK (cisguard.is_member({column}))')


def downgrade():
    raise RuntimeError('Destructive downgrade disabled; restore a reviewed backup or forward migration')
