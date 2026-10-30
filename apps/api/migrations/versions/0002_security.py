"""Membership administration, invitations, audit and distributed rate limits."""
from alembic import op
revision = '0002_security'
down_revision = '0001_foundation'
branch_labels = depends_on = None


def upgrade():
    op.execute("""CREATE TABLE cisguard.invitations (
      id uuid PRIMARY KEY, org_id uuid NOT NULL REFERENCES cisguard.organizations(id),
      email text NOT NULL, role text NOT NULL CHECK(role IN ('owner','security_admin','auditor','operator','approver','executive')),
      token_hash char(64) NOT NULL UNIQUE, invited_by uuid NOT NULL, expires_at timestamptz NOT NULL,
      accepted_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      retention_until timestamptz, legal_hold boolean NOT NULL DEFAULT false, UNIQUE(org_id,id))""")
    op.execute('CREATE INDEX ix_invitations_tenant ON cisguard.invitations(org_id,created_at)')
    op.execute('ALTER TABLE cisguard.invitations ENABLE ROW LEVEL SECURITY')
    op.execute("""CREATE FUNCTION cisguard.is_owner(tenant uuid) RETURNS boolean LANGUAGE sql STABLE
      SECURITY DEFINER SET search_path=pg_catalog,cisguard AS $$
      SELECT cisguard.is_member(tenant) AND current_setting('app.aal',true)='aal2' AND EXISTS
      (SELECT 1 FROM cisguard.organization_members WHERE org_id=tenant AND active AND role='owner'
       AND user_id=nullif(current_setting('app.user_id',true),'')::uuid) $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.is_owner(uuid) FROM PUBLIC')
    op.execute('GRANT EXECUTE ON FUNCTION cisguard.is_owner(uuid) TO cisguard_api')
    op.execute('CREATE POLICY invitation_owner ON cisguard.invitations TO cisguard_api USING (cisguard.is_owner(org_id)) WITH CHECK (cisguard.is_owner(org_id))')
    op.execute('GRANT SELECT,INSERT ON cisguard.invitations TO cisguard_api')
    # A restrictive policy intersects the original tenant policy; policies otherwise OR together.
    op.execute("""CREATE POLICY member_owner_update ON cisguard.organization_members AS RESTRICTIVE FOR UPDATE TO cisguard_api
      USING (cisguard.is_owner(org_id) AND user_id<>nullif(current_setting('app.user_id',true),'')::uuid)
      WITH CHECK (cisguard.is_owner(org_id) AND user_id<>nullif(current_setting('app.user_id',true),'')::uuid)""")
    op.execute('GRANT UPDATE(role,active,updated_at) ON cisguard.organization_members TO cisguard_api')
    op.execute("""CREATE POLICY credential_owner ON cisguard.credential_references AS RESTRICTIVE TO cisguard_api
      USING (cisguard.is_owner(org_id)) WITH CHECK (cisguard.is_owner(org_id))""")
    op.execute('GRANT INSERT ON cisguard.credential_references TO cisguard_api')
    op.execute('GRANT INSERT ON cisguard.audit_events TO cisguard_api')
    op.execute("""CREATE POLICY audit_actor ON cisguard.audit_events AS RESTRICTIVE FOR INSERT TO cisguard_api
      WITH CHECK(actor_id=nullif(current_setting('app.user_id',true),'')::uuid)""")
    op.execute("""CREATE FUNCTION cisguard.accept_invitation(invite uuid, digest text, member_id uuid) RETURNS uuid
      LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cisguard AS $$
      DECLARE i cisguard.invitations; u uuid;
      BEGIN
        u := nullif(current_setting('app.user_id',true),'')::uuid;
        SELECT * INTO i FROM cisguard.invitations WHERE id=invite AND token_hash=digest
          AND org_id=nullif(current_setting('app.org_id',true),'')::uuid FOR UPDATE;
        IF u IS NULL OR i.id IS NULL OR i.accepted_at IS NOT NULL OR i.expires_at<=now()
          OR i.email IS DISTINCT FROM nullif(current_setting('app.email',true),'')
          OR (i.role IN ('owner','security_admin','operator','approver') AND current_setting('app.aal',true) IS DISTINCT FROM 'aal2')
          THEN RAISE EXCEPTION 'Invitation unavailable' USING ERRCODE='42501'; END IF;
        INSERT INTO cisguard.organization_members(id,org_id,user_id,role) VALUES(member_id,i.org_id,u,i.role);
        UPDATE cisguard.invitations SET accepted_at=now(),updated_at=now() WHERE id=i.id;
        RETURN i.org_id;
      END $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.accept_invitation(uuid,text,uuid) FROM PUBLIC')
    op.execute('GRANT EXECUTE ON FUNCTION cisguard.accept_invitation(uuid,text,uuid) TO cisguard_api')
    op.execute("""CREATE TABLE cisguard.access_denials (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, request_id uuid NOT NULL,
      reason text NOT NULL CHECK(reason IN ('AUTH_DENIED','PERMISSION_DENIED','RATE_LIMITED','DEPENDENCY_UNAVAILABLE')),
      occurred_at timestamptz NOT NULL DEFAULT now())""")
    op.execute('ALTER TABLE cisguard.access_denials ENABLE ROW LEVEL SECURITY')
    op.execute("""CREATE FUNCTION cisguard.log_denial(req uuid, why text) RETURNS void LANGUAGE sql SECURITY DEFINER
      SET search_path=pg_catalog,cisguard AS $$ INSERT INTO cisguard.access_denials(request_id,reason) VALUES(req,why) $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.log_denial(uuid,text) FROM PUBLIC')
    op.execute('GRANT EXECUTE ON FUNCTION cisguard.log_denial(uuid,text) TO cisguard_api')
    op.execute("""CREATE TABLE cisguard.rate_windows (
      bucket char(64) NOT NULL, window_start bigint NOT NULL, hits integer NOT NULL,
      PRIMARY KEY(bucket,window_start))""")
    op.execute('ALTER TABLE cisguard.rate_windows ENABLE ROW LEVEL SECURITY')
    op.execute("""CREATE FUNCTION cisguard.consume_rate(bucket_hash text) RETURNS boolean LANGUAGE plpgsql
      SECURITY DEFINER SET search_path=pg_catalog,cisguard AS $$ DECLARE n integer; w bigint;
      BEGIN
        IF bucket_hash !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
        w := floor(extract(epoch from clock_timestamp())/60);
        INSERT INTO cisguard.rate_windows(bucket,window_start,hits) VALUES(bucket_hash,w,1)
          ON CONFLICT(bucket,window_start) DO UPDATE SET hits=least(cisguard.rate_windows.hits+1,61) RETURNING hits INTO n;
        DELETE FROM cisguard.rate_windows WHERE window_start < w-2;
        RETURN n<=60;
      END $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.consume_rate(text) FROM PUBLIC')
    op.execute('GRANT EXECUTE ON FUNCTION cisguard.consume_rate(text) TO cisguard_api')
    # Browser access is intentionally limited to own membership; JWT identity cannot choose app.* context.
    op.execute("""DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authenticated') AND to_regprocedure('auth.uid()') IS NOT NULL THEN
      GRANT USAGE ON SCHEMA cisguard TO authenticated;
      GRANT SELECT(id,org_id,user_id,role,active,created_at,updated_at) ON cisguard.organization_members TO authenticated;
      CREATE POLICY browser_own_membership ON cisguard.organization_members FOR SELECT TO authenticated USING(user_id=auth.uid() AND active);
      END IF; END $$""")


def downgrade():
    raise RuntimeError('Security downgrade requires reviewed forward migration')
