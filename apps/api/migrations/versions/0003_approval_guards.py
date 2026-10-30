"""Database enforcement of approval identity and separation of duties."""
from alembic import op
revision='0003_approval_guards'
down_revision='0002_security'
branch_labels=depends_on=None


def upgrade():
    op.execute('GRANT INSERT ON cisguard.approvals TO cisguard_api')
    op.execute("""CREATE FUNCTION cisguard.guard_approval() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,cisguard AS $$ DECLARE author uuid; BEGIN
      SELECT author_id INTO author FROM cisguard.remediation_plans WHERE org_id=NEW.org_id AND id=NEW.plan_id AND plan_sha256=NEW.plan_sha256;
      IF NOT cisguard.is_member(NEW.org_id) OR current_setting('app.aal',true) IS DISTINCT FROM 'aal2'
        OR NEW.approver_id IS DISTINCT FROM nullif(current_setting('app.user_id',true),'')::uuid
        OR author IS NULL OR NEW.plan_author_id IS DISTINCT FROM author OR NEW.approver_id=author
        OR NEW.expires_at<=now() OR NOT EXISTS(SELECT 1 FROM cisguard.organization_members WHERE org_id=NEW.org_id
          AND user_id=NEW.approver_id AND active AND role='approver') THEN
        RAISE EXCEPTION 'Approval denied' USING ERRCODE='42501'; END IF; RETURN NEW; END $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.guard_approval() FROM PUBLIC')
    op.execute('CREATE TRIGGER approval_identity BEFORE INSERT OR UPDATE ON cisguard.approvals FOR EACH ROW EXECUTE FUNCTION cisguard.guard_approval()')
    op.execute("""CREATE FUNCTION cisguard.guard_change_identity() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,cisguard AS $$ BEGIN
      IF NOT EXISTS(SELECT 1 FROM cisguard.approvals a JOIN cisguard.remediation_plans p ON p.org_id=a.org_id AND p.id=a.plan_id
        WHERE a.org_id=NEW.org_id AND a.id=NEW.approval_id AND a.plan_id=NEW.plan_id AND a.plan_sha256=p.plan_sha256
          AND a.decision='APPROVED' AND a.expires_at>now() AND a.approver_id<>NEW.operator_id AND a.approver_id<>p.author_id)
        THEN RAISE EXCEPTION 'Change approval identity denied' USING ERRCODE='42501'; END IF;
      RETURN NEW; END $$""")
    op.execute('REVOKE ALL ON FUNCTION cisguard.guard_change_identity() FROM PUBLIC')
    op.execute('CREATE TRIGGER change_identity BEFORE INSERT ON cisguard.changes FOR EACH ROW EXECUTE FUNCTION cisguard.guard_change_identity()')


def downgrade():
    raise RuntimeError('Reviewed forward migration required')
