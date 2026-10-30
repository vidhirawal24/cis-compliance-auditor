"""Grant table DML permissions for asset inventory, scans, schedules and outbox.

Revision ID: 0004_orchestration
Revises: 0003_approval_guards
Create Date: 2026-10-29 20:40:00
"""
from alembic import op

revision = "0004_orchestration"
down_revision = "0003_approval_guards"
branch_labels = None
depends_on = None


def upgrade():
    # Grant DML permissions to restricted runtime role cisguard_api
    op.execute("GRANT INSERT, UPDATE ON cisguard.assets TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.asset_groups TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.asset_group_members TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.scan_jobs TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.scan_targets TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.schedules TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.outbox_events TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.authorization_scopes TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.benchmark_packs TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.audit_results TO cisguard_api")
    op.execute("GRANT INSERT ON cisguard.config_snapshots TO cisguard_api")
    op.execute("GRANT INSERT ON cisguard.audit_evidence TO cisguard_api")


def downgrade():
    raise RuntimeError("Reviewed forward migration required")
