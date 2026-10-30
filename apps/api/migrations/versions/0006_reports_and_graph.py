"""Grant table DML permissions for reports, notifications, integrations, asset edges, risk scenarios, and risk evidence.

Revision ID: 0006_reports_and_graph
Revises: 0005_policy_engine
Create Date: 2026-10-29 23:35:00
"""
from alembic import op

revision = "0006_reports_and_graph"
down_revision = "0005_policy_engine"
branch_labels = None
depends_on = None


def upgrade():
    # Grant DML permissions for Phase 5 & 6 tables to runtime role cisguard_api
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.reports TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.notifications TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.integrations TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.asset_edges TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.risk_scenarios TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.risk_evidence TO cisguard_api")


def downgrade():
    raise RuntimeError("Reviewed forward migration required")

