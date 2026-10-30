"""Grant table DML permissions for policy rules, custom baselines, findings, exceptions, and manual reviews.

Revision ID: 0005_policy_engine
Revises: 0004_orchestration
Create Date: 2026-10-29 23:15:00
"""
from alembic import op

revision = "0005_policy_engine"
down_revision = "0004_orchestration"
branch_labels = None
depends_on = None


def upgrade():
    # Grant DML permissions for Phase 4 tables to runtime role cisguard_api
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.policy_rules TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE, DELETE ON cisguard.policy_overrides TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.findings TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.exceptions TO cisguard_api")
    op.execute("GRANT INSERT, UPDATE ON cisguard.manual_reviews TO cisguard_api")


def downgrade():
    raise RuntimeError("Reviewed forward migration required")

