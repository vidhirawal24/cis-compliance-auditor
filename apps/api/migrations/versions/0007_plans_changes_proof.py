"""Grant DML on remediation_plans, simulation_runs, approvals, changes, verification_runs,
remediation_actions, safety_contracts for Phases 7–9.

Revision ID: 0007_plans_changes_proof
Revises: 0006_reports_and_graph
Create Date: 2026-10-30
"""
from alembic import op

revision = "0007_plans_changes_proof"
down_revision = "0006_reports_and_graph"
branch_labels = None
depends_on = None


def upgrade():
    for tbl in [
        "remediation_plans",
        "remediation_actions",
        "safety_contracts",
        "simulation_runs",
        "approvals",
        "changes",
        "verification_runs",
    ]:
        op.execute(f"GRANT INSERT, UPDATE, DELETE ON cisguard.{tbl} TO cisguard_api")

    # proof_of_hardening is stored as audit_evidence + a dedicated reports row.
    # No extra table needed beyond what already exists from phase 6.


def downgrade():
    raise RuntimeError("Reviewed forward migration required")

