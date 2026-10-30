"""Authoritative tenant-aware SQLAlchemy model. Domain engines are later phases."""
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
                        Index, Integer, MetaData, String, Text, UniqueConstraint, Uuid, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

SCHEMA = "cisguard"
NAMING = {"ix":"ix_%(table_name)s_%(column_0_name)s", "uq":"uq_%(table_name)s_%(column_0_name)s",
          "ck":"ck_%(table_name)s_%(constraint_name)s", "fk":"fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
          "pk":"pk_%(table_name)s"}


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA, naming_convention=NAMING)


class Record:
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TenantRecord(Record):
    org_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey(f"{SCHEMA}.organizations.id", ondelete="RESTRICT"), nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, server_default="false")

    @declared_attr.directive
    def __table_args__(cls):
        return tenant_constraints(cls.__tablename__)


def tenant_constraints(name, *extra):
    return (UniqueConstraint("org_id","id", name=f"uq_{name}_tenant_id"),
            Index(f"ix_{name}_tenant_created", "org_id", "created_at", "id"),
            Index(f"ix_{name}_retention", "retention_until"), *extra)


def tenant_fk(table, column, *, name=None):
    return ForeignKeyConstraint(["org_id",column], [f"{SCHEMA}.{table}.org_id",f"{SCHEMA}.{table}.id"],
                                name=name or f"fk_{column}_{table}", ondelete="RESTRICT")


class Organization(Record, Base):
    __tablename__ = "organizations"
    name: Mapped[str] = mapped_column(String(200))
    default_retention_days: Mapped[int] = mapped_column(Integer, server_default="365")
    __table_args__ = (CheckConstraint("default_retention_days BETWEEN 1 AND 3650", name="retention_days"),)


class OrganizationMember(TenantRecord, Base):
    __tablename__ = "organization_members"
    user_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, server_default="true")
    __table_args__ = tenant_constraints(__tablename__, UniqueConstraint("org_id","user_id",name="uq_members_user"),
        CheckConstraint("role IN ('owner','security_admin','auditor','operator','approver','executive')",name="role"),
        Index("ix_members_user_active","user_id","active"))


class AuthorizationScope(TenantRecord, Base):
    __tablename__ = "authorization_scopes"
    name: Mapped[str] = mapped_column(String(200))
    approved_targets: Mapped[list] = mapped_column(JSONB, default=list)
    approved_by: Mapped[UUID] = mapped_column(Uuid)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CredentialReference(TenantRecord, Base):
    __tablename__ = "credential_references"
    vault_reference: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(String(200))
    # Vault pointer only; no password, private key or access-token columns.


class Asset(TenantRecord, Base):
    __tablename__ = "assets"
    name: Mapped[str] = mapped_column(String(200))
    family: Mapped[str] = mapped_column(String(32))
    platform: Mapped[str] = mapped_column(String(128))
    vendor: Mapped[str] = mapped_column(String(128))
    model: Mapped[str] = mapped_column(String(128))
    os_or_firmware_version: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(512))
    authorization_scope_id: Mapped[UUID] = mapped_column(Uuid)
    credential_reference_id: Mapped[UUID | None] = mapped_column(Uuid)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    retired: Mapped[bool] = mapped_column(Boolean, server_default="false")
    __table_args__ = tenant_constraints(__tablename__, tenant_fk("authorization_scopes","authorization_scope_id"),
        tenant_fk("credential_references","credential_reference_id"),
        CheckConstraint("family IN ('windows','linux','firewall','router','switch')",name="family"),
        UniqueConstraint("org_id","target",name="uq_assets_target"), Index("ix_assets_platform","org_id","platform"))


class AssetGroup(TenantRecord, Base):
    __tablename__ = "asset_groups"
    name: Mapped[str] = mapped_column(String(200))
    __table_args__ = tenant_constraints(__tablename__, UniqueConstraint("org_id","name",name="uq_groups_name"))


class AssetGroupMember(TenantRecord, Base):
    __tablename__ = "asset_group_members"
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    group_id: Mapped[UUID] = mapped_column(Uuid)
    __table_args__ = tenant_constraints(__tablename__, tenant_fk("assets","asset_id"),tenant_fk("asset_groups","group_id"),
        UniqueConstraint("org_id","asset_id","group_id",name="uq_group_membership"))


class PolicyPack(TenantRecord, Base):
    __tablename__ = "benchmark_packs"
    benchmark_id: Mapped[str] = mapped_column(String(200))
    benchmark_release: Mapped[str] = mapped_column(String(128))
    pack_version: Mapped[str] = mapped_column(String(128))
    profiles: Mapped[list] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(String(64))
    source_reference: Mapped[str] = mapped_column(Text)
    rights_status: Mapped[str] = mapped_column(String(32), server_default="UNREVIEWED")
    evaluator_version: Mapped[str] = mapped_column(String(128))
    content_sha256: Mapped[str] = mapped_column(String(64))
    __table_args__ = tenant_constraints(__tablename__,
        UniqueConstraint("org_id","benchmark_id","pack_version",name="uq_pack_version"),
        CheckConstraint("rights_status IN ('UNREVIEWED','AUTHORIZED','RESTRICTED')",name="rights"),
        CheckConstraint("content_sha256 ~ '^[a-f0-9]{64}$'",name="hash"))


class PolicyRule(TenantRecord, Base):
    __tablename__ = "policy_rules"
    policy_pack_id: Mapped[UUID] = mapped_column(Uuid)
    control_id: Mapped[str] = mapped_column(String(200))
    definition: Mapped[dict] = mapped_column(JSONB)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("benchmark_packs","policy_pack_id"),
        UniqueConstraint("org_id","policy_pack_id","control_id",name="uq_rule_control"))


class PolicyOverride(TenantRecord, Base):
    __tablename__ = "policy_overrides"
    rule_id: Mapped[UUID] = mapped_column(Uuid)
    version: Mapped[str] = mapped_column(String(128))
    expected: Mapped[dict] = mapped_column(JSONB)
    reason: Mapped[str] = mapped_column(Text)
    author_id: Mapped[UUID] = mapped_column(Uuid)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("policy_rules","rule_id"))


class ScanJob(TenantRecord, Base):
    __tablename__ = "scan_jobs"
    policy_pack_id: Mapped[UUID] = mapped_column(Uuid)
    requested_by: Mapped[UUID] = mapped_column(Uuid)
    profile: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), server_default="QUEUED")
    read_only: Mapped[bool] = mapped_column(Boolean, server_default="true")
    requested_assets: Mapped[int] = mapped_column(Integer, server_default="0")
    completed_assets: Mapped[int] = mapped_column(Integer, server_default="0")
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("benchmark_packs","policy_pack_id"),
        CheckConstraint("read_only = true",name="read_only"),
        CheckConstraint("status IN ('QUEUED','RUNNING','SUCCEEDED','PARTIAL','FAILED','CANCELLED')",name="status"),
        CheckConstraint("requested_assets >= 0 AND completed_assets >= 0 AND completed_assets <= requested_assets",name="progress"),
        Index("ix_scan_status","org_id","status"))


class ScanTarget(TenantRecord, Base):
    __tablename__ = "scan_targets"
    scan_id: Mapped[UUID] = mapped_column(Uuid)
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    status: Mapped[str] = mapped_column(String(32), server_default="QUEUED")
    errors: Mapped[list] = mapped_column(JSONB, default=list)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("scan_jobs","scan_id"),tenant_fk("assets","asset_id"),
        UniqueConstraint("org_id","scan_id","asset_id",name="uq_scan_target"))


class Evidence(TenantRecord, Base):
    __tablename__ = "audit_evidence"
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    source_identity: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    encrypted_artifact_location: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    collection_method: Mapped[str] = mapped_column(String(64))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("assets","asset_id"),
        CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'",name="hash"),
        CheckConstraint("encrypted_artifact_location LIKE 'private://%'",name="private_location"))


class ConfigSnapshot(TenantRecord, Base):
    __tablename__ = "config_snapshots"
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID] = mapped_column(Uuid)
    device_version: Mapped[str] = mapped_column(String(128))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("assets","asset_id"),tenant_fk("audit_evidence","evidence_id"))


class AuditResult(TenantRecord, Base):
    __tablename__ = "audit_results"
    scan_id: Mapped[UUID] = mapped_column(Uuid)
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    rule_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID | None] = mapped_column(Uuid)
    status: Mapped[str] = mapped_column(String(32))
    expected: Mapped[dict | None] = mapped_column(JSONB)
    observed: Mapped[dict | None] = mapped_column(JSONB)
    evaluator_version: Mapped[str] = mapped_column(String(128))
    limitations: Mapped[list] = mapped_column(JSONB, default=list)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("scan_jobs","scan_id"),tenant_fk("assets","asset_id"),
        tenant_fk("policy_rules","rule_id"),tenant_fk("audit_evidence","evidence_id"),
        CheckConstraint("status IN ('PASS','FAIL','NOT_APPLICABLE','MANUAL_REVIEW','ERROR','NOT_ASSESSED')",name="status"),
        CheckConstraint("status NOT IN ('PASS','FAIL') OR evidence_id IS NOT NULL",name="assessed_evidence"),
        UniqueConstraint("org_id","scan_id","asset_id","rule_id",name="uq_result_control"))


class Finding(TenantRecord, Base):
    __tablename__ = "findings"
    result_id: Mapped[UUID] = mapped_column(Uuid)
    severity: Mapped[str] = mapped_column(String(16))
    remediation_template_id: Mapped[UUID | None] = mapped_column(Uuid)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("audit_results","result_id"),
        CheckConstraint("severity IN ('CRITICAL','HIGH','MEDIUM','LOW')",name="severity"),
        UniqueConstraint("org_id","result_id",name="uq_finding_result"))


class PolicyException(TenantRecord, Base):
    __tablename__ = "exceptions"
    finding_id: Mapped[UUID] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(String(16), server_default="PENDING")
    approver_id: Mapped[UUID | None] = mapped_column(Uuid)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("findings","finding_id"),
        CheckConstraint("decision IN ('PENDING','APPROVED','REJECTED','EXPIRED')",name="decision"))


class ManualReview(TenantRecord, Base):
    __tablename__ = "manual_reviews"
    finding_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID] = mapped_column(Uuid)
    reviewer_id: Mapped[UUID] = mapped_column(Uuid)
    verdict: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(Text)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("findings","finding_id"),tenant_fk("audit_evidence","evidence_id"))


class AssetEdge(TenantRecord, Base):
    __tablename__ = "asset_edges"
    source_asset_id: Mapped[UUID] = mapped_column(Uuid)
    target_asset_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID] = mapped_column(Uuid)
    relationship: Mapped[str] = mapped_column(String(64))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("assets","source_asset_id"),tenant_fk("assets","target_asset_id"),tenant_fk("audit_evidence","evidence_id"))


class RiskScenario(TenantRecord, Base):
    __tablename__ = "risk_scenarios"
    rule_version: Mapped[str] = mapped_column(String(128))
    explanation: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)
    limitations: Mapped[list] = mapped_column(JSONB, default=list)
    __table_args__ = tenant_constraints(__tablename__,CheckConstraint("score BETWEEN 0 AND 100",name="score"))


class RiskEvidence(TenantRecord, Base):
    __tablename__ = "risk_evidence"
    scenario_id: Mapped[UUID] = mapped_column(Uuid)
    finding_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID] = mapped_column(Uuid)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("risk_scenarios","scenario_id"),tenant_fk("findings","finding_id"),tenant_fk("audit_evidence","evidence_id"))


class RemediationPlan(TenantRecord, Base):
    __tablename__ = "remediation_plans"
    author_id: Mapped[UUID] = mapped_column(Uuid)
    plan_sha256: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32))
    violated_constraints: Mapped[list] = mapped_column(JSONB, default=list)
    __table_args__ = tenant_constraints(__tablename__,CheckConstraint("outcome IN ('FEASIBLE','UNSAT','UNSUPPORTED','INSUFFICIENT_EVIDENCE')",name="outcome"),
        UniqueConstraint("org_id","id","plan_sha256",name="uq_plan_digest"),
        CheckConstraint("plan_sha256 ~ '^[a-f0-9]{64}$'",name="hash"))


class RemediationAction(TenantRecord, Base):
    __tablename__ = "remediation_actions"
    plan_id: Mapped[UUID] = mapped_column(Uuid)
    asset_id: Mapped[UUID] = mapped_column(Uuid)
    template_id: Mapped[UUID] = mapped_column(Uuid)
    template_version: Mapped[str] = mapped_column(String(128))
    validated_parameters_ref: Mapped[UUID] = mapped_column(Uuid)
    recovery: Mapped[str] = mapped_column(String(32))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("remediation_plans","plan_id"),tenant_fk("assets","asset_id"),
        CheckConstraint("recovery IN ('ROLLBACK','COMPENSATION','MANUAL_REQUIRED')",name="recovery"))


class SafetyContract(TenantRecord, Base):
    __tablename__ = "safety_contracts"
    source_asset_id: Mapped[UUID] = mapped_column(Uuid)
    destination_asset_id: Mapped[UUID] = mapped_column(Uuid)
    protocol: Mapped[str] = mapped_column(String(16))
    port: Mapped[int | None] = mapped_column(Integer)
    mandatory: Mapped[bool] = mapped_column(Boolean, server_default="true")
    expected: Mapped[str] = mapped_column(String(16))
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("assets","source_asset_id"),tenant_fk("assets","destination_asset_id"),
        CheckConstraint("port IS NULL OR port BETWEEN 1 AND 65535",name="port"),
        CheckConstraint("expected IN ('REACHABLE','BLOCKED')",name="expected"))


class SimulationRun(TenantRecord, Base):
    __tablename__ = "simulation_runs"
    plan_id: Mapped[UUID] = mapped_column(Uuid)
    plan_sha256: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(32))
    model_version: Mapped[str] = mapped_column(String(128))
    limitations: Mapped[list] = mapped_column(JSONB, default=list)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("remediation_plans","plan_id"),
        CheckConstraint("verdict IN ('SAFE_IN_MODEL','VIOLATES_CONTRACT','UNSUPPORTED','INSUFFICIENT_EVIDENCE')",name="verdict"))


class Approval(TenantRecord, Base):
    __tablename__ = "approvals"
    plan_id: Mapped[UUID] = mapped_column(Uuid)
    plan_sha256: Mapped[str] = mapped_column(String(64))
    approver_id: Mapped[UUID] = mapped_column(Uuid)
    plan_author_id: Mapped[UUID] = mapped_column(Uuid)
    decision: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    __table_args__ = tenant_constraints(__tablename__,
        ForeignKeyConstraint(["org_id","plan_id","plan_sha256"],[f"{SCHEMA}.remediation_plans.org_id",f"{SCHEMA}.remediation_plans.id",f"{SCHEMA}.remediation_plans.plan_sha256"],ondelete="RESTRICT",name="fk_approval_exact_plan"),
        CheckConstraint("approver_id <> plan_author_id",name="separation"),
        CheckConstraint("decision IN ('APPROVED','REJECTED')",name="decision"))


class Change(TenantRecord, Base):
    __tablename__ = "changes"
    plan_id: Mapped[UUID] = mapped_column(Uuid)
    approval_id: Mapped[UUID] = mapped_column(Uuid)
    simulation_id: Mapped[UUID] = mapped_column(Uuid)
    operator_id: Mapped[UUID] = mapped_column(Uuid)
    state: Mapped[str] = mapped_column(String(32), server_default="DRAFT")
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("remediation_plans","plan_id"),tenant_fk("approvals","approval_id"),tenant_fk("simulation_runs","simulation_id"),
        CheckConstraint("state IN ('DRAFT','SIMULATED','PRECHECKED','PENDING_APPROVAL','APPROVED','EXECUTING','VERIFYING','VERIFIED','FAILED','ROLLED_BACK','NEEDS_MANUAL_RECOVERY')",name="state"))


class VerificationRun(TenantRecord, Base):
    __tablename__ = "verification_runs"
    change_id: Mapped[UUID] = mapped_column(Uuid)
    post_scan_id: Mapped[UUID] = mapped_column(Uuid)
    status: Mapped[str] = mapped_column(String(32))
    control_statuses: Mapped[list] = mapped_column(JSONB)
    service_checks: Mapped[list] = mapped_column(JSONB)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("changes","change_id"),tenant_fk("scan_jobs","post_scan_id"),
        CheckConstraint("status IN ('VERIFIED','FAILED','NOT_FULLY_VERIFIED')",name="status"))


class Report(TenantRecord, Base):
    __tablename__ = "reports"
    scan_id: Mapped[UUID] = mapped_column(Uuid)
    evidence_id: Mapped[UUID | None] = mapped_column(Uuid)
    format: Mapped[str] = mapped_column(String(8))
    audience: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), server_default="QUEUED")
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("scan_jobs","scan_id"),tenant_fk("audit_evidence","evidence_id"),
        CheckConstraint("format IN ('PDF','HTML','CSV','JSON')",name="format"),
        CheckConstraint("audience IN ('TECHNICAL','EXECUTIVE')",name="audience"))


class AuditEvent(TenantRecord, Base):
    __tablename__ = "audit_events"
    actor_id: Mapped[UUID] = mapped_column(Uuid)
    request_id: Mapped[UUID] = mapped_column(Uuid)
    event_type: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[UUID] = mapped_column(Uuid)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    # Append-only event persistence; cryptographic chain/signing is a later proof-phase feature.


class Notification(TenantRecord, Base):
    __tablename__ = "notifications"
    event_id: Mapped[UUID] = mapped_column(Uuid)
    status: Mapped[str] = mapped_column(String(16), server_default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, server_default="0")
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("audit_events","event_id"),
        CheckConstraint("attempt_count >= 0",name="attempt_count"))


class Integration(TenantRecord, Base):
    __tablename__ = "integrations"
    kind: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(Text)
    credential_reference_id: Mapped[UUID] = mapped_column(Uuid)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false")
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("credential_references","credential_reference_id"))


class Schedule(TenantRecord, Base):
    __tablename__ = "schedules"
    policy_pack_id: Mapped[UUID] = mapped_column(Uuid)
    cron_utc: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false")
    selection: Mapped[dict] = mapped_column(JSONB)
    __table_args__ = tenant_constraints(__tablename__,tenant_fk("benchmark_packs","policy_pack_id"))


class OutboxEvent(TenantRecord, Base):
    __tablename__ = "outbox_events"
    topic: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict] = mapped_column(JSONB)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, server_default="0")
    __table_args__ = tenant_constraints(__tablename__,Index("ix_outbox_pending","published_at","created_at"))


class IdempotencyRecord(TenantRecord, Base):
    __tablename__ = "idempotency_records"
    actor_id: Mapped[UUID] = mapped_column(Uuid)
    key: Mapped[UUID] = mapped_column(Uuid)
    route: Mapped[str] = mapped_column(String(200))
    body_sha256: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict] = mapped_column(JSONB)
    status_code: Mapped[int] = mapped_column(Integer)
    __table_args__ = tenant_constraints(__tablename__,UniqueConstraint("org_id","actor_id","key","route",name="uq_idempotency_scope"))
