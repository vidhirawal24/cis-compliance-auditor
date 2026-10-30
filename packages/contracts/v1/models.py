"""CISGuard v1 wire types. Specification only; no deployed API or device support."""
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
Hash = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
FeatureID = Annotated[str, StringConstraints(pattern=r"^(M(0[1-9]|[12][0-9]|3[0-8])|E(0[1-9]|[12][0-9]|30)|I(0[1-9]|1[0-9]|20))$")]
UTC = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")]
Count = Annotated[int, Field(ge=0)]
Percent = Annotated[float, Field(ge=0, le=100)]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, allow_inf_nan=False)

    @model_validator(mode="after")
    def valid_timestamps(self):
        # JSON Schema pattern constrains UTC notation; also reject impossible dates.
        for name, value in self.__dict__.items():
            if name.endswith(("_at", "_until")) and isinstance(value, str):
                datetime.fromisoformat(value.replace("Z", "+00:00"))
        return self


class Versioned(WireModel):
    schema_version: Literal["1.0.0"]


class Scoped(Versioned):
    org_id: UUID


class AssessmentStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"
    NOT_ASSESSED = "NOT_ASSESSED"


class SimulationVerdict(StrEnum):
    SAFE_IN_MODEL = "SAFE_IN_MODEL"
    VIOLATES_CONTRACT = "VIOLATES_CONTRACT"
    UNSUPPORTED = "UNSUPPORTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ExecutionState(StrEnum):
    DRAFT = "DRAFT"
    SIMULATED = "SIMULATED"
    PRECHECKED = "PRECHECKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    NEEDS_MANUAL_RECOVERY = "NEEDS_MANUAL_RECOVERY"


class JobState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Role(StrEnum):
    OWNER = "owner"
    SECURITY_ADMIN = "security_admin"
    AUDITOR = "auditor"
    OPERATOR = "operator"
    APPROVER = "approver"
    EXECUTIVE = "executive"


class APIError(WireModel):
    code: Literal["UNAUTHENTICATED", "FORBIDDEN", "MFA_REQUIRED", "NOT_FOUND", "VALIDATION_ERROR", "CONFLICT", "RATE_LIMITED", "UNSUPPORTED", "INSUFFICIENT_EVIDENCE", "APPROVAL_REQUIRED", "STALE_PLAN", "SAFETY_GATE_FAILED", "DEPENDENCY_UNAVAILABLE", "INTERNAL_ERROR"]
    message: Text
    request_id: UUID
    details: list[Text] | None = None
    retryable: bool


class Meta(WireModel):
    request_id: UUID


T = TypeVar("T")


class Envelope(Versioned, Generic[T]):
    data: T
    meta: Meta


class Page(WireModel, Generic[T]):
    items: list[T]
    next_cursor: Text | None


class EvidenceRef(WireModel):
    evidence_id: UUID
    sha256: Hash
    source_identity: Text  # registered command/API identity, not executable input
    encrypted_artifact_location: Annotated[str, StringConstraints(pattern=r"^private://[a-z0-9-]+/[a-zA-Z0-9/_-]+$")]
    collected_at: UTC


class CollectorError(WireModel):
    code: Literal["UNSUPPORTED", "AUTH_FAILED", "TIMEOUT", "PARSE_ERROR", "MISSING_EVIDENCE", "DEVICE_UNAVAILABLE"]
    message: Text
    capability: Text | None = None
    retryable: bool


class Fact(WireModel):
    path: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")]
    value: JsonValue
    evidence_ids: list[UUID] = Field(min_length=1)
    observed_at: UTC


class NormalizedFacts(WireModel):
    management: list[Fact] = Field(default_factory=list)
    network_policy: list[Fact] = Field(default_factory=list)
    os_security: list[Fact] = Field(default_factory=list)
    topology: list[Fact] = Field(default_factory=list)


class NormalizedEvidence(Scoped):
    asset_id: UUID
    platform: Text
    vendor: Text
    model: Text
    os_or_firmware_version: Text
    collector_version: Text
    collection_method: Literal["ssh", "winrm", "vendor_api", "openscap", "offline_upload", "offline_fixture"]
    collected_at: UTC
    facts: NormalizedFacts
    evidence_refs: list[EvidenceRef]
    supported_capabilities: list[Text]
    unsupported_capabilities: list[Text]
    errors: list[CollectorError]

    @model_validator(mode="after")
    def fact_provenance(self):
        if set(self.supported_capabilities) & set(self.unsupported_capabilities):
            raise ValueError("Capability cannot be both supported and unsupported")
        ids = {e.evidence_id for e in self.evidence_refs}
        for category in type(self.facts).model_fields:
            for fact in getattr(self.facts, category):
                if not fact.path.startswith(category + "."):
                    raise ValueError("Fact path must match category")
                if not set(fact.evidence_ids) <= ids:
                    raise ValueError("Fact references missing evidence")
        return self


class Score(WireModel):
    pass_count: Count
    fail_count: Count
    not_applicable_count: Count
    manual_review_count: Count
    error_count: Count
    not_assessed_count: Count
    assessed_compliance_pct: Percent | None
    assessment_coverage_pct: Percent | None

    @model_validator(mode="after")
    def reconciles(self):
        assessed = self.pass_count + self.fail_count
        eligible = assessed + self.manual_review_count + self.error_count + self.not_assessed_count
        expected = (round(100 * self.pass_count / assessed, 4) if assessed else None,
                    round(100 * assessed / eligible, 4) if eligible else None)
        if (self.assessed_compliance_pct, self.assessment_coverage_pct) != expected:
            raise ValueError("Scores must reconcile; zero denominator is null")
        return self


class AssetCreate(WireModel):
    name: Text
    family: Literal["windows", "linux", "firewall", "router", "switch"]
    platform: Text
    vendor: Text
    model: Text
    os_or_firmware_version: Text
    target: Text
    authorization_scope_id: UUID
    credential_reference_id: UUID | None = None
    tags: list[Text] = Field(default_factory=list)


class Asset(AssetCreate, Scoped):
    asset_id: UUID
    retired: bool = False


class Capabilities(WireModel):
    asset_id: UUID
    supported: list[Text]
    unsupported: list[Text]
    compatibility_status: Literal["UNTESTED", "FIXTURE_TESTED", "LAB_VERIFIED"]


class ScanCreate(WireModel):
    asset_ids: list[UUID] = Field(min_length=1, max_length=1000)
    policy_pack_id: UUID
    policy_version: Text
    profile: Text
    control_ids: list[Text] = Field(default_factory=list)
    mode: Literal["read_only"] = "read_only"
    offline_evidence_ids: list[UUID] = Field(default_factory=list)


class Scan(Scoped, Score):
    scan_id: UUID
    status: JobState
    requested_assets: Count
    completed_assets: Count
    created_at: UTC

    @model_validator(mode="after")
    def progress(self):
        if self.completed_assets > self.requested_assets:
            raise ValueError("Completed assets exceeds requested assets")
        return self


class ScanTarget(WireModel):
    scan_id: UUID
    asset_id: UUID
    status: JobState
    errors: list[CollectorError]


class PolicyRule(WireModel):
    control_id: Text
    feature_ids: list[FeatureID] = Field(min_length=1)
    fact_path: Text
    operator: Literal["equals", "contains", "regex", "range", "set_membership", "cidr_contains", "ordered_acl", "xccdf_oval"]
    expected: JsonValue
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    applicability_platforms: list[Text] = Field(min_length=1)
    requires_manual_review: bool
    remediation_template_id: UUID | None


class PolicyPack(Scoped):
    policy_pack_id: UUID
    benchmark_id: Text
    benchmark_release: Text
    pack_version: Text
    profiles: list[Text] = Field(min_length=1)
    source: Literal["authorized_cis_mapping", "organizational", "validated_scap_mapping"]
    source_reference: Text
    rights_status: Literal["UNREVIEWED", "AUTHORIZED", "RESTRICTED"]
    evaluator_version: Text
    content_sha256: Hash


class PolicyDiff(WireModel):
    policy_pack_id: UUID
    from_version: Text
    to_version: Text
    added_control_ids: list[Text]
    removed_control_ids: list[Text]
    modified_control_ids: list[Text]


class ExceptionRequest(WireModel):
    finding_id: UUID
    reason: Text
    expires_at: UTC


class ExceptionOverlay(ExceptionRequest, Scoped):
    exception_id: UUID
    decision: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"]
    approver_id: UUID | None


class Finding(Scoped):
    finding_id: UUID
    scan_id: UUID
    asset_id: UUID
    device_version: Text
    control_id: Text
    policy_pack_id: UUID
    policy_version: Text
    benchmark_release: Text
    profile: Text
    applicability: Literal["APPLICABLE", "NOT_APPLICABLE", "UNKNOWN"]
    status: AssessmentStatus
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    expected: JsonValue
    observed: JsonValue
    rule_inputs: list[Fact]
    evidence_refs: list[EvidenceRef]
    evaluator_version: Text
    evaluated_at: UTC
    remediation_template_id: UUID | None
    limitations: list[Text]
    exception: ExceptionOverlay | None = None

    @model_validator(mode="after")
    def assessed_requires_evidence(self):
        if self.status in (AssessmentStatus.PASS, AssessmentStatus.FAIL):
            if self.applicability != "APPLICABLE" or not self.evidence_refs:
                raise ValueError("Assessed result requires applicability and evidence")
        if self.exception and (self.exception.org_id != self.org_id or self.exception.finding_id != self.finding_id):
            raise ValueError("Exception must belong to this tenant and finding")
        return self


class CollectionCommand(Scoped):
    job_id: UUID
    scan_id: UUID
    asset_id: UUID
    request_id: UUID
    authorization_scope_id: UUID
    credential_reference_id: UUID | None
    expected_platform: Text
    expected_device_version: Text
    requested_capabilities: list[Text]
    read_only: Literal[True] = True
    deadline_at: UTC
    idempotency_key: UUID


class CollectionResult(Scoped):
    job_id: UUID
    scan_id: UUID
    asset_id: UUID
    status: Literal["COLLECTED", "PARTIAL", "UNSUPPORTED", "ERROR"]
    evidence: NormalizedEvidence | None
    errors: list[CollectorError]

    @model_validator(mode="after")
    def collection_outcome(self):
        if self.status in ("COLLECTED", "PARTIAL") and self.evidence is None:
            raise ValueError("Collection needs evidence")
        if self.status in ("UNSUPPORTED", "ERROR") and not self.errors:
            raise ValueError("Unsuccessful collection needs reason")
        if self.status == "COLLECTED" and self.errors:
            raise ValueError("Collected result cannot hide errors")
        if self.evidence and (self.org_id != self.evidence.org_id or self.asset_id != self.evidence.asset_id):
            raise ValueError("Evidence tenant/asset mismatch")
        return self


class SafetyContract(Scoped):
    safety_contract_id: UUID
    source_asset_id: UUID
    destination_asset_id: UUID
    protocol: Literal["tcp", "udp", "icmp", "https", "ssh"]
    port: Annotated[int, Field(ge=1, le=65535)] | None
    mandatory: bool
    expected: Literal["REACHABLE", "BLOCKED"]


class PlanCreate(WireModel):
    finding_ids: list[UUID] = Field(min_length=1)
    safety_contract_ids: list[UUID] = Field(min_length=1)
    candidate_template_ids: list[UUID] = Field(min_length=1)
    max_change_cost: Annotated[int, Field(ge=0)]


class RemediationAction(WireModel):
    action_id: UUID
    asset_id: UUID
    template_id: UUID
    template_version: Text
    expected_device_version: Text
    baseline_sha256: Hash
    # Parameters are selected server-side using template-specific schemas, not commands.
    validated_parameters_ref: UUID
    depends_on: list[UUID]
    recovery: Literal["ROLLBACK", "COMPENSATION", "MANUAL_REQUIRED"]


class Plan(Scoped):
    plan_id: UUID
    plan_sha256: Hash
    outcome: Literal["FEASIBLE", "UNSAT", "UNSUPPORTED", "INSUFFICIENT_EVIDENCE"]
    actions: list[RemediationAction]
    violated_constraints: list[Text]
    safety_contract_ids: list[UUID]
    created_by: UUID
    created_at: UTC

    @model_validator(mode="after")
    def feasible_actions(self):
        if self.outcome != "FEASIBLE" and self.actions:
            raise ValueError("Non-feasible plan cannot contain executable actions")
        if self.outcome == "UNSAT" and not self.violated_constraints:
            raise ValueError("UNSAT must explain violated constraints")
        return self


class SimulationCreate(WireModel):
    plan_id: UUID
    plan_sha256: Hash
    baseline_evidence_ids: list[UUID] = Field(min_length=1)


class Simulation(Scoped):
    simulation_id: UUID
    plan_id: UUID
    plan_sha256: Hash
    verdict: SimulationVerdict
    checked_contract_ids: list[UUID]
    unsupported_capabilities: list[Text]
    evidence_ids: list[UUID]
    limitations: list[Text]
    model_version: Text
    simulated_at: UTC


class ApprovalCreate(WireModel):
    plan_id: UUID
    plan_sha256: Hash
    decision: Literal["APPROVED", "REJECTED"]
    reason: Text
    expires_at: UTC


class Approval(ApprovalCreate, Scoped):
    approval_id: UUID
    approver_id: UUID
    decided_at: UTC


class ChangeCreate(WireModel):
    plan_id: UUID
    plan_sha256: Hash
    approval_id: UUID
    simulation_id: UUID
    precheck_id: UUID


class Change(Scoped):
    change_id: UUID
    plan_id: UUID
    state: ExecutionState
    operator_id: UUID
    created_at: UTC
    previous_change_id: UUID | None


class ExecutionCommand(Scoped):
    job_id: UUID
    request_id: UUID
    change_id: UUID
    plan_id: UUID
    plan_sha256: Hash
    approval_id: UUID
    operator_id: UUID
    approver_id: UUID
    plan_author_id: UUID
    authorization_grant_id: UUID
    precheck_id: UUID
    backup_evidence_ids: list[UUID] = Field(min_length=1)
    safety_contract_ids: list[UUID] = Field(min_length=1)
    actions: list[RemediationAction] = Field(min_length=1)
    expires_at: UTC
    idempotency_key: UUID

    @model_validator(mode="after")
    def separate_duties(self):
        if self.approver_id in (self.operator_id, self.plan_author_id):
            raise ValueError("Approver must differ from operator and plan author")
        return self


class ExecutionResult(Scoped):
    job_id: UUID
    change_id: UUID
    state: Literal["VERIFYING", "FAILED", "ROLLED_BACK", "NEEDS_MANUAL_RECOVERY"]
    evidence_refs: list[EvidenceRef]
    errors: list[CollectorError]
    completed_action_ids: list[UUID]


class ServiceCheck(WireModel):
    safety_contract_id: UUID
    status: Literal["PASS", "FAIL", "ERROR", "NOT_ASSESSED"]
    evidence_refs: list[EvidenceRef]


class VerificationCommand(Scoped):
    job_id: UUID
    change_id: UUID
    scan_id: UUID
    asset_ids: list[UUID] = Field(min_length=1)
    control_ids: list[Text] = Field(min_length=1)
    safety_contract_ids: list[UUID] = Field(min_length=1)
    deadline_at: UTC


class VerificationCreate(WireModel):
    change_id: UUID


class SimulationCommand(Scoped):
    job_id: UUID
    request_id: UUID
    plan_id: UUID
    plan_sha256: Hash
    baseline_evidence_ids: list[UUID] = Field(min_length=1)
    safety_contract_ids: list[UUID] = Field(min_length=1)
    deadline_at: UTC


class Verification(Scoped):
    verification_id: UUID
    change_id: UUID
    post_scan_id: UUID
    control_statuses: list[AssessmentStatus] = Field(min_length=1)
    service_checks: list[ServiceCheck] = Field(min_length=1)
    status: Literal["VERIFIED", "FAILED", "NOT_FULLY_VERIFIED"]
    verified_at: UTC
    evidence_refs: list[EvidenceRef]

    @model_validator(mode="after")
    def dual_verification(self):
        if self.status == "VERIFIED":
            if not self.evidence_refs or any(s != "PASS" for s in self.control_statuses):
                raise ValueError("Verification requires fresh passing compliance evidence")
            if any(s.status != "PASS" or not s.evidence_refs for s in self.service_checks):
                raise ValueError("Verification requires measured passing service evidence")
        return self


class GraphNode(WireModel):
    node_id: UUID
    kind: Literal["asset", "interface", "network", "route", "service", "policy", "control", "finding"]
    label: Text


class GraphEdge(WireModel):
    edge_id: UUID
    source_id: UUID
    target_id: UUID
    relationship: Literal["hosted_on", "attached_to", "routes_to", "allows", "denies", "depends_on", "violates"]
    evidence_ids: list[UUID] = Field(min_length=1)


class Graph(Scoped):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    limitations: list[Text]


class RiskScenario(Scoped):
    scenario_id: UUID
    rule_version: Text
    source_finding_ids: list[UUID] = Field(min_length=1)
    evidence_ids: list[UUID] = Field(min_length=1)
    explanation: Text
    score: Percent
    limitations: list[Text]


class ReportCreate(WireModel):
    scan_id: UUID
    format: Literal["PDF", "HTML", "CSV", "JSON"]
    audience: Literal["TECHNICAL", "EXECUTIVE"]


class Report(Scoped):
    report_id: UUID
    scan_id: UUID
    format: Literal["PDF", "HTML", "CSV", "JSON"]
    audience: Literal["TECHNICAL", "EXECUTIVE"]
    status: JobState
    artifact: EvidenceRef | None


class Download(WireModel):
    signed_url: Annotated[str, StringConstraints(pattern=r"^https://")]
    expires_at: UTC
    sha256: Hash


class ProofCreate(WireModel):
    change_id: UUID
    verification_id: UUID


class Proof(Scoped):
    proof_id: UUID
    change_id: UUID
    verification_id: UUID
    original_finding_ids: list[UUID] = Field(min_length=1)
    benchmark_release: Text
    profile: Text
    operator_id: UUID
    approver_id: UUID
    before_evidence: list[EvidenceRef] = Field(min_length=1)
    after_evidence: list[EvidenceRef] = Field(min_length=1)
    plan_sha256: Hash
    approval_id: UUID
    simulation_id: UUID
    execution_event_ids: list[UUID] = Field(min_length=1)
    residual_risk_ids: list[UUID]
    manifest_sha256: Hash
    signature: Text
    signing_key_id: Text


class AuditEvent(Scoped):
    event_id: UUID
    event_type: Literal["audit.requested", "audit.started", "evidence.collected", "control.evaluated", "finding.created", "scenario.correlated", "plan.generated", "simulation.completed", "approval.granted", "approval.rejected", "action.started", "action.completed", "action.failed", "verification.completed", "evidence.signed", "drift.detected", "report.generated", "auth.login", "policy.changed", "report.exported"]
    request_id: UUID
    actor_id: UUID
    actor_kind: Literal["user", "worker"]
    occurred_at: UTC
    resource_id: UUID
    previous_hash: Hash | None
    event_hash: Hash


class OrganizationCreate(WireModel):
    name: Text


class Organization(OrganizationCreate):
    org_id: UUID


class MemberCreate(WireModel):
    user_id: UUID
    role: Role


class Member(MemberCreate):
    org_id: UUID


class Session(WireModel):
    user_id: UUID
    org_id: UUID
    roles: list[Role]
    aal: Literal["aal1", "aal2"]
    expires_at: UTC


class MFAStatus(WireModel):
    enrolled: bool
    aal: Literal["aal1", "aal2"]
    required: bool


class DiscoveryCreate(WireModel):
    authorization_scope_id: UUID
    approved_cidrs: list[Text] = Field(min_length=1, max_length=100)


class JobReceipt(Scoped):
    job_id: UUID
    status: JobState
    resource_id: UUID
    resource_type: Literal["discovery", "plan", "simulation", "verification", "proof", "report", "precheck"]


class ManualReviewCreate(WireModel):
    finding_id: UUID
    verdict: Literal["VALIDATED", "REJECTED", "NEEDS_EVIDENCE"]
    evidence_ids: list[UUID] = Field(min_length=1)
    rationale: Text


class ManualReview(ManualReviewCreate, Scoped):
    review_id: UUID
    reviewer_id: UUID
    reviewed_at: UTC


class PrecheckCreate(WireModel):
    plan_id: UUID
    plan_sha256: Hash
    simulation_id: UUID


class Precheck(Scoped):
    precheck_id: UUID
    plan_id: UUID
    plan_sha256: Hash
    status: Literal["READY", "BLOCKED", "EXPIRED"]
    baseline_sha256: Hash
    backup_evidence_ids: list[UUID]
    checked_at: UTC
    expires_at: UTC
    limitations: list[Text]


class ExceptionDecision(WireModel):
    decision: Literal["APPROVED", "REJECTED"]
    reason: Text


class PolicyOverrideCreate(WireModel):
    policy_pack_id: UUID
    base_version: Text
    control_id: Text
    expected: JsonValue
    reason: Text


class PolicyOverride(PolicyOverrideCreate, Scoped):
    override_id: UUID
    version: Text
    author_id: UUID
    created_at: UTC


class ScheduleCreate(WireModel):
    scan: ScanCreate
    cron_utc: Text
    enabled: bool


class Schedule(ScheduleCreate, Scoped):
    schedule_id: UUID


class Trend(WireModel):
    scan_id: UUID
    policy_version: Text
    profile: Text
    at: UTC
    score: Score


class Notification(Scoped):
    notification_id: UUID
    event_id: UUID
    status: Literal["PENDING", "DELIVERED", "FAILED"]
    attempt_count: Count


class IntegrationCreate(WireModel):
    kind: Literal["WEBHOOK", "TICKET"]
    endpoint: Annotated[str, StringConstraints(pattern=r"^https://")]
    credential_reference_id: UUID
    enabled: bool


class Integration(IntegrationCreate, Scoped):
    integration_id: UUID
