/**
 * BaselineGuard - Frozen Client Contract v1.0.0 Types
 * Source: Playbook v1.0, PRD v1.0 & Tech Stack v3.0
 * Strict TypeScript types for typed API client and fixtures
 */

import {
  EvaluationStatus,
  SeverityLevel,
  PlatformFamily,
  SimulationVerdict,
  ExecutionState,
  UserRole,
  CollectionMethod,
  ReportFormat,
} from './enums';

// -------------------------------------------------------------
// Canonical Envelopes & Common Types
// -------------------------------------------------------------

export interface CanonicalMeta {
  request_id: string;
  cursor?: {
    next: string | null;
    prev: string | null;
    has_more: boolean;
    total_count?: number;
  };
}

export interface CanonicalResourceEnvelope<T> {
  schema_version: '1.0.0';
  data: T;
  meta: CanonicalMeta;
}

export interface CanonicalCollectionEnvelope<T> {
  schema_version: '1.0.0';
  data: T[];
  meta: CanonicalMeta;
}

export interface CanonicalApiError {
  code: string;
  message: string;
  request_id: string;
  details?: Record<string, unknown>;
  retryable: boolean;
}

// -------------------------------------------------------------
// Evidence & Provenance (M12, M14, M15, SEC-07, SEC-12)
// -------------------------------------------------------------

export interface EvidenceRef {
  sha256: string;
  source_command: string;
  artifact_uri: string;
  timestamp: string; // ISO 8601 UTC
}

export interface NormalizedEvidence {
  schema_version: '1.0.0';
  org_id: string;
  asset_id: string;
  platform: PlatformFamily;
  vendor: string;
  model: string;
  os_or_firmware_version: string;
  collector_version: string;
  collection_method: CollectionMethod;
  collected_at: string; // ISO 8601 UTC
  facts: Record<string, unknown>;
  evidence_refs: EvidenceRef[];
  supported_capabilities: string[];
  unsupported_capabilities: string[];
  errors: string[];
}

// -------------------------------------------------------------
// Identity & Organizations (SEC-01, SEC-02, E15)
// -------------------------------------------------------------

export interface Organization {
  org_id: string;
  name: string;
  slug: string;
  created_at: string;
  role: UserRole;
  is_active: boolean;
}

export interface OrganizationMember {
  user_id: string;
  org_id: string;
  email: string;
  role: UserRole;
  mfa_enabled: boolean;
  last_login_at: string;
}

// -------------------------------------------------------------
// Assets & Inventory (E01, E02, E03, E17)
// -------------------------------------------------------------

export interface AssetInterface {
  interface_id: string;
  name: string;
  mac_address: string;
  ipv4_address?: string;
  ipv6_address?: string;
  subnet_mask?: string;
  vlan_id?: number;
  is_management: boolean;
  port_security_enabled?: boolean;
  max_mac_count?: number;
  is_unused_disabled?: boolean;
}

export interface Asset {
  asset_id: string;
  org_id: string;
  hostname: string;
  primary_ip: string;
  platform: PlatformFamily;
  vendor: string;
  model: string;
  os_or_firmware_version: string;
  site: string;
  environment: 'production' | 'staging' | 'lab';
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  tags: string[];
  credential_reference_id: string; // OpenBao reference, e.g. "vault:sec-01" (never secret text)
  last_scan_id?: string;
  last_scan_status?: EvaluationStatus;
  last_assessed_at?: string;
  is_offline_fixture?: boolean;
  created_at: string;
}

export type AssetCreateInput = Omit<Asset, 'asset_id' | 'org_id' | 'created_at'>;

export interface DiscoveredCandidate {
  ip: string;
  open_ports: number[];
  estimated_platform?: PlatformFamily;
  mac_vendor?: string;
  response_time_ms: number;
}

// -------------------------------------------------------------
// Audit Queue & Scans (M13, E04, E08, E18)
// -------------------------------------------------------------

export interface ScanJob {
  scan_id: string;
  org_id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  read_only: true; // Invariant: scans are strictly read-only
  requested_assets: number;
  completed_assets: number;
  failed_assets: number;
  assessed_compliance_pct: number; // PASS / (PASS + FAIL) * 100
  assessment_coverage_pct: number; // (PASS + FAIL) / Total Applicable * 100
  policy_pack_id: string;
  profile_level: 'LEVEL_1' | 'LEVEL_2';
  target_asset_ids: string[];
  started_at: string;
  completed_at?: string;
  trigger_type: 'MANUAL' | 'SCHEDULED' | 'OFFLINE_UPLOAD';
  target_errors?: Array<{ asset_id: string; hostname?: string; error: string }>;
}

export interface ComplianceTrendPoint {
  date: string;
  assessed_compliance_pct: number;
  assessment_coverage_pct: number;
  critical_findings: number;
  high_findings: number;
}

export interface ScanSchedule {
  schedule_id: string;
  org_id: string;
  name: string;
  cron_expression: string;
  target_asset_group: string;
  policy_pack_id: string;
  profile_level: 'LEVEL_1' | 'LEVEL_2';
  is_active: boolean;
  last_run_at?: string;
  next_run_at: string;
}

// -------------------------------------------------------------
// Policy Library & Rules (M16, M17, M18, M19, E11, E20, I19)
// -------------------------------------------------------------

export interface PolicyRule {
  rule_id: string;
  control_id: string;
  title: string;
  description: string;
  rationale: string;
  profile_level: 'LEVEL_1' | 'LEVEL_2';
  category: string;
  severity: SeverityLevel;
  evaluation_operator: 'equals' | 'contains' | 'regex' | 'range' | 'set_membership' | 'cidr_contains' | 'ordered_acl';
  expected_value: unknown;
  remediation_cli_template?: string;
  remediation_prerequisites?: string[];
  remediation_risk_warning?: string;
  requires_manual_review: boolean;
  unsupported_content_warning?: string;
}

export interface PolicyOverride {
  override_id: string;
  org_id: string;
  policy_pack_id: string;
  control_id: string;
  rule_title: string;
  benchmark_value: unknown;
  override_value: unknown;
  rationale: string;
  approved_by: string;
  approved_at: string;
}

export interface PolicyVersionDiff {
  pack_id: string;
  pack_name: string;
  from_version: string;
  to_version: string;
  added_rules: PolicyRule[];
  removed_rules: Array<{ control_id: string; title: string; rationale: string }>;
  modified_rules: Array<{
    control_id: string;
    title: string;
    change_type: 'SEVERITY' | 'OPERATOR' | 'EXPECTED_VALUE' | 'PROFILE_LEVEL';
    old_value: unknown;
    new_value: unknown;
    upgrade_impact: string;
  }>;
  predicted_compliance_impact_pct: number;
  affected_devices_count: number;
}

export interface PolicyExceptionItem {
  exception_id: string;
  org_id: string;
  finding_id: string;
  control_id: string;
  asset_id: string;
  hostname: string;
  reason: string;
  approver_email: string;
  approved_at: string;
  expires_at: string;
  is_expired: boolean;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
}

export interface PolicyPack {
  policy_pack_id: string;
  name: string;
  version: string;
  publisher: string;
  platform: PlatformFamily;
  profiles: Array<'LEVEL_1' | 'LEVEL_2'>;
  total_rules_count: number;
  rules?: PolicyRule[];
  is_custom_baseline: boolean;
  created_at: string;
}

// -------------------------------------------------------------
// Findings & Side-by-Side Detail (M35, M36, M37, E12, E14, E29)
// -------------------------------------------------------------

export interface FindingException {
  exception_id: string;
  reason: string;
  approver_email: string;
  approved_at: string;
  expires_at: string;
  is_expired: boolean;
}

export interface Finding {
  finding_id: string;
  org_id: string;
  asset_id: string;
  scan_id: string;
  control_id: string;
  benchmark_pack_id: string;
  profile_level: 'LEVEL_1' | 'LEVEL_2';
  title: string;
  category: string;
  severity: SeverityLevel;
  status: EvaluationStatus;
  expected_state: Record<string, unknown>;
  observed_state: Record<string, unknown>;
  evidence_ref: EvidenceRef;
  exception?: FindingException; // Overlay badge; does NOT turn FAIL into PASS
  remediation_cli?: string;
  remediation_prerequisites?: string[];
  remediation_risk_warning?: string;
  requires_manual_review: boolean;
  evaluated_at: string;
}

export interface ManualReviewItem {
  review_id: string;
  finding_id: string;
  control_id: string;
  asset_id: string;
  status: 'PENDING' | 'ATTESTED_PASS' | 'ATTESTED_FAIL';
  reviewer_email?: string;
  attestation_evidence_uri?: string;
  justification?: string;
  submitted_at?: string;
}

// -------------------------------------------------------------
// Security Graph & Cross-Layer Risk (I01, I02, I03, I04, I05)
// -------------------------------------------------------------

export interface CytoscapeNodeData {
  id: string;
  label: string;
  type: 'asset' | 'interface' | 'subnet' | 'service' | 'finding';
  platform?: PlatformFamily;
  ip_address?: string;
  cidr?: string;
  port?: number;
  severity?: SeverityLevel;
  status?: EvaluationStatus;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  relation: 'hosted_on' | 'attached_to' | 'routes_to' | 'allows' | 'denies' | 'violates';
  evidence_ref?: string;
  confidence: 'CONFIRMED' | 'SUSPECTED';
}

export interface SecurityGraphData {
  nodes: Array<{ data: CytoscapeNodeData }>;
  edges: Array<{ data: CytoscapeEdgeData }>;
  meta: {
    total_nodes: number;
    total_edges: number;
    coverage_completeness_pct: number;
  };
}

export interface RiskScenario {
  scenario_id: string;
  org_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  risk_score: number; // 0 - 100
  source_finding_ids: string[];
  affected_asset_ids: string[];
  causal_chain: string[];
  confidence_pct: number;
  business_impact: string;
}

// -------------------------------------------------------------
// Remediation Planner & What-If Simulation (I06 - I14)
// -------------------------------------------------------------

export interface RemediationAction {
  action_id: string;
  asset_id: string;
  vendor: string;
  title: string;
  command_template: string; // Read-only preview text; browser cannot execute arbitrary CLI
  sequence_order: number;
  risk_weight: number;
  is_reversible: boolean;
  recovery_plan?: string;
  prerequisites: string[];
  status: 'PENDING' | 'EXECUTING' | 'SUCCESS' | 'FAILED';
}

export interface RemediationPlan {
  plan_id: string;
  org_id: string;
  state: ExecutionState;
  plan_hash: string; // SHA-256 bound to plan contents
  target_asset_ids: string[];
  actions: RemediationAction[];
  minimal_change_score: number;
  conflict_detected: boolean;
  conflicts: string[];
  created_at: string;
}

export interface ServiceSafetyContract {
  contract_id: string;
  org_id: string;
  name: string;
  description: string;
  source_cidr: string;
  destination_cidr: string;
  port_range: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  mandatory: boolean; // If mandatory and violated, approval path is hard-blocked (I14)
  active: boolean;
}

export interface WhatIfSimulation {
  simulation_id: string;
  plan_id: string;
  verdict: SimulationVerdict;
  model_engine: 'BATFISH' | 'CUSTOM_SEMANTICS';
  model_coverage_pct: number;
  safety_contracts_evaluated: number;
  safety_contracts_violated: number;
  affected_services: string[];
  blast_radius_asset_count: number;
  created_at: string;
}

// -------------------------------------------------------------
// Approvals & Hardening Execution (E21, E23, E24, I15)
// -------------------------------------------------------------

export interface ApprovalRecord {
  approval_id: string;
  plan_id: string;
  plan_hash: string;
  approver_id: string;
  approver_email: string;
  operator_id: string; // Must differ from approver_id (Separation of Duties)
  justification: string;
  safety_contracts_passed: boolean;
  backup_readiness_confirmed: boolean;
  status: 'APPROVED' | 'REJECTED' | 'EXPIRED';
  approved_at?: string;
}

export interface HardeningChange {
  change_id: string;
  plan_id: string;
  state: ExecutionState;
  current_stage_batch: number;
  total_stage_batches: number;
  backup_snapshot_hash: string;
  canary_halt_triggered: boolean;
  execution_events: Array<{
    timestamp: string;
    stage: string;
    status: string;
    message: string;
  }>;
}

// -------------------------------------------------------------
// Verification & Proof Dossier (E25, I16, I17, I18)
// -------------------------------------------------------------

export interface DualVerification {
  verification_id: string;
  change_id: string;
  cis_control_status: EvaluationStatus; // Re-audit CIS outcome
  service_probe_status: EvaluationStatus; // Live service reachability check
  overall_verified: boolean; // Both must be PASS for overall SUCCESS
  residual_risk_score: number;
  pre_change_risk_score: number;
  verified_at: string;
}

export interface ProofPackage {
  package_id: string;
  change_id: string;
  org_id: string;
  digital_signature: string;
  signer_identity: string;
  pre_hardening_config_hash: string;
  post_hardening_config_hash: string;
  execution_log_hash: string;
  manifest_verified: boolean;
  created_at: string;
  download_urls: {
    pdf: string;
    json: string;
  };
}

// -------------------------------------------------------------
// Reports, Drift & Audit Trail (M38, E05, E06, E07, E19, E28)
// -------------------------------------------------------------

export interface GeneratedReport {
  report_id: string;
  org_id: string;
  title: string;
  format: ReportFormat;
  file_size_bytes: number;
  download_url: string;
  signed_url_expires_at: string;
  created_at: string;
}

export interface ConfigSnapshot {
  snapshot_id: string;
  asset_id: string;
  sha256_hash: string;
  created_at: string;
  is_drift_detected: boolean;
  raw_content_preview?: string;
}

export interface DriftEvent {
  event_id: string;
  org_id: string;
  asset_id: string;
  hostname: string;
  detected_at: string;
  severity: SeverityLevel;
  diff_preview: string;
  previous_snapshot_id: string;
  current_snapshot_id: string;
}

export interface ApplicationAuditEvent {
  event_id: string;
  org_id: string;
  actor_id: string;
  actor_email: string;
  action_type: string;
  target_resource_id: string;
  timestamp: string;
  ip_address: string;
  sha256_hash: string;
}

