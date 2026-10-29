/**
 * BaselineGuard - Typed API Client Interface
 * Adheres strictly to Frozen Contract v1.0.0
 * Binds either to live FastAPI backend (/api/v1) or deterministic DEMO fixture store.
 */

import { fixtureStore } from './store';
import type {
  CanonicalResourceEnvelope,
  CanonicalCollectionEnvelope,
  Organization,
  Asset,
  AssetCreateInput,
  DiscoveredCandidate,
  ScanJob,
  Finding,
  SecurityGraphData,
  RiskScenario,
  RemediationPlan,
  ServiceSafetyContract,
  WhatIfSimulation,
  ApprovalRecord,
  HardeningChange,
  DualVerification,
  ProofPackage,
  GeneratedReport,
  DriftEvent,
  ApplicationAuditEvent,
  ScanSchedule,
  PolicyPack,
  PolicyOverride,
  PolicyVersionDiff,
  PolicyExceptionItem,
  ManualReviewItem,
  ComplianceTrendPoint,
} from '../contracts/v1/types';
import { ExecutionState } from '../contracts/v1/enums';

function wrapResource<T>(data: T): CanonicalResourceEnvelope<T> {
  return {
    schema_version: '1.0.0',
    data,
    meta: {
      request_id: `req-${Math.random().toString(36).substring(2, 10)}`,
    },
  };
}

function wrapCollection<T>(data: T[]): CanonicalCollectionEnvelope<T> {
  return {
    schema_version: '1.0.0',
    data,
    meta: {
      request_id: `req-${Math.random().toString(36).substring(2, 10)}`,
      cursor: {
        next: null,
        prev: null,
        has_more: false,
        total_count: data.length,
      },
    },
  };
}

export interface ApiClientInterface {
  getOrganizations: () => Promise<CanonicalCollectionEnvelope<Organization>>;
  createOrganization: (payload: { name: string; slug: string }) => Promise<CanonicalResourceEnvelope<Organization>>;
  getAssets: (orgId: string) => Promise<CanonicalCollectionEnvelope<Asset>>;
  getAsset: (assetId: string) => Promise<CanonicalResourceEnvelope<Asset>>;
  createAsset: (orgId: string, payload: AssetCreateInput) => Promise<CanonicalResourceEnvelope<Asset>>;
  updateAsset: (assetId: string, payload: Partial<Asset>) => Promise<CanonicalResourceEnvelope<Asset>>;
  retireAsset: (assetId: string) => Promise<CanonicalResourceEnvelope<Asset>>;
  previewDiscovery: (payload: { cidr_ranges: string[]; ports_to_probe: number[]; scope_consent_confirmed: boolean }) => Promise<CanonicalCollectionEnvelope<DiscoveredCandidate>>;
  getScans: (orgId: string) => Promise<CanonicalCollectionEnvelope<ScanJob>>;
  getScan: (scanId: string) => Promise<CanonicalResourceEnvelope<ScanJob>>;
  createScan: (payload: { target_asset_ids: string[]; policy_pack_id: string; profile_level: 'LEVEL_1' | 'LEVEL_2' }) => Promise<CanonicalResourceEnvelope<ScanJob>>;
  retryScan: (scanId: string) => Promise<CanonicalResourceEnvelope<ScanJob>>;
  getSchedules: (orgId: string) => Promise<CanonicalCollectionEnvelope<ScanSchedule>>;
  createSchedule: (payload: { name: string; cron_expression: string; target_asset_group: string; policy_pack_id: string; profile_level: 'LEVEL_1' | 'LEVEL_2' }) => Promise<CanonicalResourceEnvelope<ScanSchedule>>;
  toggleSchedule: (scheduleId: string) => Promise<CanonicalResourceEnvelope<ScanSchedule>>;
  deleteSchedule: (scheduleId: string) => Promise<{ success: boolean }>;
  getPolicyPacks: () => Promise<CanonicalCollectionEnvelope<PolicyPack>>;
  getPolicyOverrides: (orgId: string) => Promise<CanonicalCollectionEnvelope<PolicyOverride>>;
  createPolicyOverride: (payload: Omit<PolicyOverride, 'override_id' | 'org_id' | 'approved_at'>) => Promise<CanonicalResourceEnvelope<PolicyOverride>>;
  deletePolicyOverride: (overrideId: string) => Promise<{ success: boolean }>;
  getPolicyVersionDiff: (packId: string) => Promise<CanonicalResourceEnvelope<PolicyVersionDiff | null>>;
  getPolicyExceptions: (orgId: string) => Promise<CanonicalCollectionEnvelope<PolicyExceptionItem>>;
  createPolicyException: (payload: { finding_id: string; control_id: string; asset_id: string; reason: string; approver_email: string; expires_at: string }) => Promise<CanonicalResourceEnvelope<PolicyExceptionItem>>;
  getManualReviews: (orgId: string) => Promise<CanonicalCollectionEnvelope<ManualReviewItem>>;
  submitManualReview: (payload: { review_id: string; verdict: 'ATTESTED_PASS' | 'ATTESTED_FAIL'; reviewer_email: string; justification: string; evidence_uri: string }) => Promise<CanonicalResourceEnvelope<ManualReviewItem>>;
  getComplianceTrends: () => Promise<CanonicalCollectionEnvelope<ComplianceTrendPoint>>;
  getFindings: (filters?: { assetId?: string; severity?: string; status?: string }) => Promise<CanonicalCollectionEnvelope<Finding>>;
  getFinding: (findingId: string) => Promise<CanonicalResourceEnvelope<Finding>>;
  getSecurityGraph: () => Promise<CanonicalResourceEnvelope<SecurityGraphData>>;
  getRiskScenarios: () => Promise<CanonicalCollectionEnvelope<RiskScenario>>;
  getRemediationPlan: (planId: string) => Promise<CanonicalResourceEnvelope<RemediationPlan>>;
  getSafetyContracts: () => Promise<CanonicalCollectionEnvelope<ServiceSafetyContract>>;
  getSimulation: (simId: string) => Promise<CanonicalResourceEnvelope<WhatIfSimulation>>;
  getApprovals: () => Promise<CanonicalCollectionEnvelope<ApprovalRecord>>;
  approvePlan: (planId: string, payload: { plan_hash: string; justification: string }) => Promise<CanonicalResourceEnvelope<ApprovalRecord>>;
  getChange: (changeId: string) => Promise<CanonicalResourceEnvelope<HardeningChange>>;
  executeChange: (changeId: string) => Promise<CanonicalResourceEnvelope<HardeningChange>>;
  getVerification: (verificationId: string) => Promise<CanonicalResourceEnvelope<DualVerification>>;
  getProofPackage: (packageId: string) => Promise<CanonicalResourceEnvelope<ProofPackage>>;
  getReports: () => Promise<CanonicalCollectionEnvelope<GeneratedReport>>;
  getDriftEvents: () => Promise<CanonicalCollectionEnvelope<DriftEvent>>;
  getAuditEvents: () => Promise<CanonicalCollectionEnvelope<ApplicationAuditEvent>>;
}

export class DemoApiClient implements ApiClientInterface {
  async getOrganizations() {
    return wrapCollection(fixtureStore.organizations);
  }

  async createOrganization(payload: { name: string; slug: string }) {
    const org = fixtureStore.createOrganization(payload.name, payload.slug);
    return wrapResource(org);
  }

  async getAssets(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.assets);
  }

  async getAsset(assetId: string) {
    const asset = fixtureStore.assets.find((a) => a.asset_id === assetId);
    if (!asset) throw new Error(`Asset ${assetId} not found`);
    return wrapResource(asset);
  }

  async createAsset(orgId: string, payload: AssetCreateInput) {
    const asset = fixtureStore.createAsset(orgId, payload);
    return wrapResource(asset);
  }

  async updateAsset(assetId: string, payload: Partial<Asset>) {
    const updated = fixtureStore.updateAsset(assetId, payload);
    return wrapResource(updated);
  }

  async retireAsset(assetId: string) {
    const retired = fixtureStore.retireAsset(assetId);
    return wrapResource(retired);
  }

  async previewDiscovery(payload: { cidr_ranges: string[]; ports_to_probe: number[]; scope_consent_confirmed: boolean }) {
    if (!payload.scope_consent_confirmed) {
      throw new Error('Explicit scope authorization consent is mandatory prior to discovery sweep.');
    }
    const candidates = fixtureStore.previewDiscovery(payload.cidr_ranges, payload.ports_to_probe);
    return wrapCollection(candidates);
  }

  async getScans(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.scans);
  }

  async getScan(scanId: string) {
    const scan = fixtureStore.scans.find((s) => s.scan_id === scanId);
    if (!scan) throw new Error(`Scan ${scanId} not found`);
    return wrapResource(scan);
  }

  async createScan(payload: { target_asset_ids: string[]; policy_pack_id: string; profile_level: 'LEVEL_1' | 'LEVEL_2' }) {
    const newScan: ScanJob = {
      scan_id: `scan-${Date.now()}`,
      org_id: fixtureStore.org.org_id,
      status: 'RUNNING',
      read_only: true,
      requested_assets: payload.target_asset_ids.length,
      completed_assets: 0,
      failed_assets: 0,
      assessed_compliance_pct: 0,
      assessment_coverage_pct: 0,
      policy_pack_id: payload.policy_pack_id,
      profile_level: payload.profile_level,
      target_asset_ids: payload.target_asset_ids,
      started_at: new Date().toISOString(),
      trigger_type: 'MANUAL',
    };
    fixtureStore.scans.unshift(newScan);
    return wrapResource(newScan);
  }

  async retryScan(scanId: string) {
    const retried = fixtureStore.retryScan(scanId);
    return wrapResource(retried);
  }

  async getSchedules(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.scanSchedules);
  }

  async createSchedule(payload: {
    name: string;
    cron_expression: string;
    target_asset_group: string;
    policy_pack_id: string;
    profile_level: 'LEVEL_1' | 'LEVEL_2';
  }) {
    const created = fixtureStore.createSchedule(payload);
    return wrapResource(created);
  }

  async toggleSchedule(scheduleId: string) {
    const toggled = fixtureStore.toggleSchedule(scheduleId);
    return wrapResource(toggled);
  }

  async deleteSchedule(scheduleId: string) {
    fixtureStore.deleteSchedule(scheduleId);
    return { success: true };
  }

  async getPolicyPacks() {
    return wrapCollection(fixtureStore.policyPacks);
  }

  async getPolicyOverrides(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.policyOverrides);
  }

  async createPolicyOverride(payload: Omit<PolicyOverride, 'override_id' | 'org_id' | 'approved_at'>) {
    const created = fixtureStore.createOverride(payload);
    return wrapResource(created);
  }

  async deletePolicyOverride(overrideId: string) {
    fixtureStore.deleteOverride(overrideId);
    return { success: true };
  }

  async getPolicyVersionDiff(packId: string) {
    const diff = fixtureStore.policyVersionDiffs[packId] || null;
    return wrapResource(diff);
  }

  async getPolicyExceptions(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.policyExceptions);
  }

  async createPolicyException(payload: {
    finding_id: string;
    control_id: string;
    asset_id: string;
    reason: string;
    approver_email: string;
    expires_at: string;
  }) {
    const created = fixtureStore.createException(payload);
    return wrapResource(created);
  }

  async getManualReviews(_orgId: string) {
    void _orgId; // DEMO-only getter; no production binding is inferred.
    return wrapCollection(fixtureStore.manualReviews);
  }

  async submitManualReview(payload: {
    review_id: string;
    verdict: 'ATTESTED_PASS' | 'ATTESTED_FAIL';
    reviewer_email: string;
    justification: string;
    evidence_uri: string;
  }) {
    const updated = fixtureStore.submitManualReview(
      payload.review_id,
      payload.verdict,
      payload.reviewer_email,
      payload.justification,
      payload.evidence_uri
    );
    return wrapResource(updated);
  }

  async getComplianceTrends() {
    return wrapCollection(fixtureStore.complianceTrends);
  }

  async getFindings(filters?: { assetId?: string; severity?: string; status?: string }) {
    let findings = fixtureStore.findings;
    if (filters?.assetId) {
      findings = findings.filter((f) => f.asset_id === filters.assetId);
    }
    if (filters?.severity) {
      findings = findings.filter((f) => f.severity === filters.severity);
    }
    if (filters?.status) {
      findings = findings.filter((f) => f.status === filters.status);
    }
    return wrapCollection(findings);
  }

  async getFinding(findingId: string) {
    const finding = fixtureStore.findings.find((f) => f.finding_id === findingId);
    if (!finding) throw new Error(`Finding ${findingId} not found`);
    return wrapResource(finding);
  }

  async getSecurityGraph() {
    return wrapResource(fixtureStore.securityGraph);
  }

  async getRiskScenarios() {
    return wrapCollection(fixtureStore.riskScenarios);
  }

  async getRemediationPlan(planId: string) {
    if (fixtureStore.remediationPlan.plan_id !== planId) {
      throw new Error(`Remediation plan ${planId} not found`);
    }
    return wrapResource(fixtureStore.remediationPlan);
  }

  async getSafetyContracts() {
    return wrapCollection(fixtureStore.safetyContracts);
  }

  async getSimulation(_simId: string) {
    void _simId; // DEMO-only getter; no production binding is inferred.
    return wrapResource(fixtureStore.whatIfSimulation);
  }

  async getApprovals() {
    return wrapCollection(fixtureStore.approvals);
  }

  async approvePlan(planId: string, payload: { plan_hash: string; justification: string }) {
    const approval: ApprovalRecord = {
      approval_id: `appr-${Date.now()}`,
      plan_id: planId,
      plan_hash: payload.plan_hash,
      approver_id: 'usr-ciso-01',
      approver_email: 'ciso@acmefinancial.com',
      operator_id: 'usr-secops-02',
      justification: payload.justification,
      safety_contracts_passed: true,
      backup_readiness_confirmed: true,
      status: 'APPROVED',
      approved_at: new Date().toISOString(),
    };
    fixtureStore.approvals.unshift(approval);
    fixtureStore.remediationPlan.state = ExecutionState.APPROVED;
    return wrapResource(approval);
  }

  async getChange(_changeId: string) {
    void _changeId; // DEMO-only getter; no production binding is inferred.
    return wrapResource(fixtureStore.hardeningChange);
  }

  async executeChange(_changeId: string) {
    void _changeId; // DEMO-only getter; no production binding is inferred.
    fixtureStore.hardeningChange.state = ExecutionState.EXECUTING;
    return wrapResource(fixtureStore.hardeningChange);
  }

  async getVerification(_verificationId: string) {
    void _verificationId; // DEMO-only getter; no production binding is inferred.
    return wrapResource(fixtureStore.dualVerification);
  }

  async getProofPackage(_packageId: string) {
    void _packageId; // DEMO-only getter; no production binding is inferred.
    return wrapResource(fixtureStore.proofPackage);
  }

  async getReports() {
    return wrapCollection(fixtureStore.reports);
  }

  async getDriftEvents() {
    return wrapCollection(fixtureStore.driftEvents);
  }

  async getAuditEvents() {
    return wrapCollection(fixtureStore.auditEvents);
  }
}
