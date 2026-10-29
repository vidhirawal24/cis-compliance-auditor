/**
 * BaselineGuard - Typed API Client Interface
 * Adheres strictly to Frozen Contract v1.0.0
 * Binds either to live FastAPI backend (/api/v1) or deterministic DEMO fixture store.
 */

import { fixtureStore } from './store';
import type {
  CanonicalResourceEnvelope,
  CanonicalCollectionEnvelope,
  Asset,
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
  getAssets: (orgId: string) => Promise<CanonicalCollectionEnvelope<Asset>>;
  getAsset: (assetId: string) => Promise<CanonicalResourceEnvelope<Asset>>;
  getScans: (orgId: string) => Promise<CanonicalCollectionEnvelope<ScanJob>>;
  getScan: (scanId: string) => Promise<CanonicalResourceEnvelope<ScanJob>>;
  createScan: (payload: { target_asset_ids: string[]; policy_pack_id: string; profile_level: 'LEVEL_1' | 'LEVEL_2' }) => Promise<CanonicalResourceEnvelope<ScanJob>>;
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
  async getAssets(_orgId: string) {
    return wrapCollection(fixtureStore.assets);
  }

  async getAsset(assetId: string) {
    const asset = fixtureStore.assets.find((a) => a.asset_id === assetId);
    if (!asset) throw new Error(`Asset ${assetId} not found`);
    return wrapResource(asset);
  }

  async getScans(_orgId: string) {
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
    return wrapResource(fixtureStore.hardeningChange);
  }

  async executeChange(_changeId: string) {
    fixtureStore.hardeningChange.state = ExecutionState.EXECUTING;
    return wrapResource(fixtureStore.hardeningChange);
  }

  async getVerification(_verificationId: string) {
    return wrapResource(fixtureStore.dualVerification);
  }

  async getProofPackage(_packageId: string) {
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

export const apiClient: ApiClientInterface = new DemoApiClient();

