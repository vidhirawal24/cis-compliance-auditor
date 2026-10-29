/**
 * BaselineGuard - Deterministic In-Memory Fixture Store
 * [DEMO - SYNTHETIC DATA STORE]
 * Provides mockable state for all 19 screen families without inventing device results.
 */

import {
  DEMO_ORG_ID,
  DEMO_ORGANIZATION,
  DEMO_ASSETS,
  DEMO_SWITCH_INTERFACES,
  DEMO_SCANS,
  DEMO_FINDINGS,
  DEMO_SECURITY_GRAPH,
  DEMO_RISK_SCENARIOS,
  DEMO_REMEDIATION_PLAN,
  DEMO_SAFETY_CONTRACTS,
  DEMO_WHAT_IF_SIMULATION,
  DEMO_APPROVAL_RECORD,
  DEMO_HARDENING_CHANGE,
  DEMO_DUAL_VERIFICATION,
  DEMO_PROOF_PACKAGE,
  DEMO_DRIFT_EVENTS,
  DEMO_REPORTS,
  DEMO_AUDIT_TRAIL,
  DEMO_SCAN_SCHEDULES,
  DEMO_POLICY_PACKS,
  DEMO_COMPLIANCE_TRENDS,
  DEMO_POLICY_OVERRIDES,
  DEMO_POLICY_VERSION_DIFFS,
  DEMO_POLICY_EXCEPTIONS,
  DEMO_MANUAL_REVIEWS,
} from '../fixtures/demoData';

import { PlatformFamily, UserRole } from '../contracts/v1/enums';

import type {
  Organization,
  Asset,
  AssetCreateInput,
  DiscoveredCandidate,
  ScanJob,
  ScanSchedule,
  PolicyPack,
  PolicyOverride,
  PolicyVersionDiff,
  PolicyExceptionItem,
  ManualReviewItem,
  ComplianceTrendPoint,
  Finding,
  RemediationPlan,
  ServiceSafetyContract,
  WhatIfSimulation,
  ApprovalRecord,
  HardeningChange,
  DualVerification,
  ProofPackage,
  GeneratedReport,
  DriftEvent,
} from '../contracts/v1/types';

class FixtureStore {
  public defaultOrgId = DEMO_ORG_ID;
  public org = DEMO_ORGANIZATION;
  public organizations: Organization[] = [
    DEMO_ORGANIZATION,
    {
      org_id: 'org-health-staging',
      name: 'Healthcare DMZ Staging',
      slug: 'health-dmz-staging',
      created_at: '2026-02-01T00:00:00Z',
      role: UserRole.VIEWER,
      is_active: true,
    },
  ];
  public assets: Asset[] = [...DEMO_ASSETS];
  public switchInterfaces = [...DEMO_SWITCH_INTERFACES];
  public scans: ScanJob[] = [...DEMO_SCANS];
  public scanSchedules: ScanSchedule[] = [...DEMO_SCAN_SCHEDULES];
  public policyPacks: PolicyPack[] = [...DEMO_POLICY_PACKS];
  public complianceTrends: ComplianceTrendPoint[] = [...DEMO_COMPLIANCE_TRENDS];
  public policyOverrides: PolicyOverride[] = [...DEMO_POLICY_OVERRIDES];
  public policyVersionDiffs: Record<string, PolicyVersionDiff> = { ...DEMO_POLICY_VERSION_DIFFS };
  public policyExceptions: PolicyExceptionItem[] = [...DEMO_POLICY_EXCEPTIONS];
  public manualReviews: ManualReviewItem[] = [...DEMO_MANUAL_REVIEWS];
  public findings: Finding[] = [...DEMO_FINDINGS];
  public securityGraph = { ...DEMO_SECURITY_GRAPH };
  public riskScenarios = [...DEMO_RISK_SCENARIOS];
  public remediationPlan: RemediationPlan = { ...DEMO_REMEDIATION_PLAN };
  public safetyContracts: ServiceSafetyContract[] = [...DEMO_SAFETY_CONTRACTS];
  public whatIfSimulation: WhatIfSimulation = { ...DEMO_WHAT_IF_SIMULATION };
  public approvals: ApprovalRecord[] = [{ ...DEMO_APPROVAL_RECORD }];
  public hardeningChange: HardeningChange = { ...DEMO_HARDENING_CHANGE };
  public dualVerification: DualVerification = { ...DEMO_DUAL_VERIFICATION };
  public proofPackage: ProofPackage = { ...DEMO_PROOF_PACKAGE };
  public driftEvents: DriftEvent[] = [...DEMO_DRIFT_EVENTS];
  public reports: GeneratedReport[] = [...DEMO_REPORTS];
  public auditEvents = [...DEMO_AUDIT_TRAIL];

  public createAsset(orgId: string, input: AssetCreateInput): Asset {
    const assetId = `a${String(this.assets.length + 1).padStart(2, '0')}-${input.hostname.toLowerCase().replace(/[^a-z0-9]/g, '-').slice(0, 16)}`;
    const newAsset: Asset = {
      ...input,
      asset_id: assetId,
      org_id: orgId,
      created_at: new Date().toISOString(),
    };
    this.assets.unshift(newAsset);
    return newAsset;
  }

  public updateAsset(assetId: string, updates: Partial<Asset>): Asset {
    const index = this.assets.findIndex((a) => a.asset_id === assetId);
    if (index === -1) {
      throw new Error(`Asset ${assetId} not found`);
    }
    const updated = { ...this.assets[index], ...updates };
    this.assets[index] = updated;
    return updated;
  }

  public retireAsset(assetId: string): Asset {
    const index = this.assets.findIndex((a) => a.asset_id === assetId);
    if (index === -1) {
      throw new Error(`Asset ${assetId} not found`);
    }
    const retired = this.assets[index];
    this.assets.splice(index, 1);
    return retired;
  }

  public createOrganization(name: string, slug: string): Organization {
    const newOrg: Organization = {
      org_id: `org-${Date.now()}`,
      name,
      slug,
      created_at: new Date().toISOString(),
      role: UserRole.OWNER,
      is_active: true,
    };
    this.organizations.push(newOrg);
    return newOrg;
  }

  public previewDiscovery(cidrRanges: string[], portsToProbe: number[]): DiscoveredCandidate[] {
    const baseOctets = cidrRanges[0]?.split('/')[0]?.split('.')?.slice(0, 3)?.join('.') || '192.168.10';
    return [
      {
        ip: `${baseOctets}.45`,
        open_ports: portsToProbe.filter((p) => [22, 443].includes(p)),
        estimated_platform: PlatformFamily.CISCO_IOS_SWITCH,
        mac_vendor: 'Cisco Systems',
        response_time_ms: 4,
      },
      {
        ip: `${baseOctets}.88`,
        open_ports: portsToProbe.filter((p) => [443, 80].includes(p)),
        estimated_platform: PlatformFamily.FORTINET_FORTIOS,
        mac_vendor: 'Fortinet Technologies',
        response_time_ms: 7,
      },
      {
        ip: `${baseOctets}.112`,
        open_ports: portsToProbe.filter((p) => [445, 3389].includes(p)),
        estimated_platform: PlatformFamily.WINDOWS_SERVER_2019,
        mac_vendor: 'Dell Inc.',
        response_time_ms: 12,
      },
    ];
  }

  public createSchedule(input: {
    name: string;
    cron_expression: string;
    target_asset_group: string;
    policy_pack_id: string;
    profile_level: 'LEVEL_1' | 'LEVEL_2';
  }): ScanSchedule {
    const newSchedule: ScanSchedule = {
      schedule_id: `sched-${Date.now()}`,
      org_id: this.defaultOrgId,
      name: input.name,
      cron_expression: input.cron_expression,
      target_asset_group: input.target_asset_group,
      policy_pack_id: input.policy_pack_id,
      profile_level: input.profile_level,
      is_active: true,
      next_run_at: new Date(Date.now() + 86400000).toISOString(),
    };
    this.scanSchedules.unshift(newSchedule);
    return newSchedule;
  }

  public toggleSchedule(scheduleId: string): ScanSchedule {
    const schedule = this.scanSchedules.find((s) => s.schedule_id === scheduleId);
    if (!schedule) throw new Error(`Schedule ${scheduleId} not found`);
    schedule.is_active = !schedule.is_active;
    return schedule;
  }

  public deleteSchedule(scheduleId: string): void {
    const idx = this.scanSchedules.findIndex((s) => s.schedule_id === scheduleId);
    if (idx !== -1) {
      this.scanSchedules.splice(idx, 1);
    }
  }

  public retryScan(scanId: string): ScanJob {
    const existing = this.scans.find((s) => s.scan_id === scanId);
    if (!existing) throw new Error(`Scan ${scanId} not found`);

    const retriedScan: ScanJob = {
      scan_id: `scan-${Date.now()}`,
      org_id: existing.org_id,
      status: 'RUNNING',
      read_only: true,
      requested_assets: existing.requested_assets,
      completed_assets: 0,
      failed_assets: 0,
      assessed_compliance_pct: 0,
      assessment_coverage_pct: 0,
      policy_pack_id: existing.policy_pack_id,
      profile_level: existing.profile_level,
      target_asset_ids: [...existing.target_asset_ids],
      started_at: new Date().toISOString(),
      trigger_type: 'MANUAL',
    };
    this.scans.unshift(retriedScan);
    return retriedScan;
  }

  // -----------------------------------------------------------
  // Phase 4: Policy Overrides, Exceptions & Manual Reviews
  // -----------------------------------------------------------

  public createOverride(input: Omit<PolicyOverride, 'override_id' | 'org_id' | 'approved_at'>): PolicyOverride {
    const newOverride: PolicyOverride = {
      override_id: `ovr-${Date.now()}`,
      org_id: this.defaultOrgId,
      ...input,
      approved_at: new Date().toISOString(),
    };
    this.policyOverrides.unshift(newOverride);
    return newOverride;
  }

  public deleteOverride(overrideId: string): void {
    const idx = this.policyOverrides.findIndex((o) => o.override_id === overrideId);
    if (idx !== -1) {
      this.policyOverrides.splice(idx, 1);
    }
  }

  public createException(input: {
    finding_id: string;
    control_id: string;
    asset_id: string;
    reason: string;
    approver_email: string;
    expires_at: string;
  }): PolicyExceptionItem {
    const targetAsset = this.assets.find((a) => a.asset_id === input.asset_id);
    const isExpired = new Date(input.expires_at).getTime() < Date.now();

    const newException: PolicyExceptionItem = {
      exception_id: `exc-${Date.now()}`,
      org_id: this.defaultOrgId,
      finding_id: input.finding_id,
      control_id: input.control_id,
      asset_id: input.asset_id,
      hostname: targetAsset?.hostname || input.asset_id,
      reason: input.reason,
      approver_email: input.approver_email,
      approved_at: new Date().toISOString(),
      expires_at: input.expires_at,
      is_expired: isExpired,
      status: isExpired ? 'EXPIRED' : 'ACTIVE',
    };

    this.policyExceptions.unshift(newException);

    // Overlay exception onto finding in store without altering violation status (E14 Invariant)
    const finding = this.findings.find((f) => f.finding_id === input.finding_id);
    if (finding) {
      finding.exception = {
        exception_id: newException.exception_id,
        reason: newException.reason,
        approver_email: newException.approver_email,
        approved_at: newException.approved_at,
        expires_at: newException.expires_at,
        is_expired: isExpired,
      };
      // Explicit rule: exception DOES NOT turn finding status into PASS!
    }

    return newException;
  }

  public submitManualReview(
    reviewId: string,
    verdict: 'ATTESTED_PASS' | 'ATTESTED_FAIL',
    reviewerEmail: string,
    justification: string,
    evidenceUri: string
  ): ManualReviewItem {
    const review = this.manualReviews.find((r) => r.review_id === reviewId);
    if (!review) throw new Error(`Manual review ${reviewId} not found`);

    review.status = verdict;
    review.reviewer_email = reviewerEmail;
    review.justification = justification;
    review.attestation_evidence_uri = evidenceUri;
    review.submitted_at = new Date().toISOString();

    return review;
  }

  // Helper to reset to pristine synthetic state
  public reset() {
    this.assets = [...DEMO_ASSETS];
    this.scans = [...DEMO_SCANS];
    this.scanSchedules = [...DEMO_SCAN_SCHEDULES];
    this.policyPacks = [...DEMO_POLICY_PACKS];
    this.complianceTrends = [...DEMO_COMPLIANCE_TRENDS];
    this.policyOverrides = [...DEMO_POLICY_OVERRIDES];
    this.policyVersionDiffs = { ...DEMO_POLICY_VERSION_DIFFS };
    this.policyExceptions = [...DEMO_POLICY_EXCEPTIONS];
    this.manualReviews = [...DEMO_MANUAL_REVIEWS];
    this.findings = [...DEMO_FINDINGS];
    this.remediationPlan = { ...DEMO_REMEDIATION_PLAN };
    this.safetyContracts = [...DEMO_SAFETY_CONTRACTS];
    this.organizations = [
      DEMO_ORGANIZATION,
      {
        org_id: 'org-health-staging',
        name: 'Healthcare DMZ Staging',
        slug: 'health-dmz-staging',
        created_at: '2026-02-01T00:00:00Z',
        role: UserRole.VIEWER,
        is_active: true,
      },
    ];
  }
}

export const fixtureStore = new FixtureStore();

