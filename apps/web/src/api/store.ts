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
} from '../fixtures/demoData';

import type {
  Asset,
  ScanJob,
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
  public assets: Asset[] = [...DEMO_ASSETS];
  public switchInterfaces = [...DEMO_SWITCH_INTERFACES];
  public scans: ScanJob[] = [...DEMO_SCANS];
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

  // Helper to reset to pristine synthetic state
  public reset() {
    this.assets = [...DEMO_ASSETS];
    this.scans = [...DEMO_SCANS];
    this.findings = [...DEMO_FINDINGS];
    this.remediationPlan = { ...DEMO_REMEDIATION_PLAN };
    this.safetyContracts = [...DEMO_SAFETY_CONTRACTS];
  }
}

export const fixtureStore = new FixtureStore();

