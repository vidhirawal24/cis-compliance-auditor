import { EvaluationStatus, ExecutionState } from '../../contracts/v1/enums';
import type { ApprovalRecord, DualVerification, HardeningChange, RemediationPlan } from '../../contracts/v1/types';

export function approvalState(record: ApprovalRecord, plan: RemediationPlan, snapshot?: RemediationPlan): string {
  if (record.plan_id !== plan.plan_id || record.plan_hash !== plan.plan_hash ||
      (snapshot && JSON.stringify(snapshot) !== JSON.stringify(plan))) return 'STALE';
  if (record.operator_id === record.approver_id) return 'INVALID_SEPARATION_OF_DUTIES';
  return record.status;
}

export function verificationOutcome(change: HardeningChange, verification: DualVerification): string {
  if (change.change_id !== verification.change_id) return 'INSUFFICIENT_EVIDENCE';
  if (verification.cis_control_status === EvaluationStatus.FAIL || verification.service_probe_status === EvaluationStatus.FAIL || change.state === ExecutionState.FAILED) return 'FAILED';
  if (verification.cis_control_status === EvaluationStatus.NOT_APPLICABLE || verification.service_probe_status === EvaluationStatus.NOT_APPLICABLE) return 'UNSUPPORTED';
  if (verification.cis_control_status === EvaluationStatus.NOT_ASSESSED || verification.service_probe_status === EvaluationStatus.NOT_ASSESSED || verification.cis_control_status === EvaluationStatus.MANUAL_REVIEW || verification.service_probe_status === EvaluationStatus.MANUAL_REVIEW) return 'INSUFFICIENT_EVIDENCE';
  if (change.state === ExecutionState.VERIFIED && verification.overall_verified === true && verification.cis_control_status === EvaluationStatus.PASS && verification.service_probe_status === EvaluationStatus.PASS) return 'SUCCESS';
  return 'UNKNOWN';
}

export const validHash = (value?: string) => !!value && /^[a-f0-9]{64}$/i.test(value);
