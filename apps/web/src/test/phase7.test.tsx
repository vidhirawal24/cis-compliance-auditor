import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { DemoApiClient } from '../api/client';
import { fixtureStore } from '../api/store';
import { ExecutionState, EvaluationStatus, UserRole } from '../contracts/v1/enums';
import { ApprovalsHardeningShell } from '../routes/shells/14_ApprovalsHardeningShell';
import { VerificationProofShell } from '../routes/shells/15_VerificationProofShell';
import { approvalState, verificationOutcome } from '../features/phase7/review';
import { updateSession } from '../features/phase6/model';
import { DEMO_ORG_ID, DEMO_REMEDIATION_PLAN, DEMO_APPROVAL_RECORD, DEMO_DUAL_VERIFICATION, DEMO_HARDENING_CHANGE } from '../fixtures/demoData';
import { renderWorkspace } from './renderWorkspace';

beforeEach(() => { fixtureStore.reset(); updateSession(DEMO_ORG_ID, { selected: 'balanced', preview: null, dirty: false }); vi.restoreAllMocks(); });

describe('Phase 7 - E21-E25, I14-I18', () => {
  it.each([UserRole.APPROVER, UserRole.OPERATOR])('shows %s role restrictions and backend authority', async role => {
    renderWorkspace(<ApprovalsHardeningShell />, { role });
    expect(await screen.findByText(/Current role:/)).toHaveTextContent(role);
    expect(await screen.findByRole('button', { name: role === UserRole.APPROVER ? 'Approve plan - unavailable' : 'Approval requires approver role' })).toBeDisabled();
    expect(screen.getByText(/Server authorization and separation/)).toBeInTheDocument();
  });
  it.each([401, 403])('displays HTTP %s without falling back to fixtures', async status => {
    const api = new DemoApiClient(); vi.spyOn(api, 'getApprovals').mockRejectedValue({ status });
    renderWorkspace(<ApprovalsHardeningShell />, { api });
    expect(await screen.findByText(new RegExp(`${status} ${status === 403 ? 'Forbidden' : 'Unauthorized'}`))).toBeInTheDocument();
    expect(screen.queryByText(/Approval ID:/)).not.toBeInTheDocument();
  });
  it('captures immutable plan contents and detects changes even if the hash is reused', async () => {
    const api = new DemoApiClient(); const view = renderWorkspace(<ApprovalsHardeningShell />, { api });
    expect(await screen.findByText('Immutable review snapshot')).toBeInTheDocument();
    fixtureStore.remediationPlan = { ...DEMO_REMEDIATION_PLAN, actions: DEMO_REMEDIATION_PLAN.actions.map((a, i) => i ? a : { ...a, title: 'Changed unsafe step' }) };
    await view.client.invalidateQueries({ queryKey: ['phase6'] });
    expect(await screen.findByText(/STALE: underlying plan contents changed/)).toBeInTheDocument();
    expect(screen.queryByText('Changed unsafe step')).not.toBeInTheDocument();
  });
  it('invalidates mismatched approval hashes and identities', () => {
    expect(approvalState(DEMO_APPROVAL_RECORD, { ...DEMO_REMEDIATION_PLAN, plan_hash: 'new' })).toBe('STALE');
    expect(approvalState({ ...DEMO_APPROVAL_RECORD, approver_id: DEMO_APPROVAL_RECORD.operator_id }, DEMO_REMEDIATION_PLAN)).toBe('INVALID_SEPARATION_OF_DUTIES');
  });
  it('displays missing backup, unknown dry-run and failed historical safety checks', async () => {
    fixtureStore.hardeningChange = { ...DEMO_HARDENING_CHANGE, backup_snapshot_hash: '' };
    fixtureStore.approvals = [{ ...DEMO_APPROVAL_RECORD, backup_readiness_confirmed: false, safety_contracts_passed: false }];
    renderWorkspace(<ApprovalsHardeningShell />);
    expect(await screen.findByText(/Backup readiness: FAILED/)).toBeInTheDocument();
    expect(screen.getByText('Safety tests: FAILED')).toBeInTheDocument();
    expect(screen.getByText(/Dry-run status: UNKNOWN/)).toBeInTheDocument();
    expect(screen.getByText(/Backup artifact hash: UNKNOWN/)).toBeInTheDocument();
  });
  it('has no CLI input and sends no execution or approval requests when prerequisites are missing', async () => {
    const api = new DemoApiClient(); const execute = vi.spyOn(api, 'executeChange'); const approve = vi.spyOn(api, 'approvePlan');
    renderWorkspace(<ApprovalsHardeningShell />, { api });
    const button = await screen.findByRole('button', { name: 'Execute approved change - blocked' });
    fireEvent.click(button);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(execute).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
  });
  it('rejects a route identifier not matching the bounded change record', async () => {
    const api = new DemoApiClient(); const execute = vi.spyOn(api, 'executeChange');
    renderWorkspace(<ApprovalsHardeningShell />, { api, path: 'changes/arbitrary-command', pattern: '/orgs/:orgId/changes/:changeId' });
    expect(await screen.findByText(/Request failed/)).toBeInTheDocument();
    expect(execute).not.toHaveBeenCalled();
  });
  it('shows failed events and manual recovery honestly without a fake retry action', async () => {
    fixtureStore.hardeningChange = { ...DEMO_HARDENING_CHANGE, state: ExecutionState.NEEDS_MANUAL_RECOVERY, canary_halt_triggered: true, execution_events: [{ timestamp: '2026-10-29T10:00:00Z', stage: 'CANARY', status: 'FAILED', message: 'Management probe timed out' }] };
    renderWorkspace(<ApprovalsHardeningShell />);
    expect(await screen.findByText(/Management probe timed out/)).toBeInTheDocument();
    expect(screen.getByText(/Execution state: NEEDS_MANUAL_RECOVERY/)).toBeInTheDocument();
    expect(screen.getByText(/Retry and automated recovery: UNSUPPORTED/)).toBeInTheDocument();
  });
  it('retains the Phase 6 contract violation gate', async () => {
    updateSession(DEMO_ORG_ID, { selected: 'restrictive' }); renderWorkspace(<ApprovalsHardeningShell />);
    expect(screen.getByRole('alert')).toHaveTextContent('Approval blocked');
    expect(await screen.findByRole('button', { name: 'Approve plan - unavailable' })).toBeDisabled();
  });
  it.each([
    [EvaluationStatus.NOT_ASSESSED, 'INSUFFICIENT_EVIDENCE'],
    [EvaluationStatus.ERROR, 'UNKNOWN'],
    [EvaluationStatus.FAIL, 'FAILED'],
    [EvaluationStatus.NOT_APPLICABLE, 'UNSUPPORTED'],
  ])('never displays SUCCESS for service status %s', async (status, outcome) => {
    fixtureStore.dualVerification = { ...DEMO_DUAL_VERIFICATION, service_probe_status: status };
    renderWorkspace(<VerificationProofShell />);
    expect(await screen.findByText(`Overall result: ${outcome}`)).toBeInTheDocument();
    expect(screen.queryByText(/Overall result: SUCCESS/)).not.toBeInTheDocument();
  });
  it('requires backend VERIFIED and both pass checks for SUCCESS', () => {
    expect(verificationOutcome({ ...DEMO_HARDENING_CHANGE, state: ExecutionState.VERIFYING }, DEMO_DUAL_VERIFICATION)).toBe('UNKNOWN');
    expect(verificationOutcome(DEMO_HARDENING_CHANGE, { ...DEMO_DUAL_VERIFICATION, overall_verified: false })).toBe('UNKNOWN');
    expect(verificationOutcome(DEMO_HARDENING_CHANGE, DEMO_DUAL_VERIFICATION)).toBe('SUCCESS');
  });
  it('displays evidence linkage and missing/hash-unverified states without inventing artifacts', async () => {
    fixtureStore.proofPackage = { ...fixtureStore.proofPackage, manifest_verified: false, post_hardening_config_hash: '' };
    renderWorkspace(<VerificationProofShell />);
    expect(await screen.findByText(/Manifest state: NOT VERIFIED/)).toBeInTheDocument();
    expect(screen.getByText('Unavailable or invalid SHA-256')).toBeInTheDocument();
    expect(screen.getByText(/Before\/after artifact URIs/)).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
  it('shows proof authorization failures and no stale dossier', async () => {
    const api = new DemoApiClient(); vi.spyOn(api, 'getProofPackage').mockRejectedValue({ status: 403 });
    renderWorkspace(<VerificationProofShell />, { api });
    expect(await screen.findByRole('alert')).toHaveTextContent('403 Forbidden');
    expect(screen.queryByText('Proof manifest (I18)')).not.toBeInTheDocument();
  });
  it('shows an empty approval collection and loading state', async () => {
    fixtureStore.approvals = []; renderWorkspace(<ApprovalsHardeningShell />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading records');
    expect(await screen.findByText(/No approval records supplied/)).toBeInTheDocument();
  });
  it('retries failed reads without retrying device execution', async () => {
    const api = new DemoApiClient(); const read = vi.spyOn(api, 'getApprovals').mockRejectedValueOnce(new Error('Network'));
    renderWorkspace(<ApprovalsHardeningShell />, { api });
    fireEvent.click(await screen.findByRole('button', { name: 'Retry request' }));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/Approval ID:/)).toBeInTheDocument();
  });
});
