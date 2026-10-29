import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useApi } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import { useAuth } from '../../auth/context';
import { UserRole } from '../../contracts/v1/enums';
import type { RemediationPlan } from '../../contracts/v1/types';
import { usePhase6 } from '../../features/phase6/model';
import { approvalState, validHash } from '../../features/phase7/review';
import { ApiState } from '../../components/common/ApiState';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';

// E21-E24, I14-I15. No production write capability is established by v1.
export function ApprovalsHardeningShell() {
  const { orgId = '', changeId } = useParams();
  const api = useApi();
  const { role, user } = useAuth();
  const safety = usePhase6(orgId);
  const [snapshot, setSnapshot] = useState<RemediationPlan>();
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const records = useQuery({ queryKey: ['phase7-review', orgId, changeId], queryFn: async () => {
    const [approvals, change] = await Promise.all([api.getApprovals(), api.getChange(changeId ?? 'chg-2026-7701')]);
    if (changeId && change.data.change_id !== changeId) throw new Error('Change identity mismatch');
    return { approvals: approvals.data, change: change.data };
  }, retry: false });
  useEffect(() => {
    if (!snapshot && safety.data?.plan) setSnapshot(JSON.parse(JSON.stringify(safety.data.plan)) as RemediationPlan);
  }, [safety.data?.plan, snapshot]);
  const approver = [UserRole.OWNER, UserRole.ADMIN, UserRole.APPROVER].includes(role);
  const operator = [UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR].includes(role);
  const stale = !!snapshot && !!safety.data && JSON.stringify(snapshot) !== JSON.stringify(safety.data.plan);
  return <div className="space-y-5">
    <h1 className="text-xl font-bold">Approvals &amp; Controlled Hardening (E21-E24, I14-I15)</h1>
    <Badge variant="warning">{api instanceof DemoApiClient ? 'DEMO - synthetic records, read-only review' : 'Backend records - execution capabilities unconfirmed'}</Badge>
    <p>Current role: {role}. {approver ? 'Approval review role' : 'Operator review; approval decision unavailable for this role'}. Server authorization and separation of duties are required for every write.</p>
    {!safety.canReview && <p role="alert">Approval blocked: no current eligible simulation preview. Known violations, changed contracts, unsupported models and insufficient evidence cannot be overridden here.</p>}
    <ApiState pending={records.isPending || safety.isPending} error={records.error || safety.error} retry={() => { void records.refetch(); void safety.refetch(); }}>
      {snapshot && <Card className="p-4 space-y-2"><h2>Immutable review snapshot</h2>
        <p>Plan: {snapshot.plan_id}; submitted hash: {snapshot.plan_hash || 'UNKNOWN'}</p>
        <p>This is a captured review snapshot, not proof of server submission. Contents stay fixed while this review is open.</p>
        {stale && <p role="alert">STALE: underlying plan contents changed. Review is invalidated.</p>}
        <ol>{snapshot.actions.map(action => <li key={action.action_id}>{action.sequence_order}. {action.title} / {action.asset_id} / risk {action.risk_weight}<p>Prerequisites: {action.prerequisites.join('; ') || 'UNKNOWN'}</p><pre className="overflow-auto whitespace-pre-wrap">{action.command_template}</pre><p>Manual recovery guidance: {action.recovery_plan ?? 'Not supplied'}</p></li>)}</ol>
        <p>Conflicts: {snapshot.conflicts.join('; ') || (snapshot.conflict_detected ? 'Detected; details missing' : 'None reported')}</p>
        <p>Safety model: {safety.candidate?.verdict ?? 'UNKNOWN'}; coverage: {safety.data?.simulation.model_coverage_pct ?? 'UNKNOWN'}%.</p>
      </Card>}
      <Card className="p-4 space-y-3"><h2>Approval queue and decision history</h2>
        <label>Approval decision filter <select className="bg-slate-900 border p-2" value={decisionFilter} onChange={event => setDecisionFilter(event.target.value)}>{['ALL', 'APPROVED', 'REJECTED', 'EXPIRED', 'STALE'].map(status => <option key={status}>{status}</option>)}</select></label>
        {!records.data?.approvals.length && <p>No approval records supplied. Pending requests are unsupported by the current collection contract.</p>}
        {records.data?.approvals.filter(a => a.plan_id === safety.data?.plan.plan_id && (decisionFilter === 'ALL' || (safety.data && approvalState(a, safety.data.plan, snapshot) === decisionFilter))).map(record => <article key={record.approval_id} className="p-3 border border-slate-700 rounded">
          <p>Approval ID: {record.approval_id}</p><p>Decision: {safety.data ? approvalState(record, safety.data.plan, snapshot) : 'UNKNOWN'}</p>
          <p>Reviewer: {record.approver_email || record.approver_id || 'Not supplied'}; operator: {record.operator_id || 'Not supplied'}</p>
          <p>Timestamp: {record.approved_at || 'Not supplied'}; reason: {record.justification || 'Not supplied'}</p>
          <p>Backup readiness: {record.backup_readiness_confirmed === true ? 'CONFIRMED in approval record' : record.backup_readiness_confirmed === false ? 'FAILED / not confirmed' : 'UNKNOWN'}</p>
          <p>Safety tests: {record.safety_contracts_passed === true ? 'Passed in historical approval record; current checks still required' : record.safety_contracts_passed === false ? 'FAILED' : 'UNKNOWN'}</p>
          {user?.id === record.operator_id && <p>Separation of duties: this operator cannot approve their own plan.</p>}
        </article>)}
        <p>BLOCKED: no production approval adapter, immutable submission revision or rejection operation is available. No decision has been submitted.</p>
        <Button disabled>{approver ? 'Approve plan - unavailable' : 'Approval requires approver role'}</Button>
      </Card>
      {records.data && <Card className="p-4 space-y-3"><h2>Execution preconditions and rollout</h2>
        <p>Supported change record: {records.data.change.change_id}; plan: {records.data.change.plan_id}</p>
        <p>Backup artifact hash: {validHash(records.data.change.backup_snapshot_hash) ? records.data.change.backup_snapshot_hash : 'UNKNOWN / invalid hash'}. Artifact restore readiness is not supplied.</p>
        <p>Dry-run status: UNKNOWN - no typed dry-run result. Current safety-test result and per-target outcomes: UNKNOWN.</p>
        <p>Execution blocked: missing current dry-run, restore-readiness and safety attestation. A snapshot hash alone is not a passed backup check.</p>
        <p>Execution state: {records.data.change.state}; batch {records.data.change.current_stage_batch} of {records.data.change.total_stage_batches}. Per-stage target scope not supplied.</p>
        {records.data.change.canary_halt_triggered && <p role="alert">HALTED: backend record reports canary halt.</p>}
        <ol>{records.data.change.execution_events.map((event, i) => <li key={i}>{event.timestamp}: {event.stage} / {event.status} / {event.message}</li>)}</ol>
        {!records.data.change.execution_events.length && <p>No execution events supplied.</p>}
        <Button disabled>{operator ? 'Execute approved change - blocked' : 'Execution requires operator role'}</Button>
        <p>Retry and automated recovery: UNSUPPORTED (no API methods). For NEEDS_MANUAL_RECOVERY, use the supplied plan guidance with an authorized device operator; no recovery was executed here.</p>
      </Card>}
    </ApiState>
  </div>;
}
