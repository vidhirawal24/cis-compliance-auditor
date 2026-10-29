import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ShieldAlert, Play, CheckCircle2 } from 'lucide-react';
import { Card, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { ConfirmDialog } from '../../components/common/ConfirmDialog';
import { fixtureStore } from '../../api/store';
import { ExecutionState } from '../../contracts/v1/enums';

export const ApprovalsHardeningShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const [showConfirm, setShowConfirm] = useState(false);
  const change = fixtureStore.hardeningChange;
  const approval = fixtureStore.approvals[0];

  const handleExecuteChange = () => {
    setShowConfirm(false);
    change.state = ExecutionState.VERIFIED;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            Approvals & Controlled Hardening (E21, E23, I15)
          </h1>
          <p className="text-xs text-slate-400">
            Multi-role cryptographic sign-off and staged canary execution with automatic rollback safeguards.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/verifications`)}
            size="sm"
            variant="outline"
            className="text-xs"
          >
            Dual Verification (I16) &rarr;
          </Button>
        </div>
      </div>

      {/* Multi-Role Approval Review Card (E23) */}
      <Card className="border-slate-800 bg-slate-900/90 p-5 space-y-4">
        <div className="flex items-start justify-between pb-3 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Badge variant="success" className="gap-1 font-mono text-[10px]">
                <CheckCircle2 className="w-3 h-3" /> FORMALLY APPROVED
              </Badge>
              <span className="font-mono text-xs text-slate-400">Approval ID: {approval.approval_id}</span>
            </div>
            <h2 className="text-sm font-bold text-white">Plan Hash Verification (SHA-256)</h2>
            <p className="font-mono text-xs text-sky-400 truncate max-w-xl">{approval.plan_hash}</p>
          </div>

          <div className="text-right text-xs">
            <div className="text-slate-400">Approved by Approver Persona:</div>
            <div className="font-mono text-emerald-400 font-bold">{approval.approver_email}</div>
          </div>
        </div>

        {/* Separation of Duties & Backup Verification Pills */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-2.5 rounded bg-black/40 border border-slate-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Separation of Duties Enforced (Operator != Approver)</span>
          </div>
          <div className="p-2.5 rounded bg-black/40 border border-slate-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Pre-Change Snapshot Hash Recorded (E24)</span>
          </div>
          <div className="p-2.5 rounded bg-black/40 border border-slate-800 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Simulation Reachability Cleared (I14)</span>
          </div>
        </div>
      </Card>

      {/* Controlled Hardening Execution State Machine (I15) */}
      <Card className="border-slate-800 bg-slate-900/90 p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Play className="w-4 h-4 text-sky-400" />
            Stage Rollout Progress & Execution Events (I15)
          </CardTitle>
          <Badge variant="outline" className="font-mono text-xs text-emerald-400 border-emerald-800">
            STATE: {change.state}
          </Badge>
        </div>

        <div className="space-y-3">
          {change.execution_events.map((evt, idx) => (
            <div
              key={idx}
              className="p-3 bg-black/40 rounded border border-slate-800 flex items-center justify-between text-xs font-mono"
            >
              <div className="flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span className="text-slate-400">{evt.timestamp}</span>
                <span className="text-white font-bold">{evt.stage}</span>
                <span className="text-slate-300">{evt.message}</span>
              </div>
              <Badge variant="success" className="text-[10px]">
                {evt.status}
              </Badge>
            </div>
          ))}
        </div>

        <div className="flex justify-end pt-2">
          <Button
            onClick={() => setShowConfirm(true)}
            size="sm"
            className="gap-2 bg-rose-600 hover:bg-rose-500 text-white text-xs"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Trigger Stage 2 Canary Execution (DEMO)
          </Button>
        </div>
      </Card>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showConfirm}
        onClose={() => setShowConfirm(false)}
        onConfirm={handleExecuteChange}
        title="Execute Approved Controlled Hardening Change"
        description="This action executes bounded vendor configuration templates. Pre-change snapshots are archived in OpenBao. Type EXECUTE to confirm."
        confirmWord="EXECUTE"
        danger={true}
      />
    </div>
  );
};

