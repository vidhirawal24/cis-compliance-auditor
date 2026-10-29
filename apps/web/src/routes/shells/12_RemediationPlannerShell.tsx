import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ListTree, Cpu, ArrowRight, CheckCircle2 } from 'lucide-react';
import { Card, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { fixtureStore } from '../../api/store';

export const RemediationPlannerShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const plan = fixtureStore.remediationPlan;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ListTree className="w-5 h-5 text-sky-400" />
            Remediation Planner & Sequence DAG (I06, I08, I10)
          </h1>
          <p className="text-xs text-slate-400">
            Constraint-aware minimal change optimization via Google OR-Tools CP-SAT with cross-vendor sequencing.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/simulator`)}
            size="sm"
            className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500"
          >
            <span>Proceed to What-If Simulation (I11)</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Plan Optimization Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">OR-Tools Optimization Score (I06)</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-emerald-400" />
            {plan.minimal_change_score} <span className="text-xs font-normal text-slate-400">Minimal Disruption</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Weighted objective minimized under availability constraints</div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Sequenced Actions (I10)</div>
          <div className="text-2xl font-bold font-mono text-white">
            {plan.actions.length} Steps
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Cross-vendor coordination (Cisco + Linux)</div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Safety & Conflict Matrix (I09)</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5" /> 0 Conflicts
          </div>
          <div className="text-[11px] text-slate-500 mt-1">No management lockout or route loops detected</div>
        </Card>
      </div>

      {/* Change Sequencing DAG Shell (React Flow Plan) */}
      <Card className="border-slate-800 bg-slate-900/90 p-5 space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ListTree className="w-4 h-4 text-sky-400" />
            Ordered Hardening Actions Sequence (React Flow DAG Shell)
          </CardTitle>
          <Badge variant="outline" className="font-mono text-xs text-slate-400">
            Hash: {plan.plan_hash.slice(0, 16)}...
          </Badge>
        </div>

        <div className="space-y-3">
          {plan.actions.map((act) => (
            <div
              key={act.action_id}
              className="p-3 rounded-lg bg-black/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
            >
              <div className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-sky-950 text-sky-300 border border-sky-800 font-mono font-bold flex items-center justify-center shrink-0">
                  {act.sequence_order}
                </span>
                <div>
                  <div className="font-semibold text-white flex items-center gap-2">
                    {act.title}
                    <Badge variant="secondary" className="text-[10px] uppercase font-mono">
                      {act.vendor}
                    </Badge>
                  </div>
                  <pre className="mt-1 font-mono text-[11px] text-slate-300 bg-slate-950 p-2 rounded border border-slate-800/80 overflow-x-auto">
                    {act.command_template}
                  </pre>
                </div>
              </div>

              <div className="text-right shrink-0">
                <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-800">
                  REVERSIBLE (E24)
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

