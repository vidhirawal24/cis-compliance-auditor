import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Flame, ArrowRight } from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { Badge } from '../../components/ui/badge';
import { fixtureStore } from '../../api/store';

export const RiskScenariosShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const scenarios = fixtureStore.riskScenarios;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-500" />
            Correlated Risk Scenarios & Root Causes (I02, I04, I05)
          </h1>
          <p className="text-xs text-slate-400">
            Multi-device correlation joining disparate findings into verifiable attack pathways.
          </p>
        </div>
      </div>

      {/* Scenarios List */}
      <div className="space-y-4">
        {scenarios.map((scen) => (
          <Card key={scen.scenario_id} className="border-slate-800 bg-slate-900/90 p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={scen.severity} />
                  <span className="font-mono text-xs text-rose-400 font-bold">
                    Risk Score: {scen.risk_score} / 100
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-800">
                    {scen.confidence_pct}% Explainability Confidence (I05)
                  </Badge>
                </div>
                <h2 className="text-base font-bold text-white">{scen.title}</h2>
                <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">{scen.description}</p>
              </div>

              <div className="flex md:flex-col items-end gap-2 shrink-0">
                <Button
                  onClick={() => navigate(`/orgs/${orgId}/planner`)}
                  size="sm"
                  className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500"
                >
                  <span>Open Planner (I06)</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>

            {/* Causal Chain Timeline (I04) */}
            <div className="p-3 bg-black/40 rounded-lg border border-slate-800 space-y-2">
              <div className="text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider">
                Root-Cause Causal Sequence (I04)
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                {scen.causal_chain.map((step, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-slate-300">
                    <span className="w-5 h-5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 text-[10px] font-bold flex items-center justify-center shrink-0">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Business Impact Footer */}
            <div className="p-2.5 rounded bg-rose-950/20 border border-rose-900/60 text-xs text-rose-300 flex items-center justify-between">
              <div>
                <strong>Business Impact:</strong> {scen.business_impact}
              </div>
              <div className="text-[11px] font-mono text-slate-400">
                {scen.affected_asset_ids.length} Assets Exposed
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};

