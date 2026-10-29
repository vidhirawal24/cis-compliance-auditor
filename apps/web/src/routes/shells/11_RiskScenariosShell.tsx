import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Flame,
  ArrowRight,
  ShieldAlert,
  AlertTriangle,
  Network,
  Filter,
  Search,
  Layers,
  HelpCircle,
} from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { fixtureStore } from '../../api/store';
import type { RiskScenario } from '../../contracts/v1/types';

export const RiskScenariosShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const scenarios: RiskScenario[] = fixtureStore.riskScenarios;

  // Filter & Search State
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Filtered scenarios
  const filteredScenarios = scenarios.filter((scen) => {
    if (severityFilter !== 'ALL' && scen.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = scen.title.toLowerCase().includes(q);
      const matchDesc = scen.description.toLowerCase().includes(q);
      const matchId = scen.scenario_id.toLowerCase().includes(q);
      const matchFinding = scen.source_finding_ids.some((f) => f.toLowerCase().includes(q));
      const matchAsset = scen.affected_asset_ids.some((a) => a.toLowerCase().includes(q));
      return matchTitle || matchDesc || matchId || matchFinding || matchAsset;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-500" />
            Correlated Risk Scenarios & Lateral Movement (I02, I04, I05)
          </h1>
          <p className="text-xs text-slate-400">
            Multi-device correlation joining disparate findings into verifiable attack pathways with root-cause causation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/graph`)}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs text-sky-400 border-sky-800/80 hover:bg-sky-950/40"
          >
            <Network className="w-3.5 h-3.5" />
            <span>Interactive Security Graph (I01)</span>
          </Button>
        </div>
      </div>

      {/* Topology & Causation Invariant Notice (I05) */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 text-xs text-slate-300 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-white flex items-center gap-2">
            <span>Causal Graph Correlation & Uncertainty Principles (I04, I05)</span>
            <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-800 font-mono">
              EVIDENCE-BOUND
            </Badge>
          </div>
          <p className="text-slate-400 leading-relaxed">
            Risk scenarios join multiple failed CIS benchmarks across network perimeter, intermediate switching, and host endpoints.
            Causal sequences require evidence-proven network adjacency and valid access rules. Where topology data is unassessed,
            uncertainty warnings are explicitly flagged; unverified lateral paths are never fabricated or presented as verified facts.
          </p>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 text-xs">
        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              severityFilter === 'ALL'
                ? 'bg-sky-600 text-white font-medium'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            All ({scenarios.length})
          </button>
          <button
            onClick={() => setSeverityFilter('CRITICAL')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              severityFilter === 'CRITICAL'
                ? 'bg-rose-600 text-white font-medium'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Critical ({scenarios.filter((s) => s.severity === 'CRITICAL').length})
          </button>
          <button
            onClick={() => setSeverityFilter('HIGH')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              severityFilter === 'HIGH'
                ? 'bg-orange-600 text-white font-medium'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            High ({scenarios.filter((s) => s.severity === 'HIGH').length})
          </button>
          <button
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              severityFilter === 'MEDIUM'
                ? 'bg-amber-600 text-white font-medium'
                : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Medium ({scenarios.filter((s) => s.severity === 'MEDIUM').length})
          </button>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
          <Input
            placeholder="Search scenarios or findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs bg-slate-900 border-slate-800"
          />
        </div>
      </div>

      {/* Scenarios List */}
      <div className="space-y-4">
        {filteredScenarios.length === 0 ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-8 text-center text-xs text-slate-500">
            No risk scenarios found matching the current search and severity filters.
          </div>
        ) : (
          filteredScenarios.map((scen) => (
            <Card key={scen.scenario_id} className="border-slate-800 bg-slate-900/90 p-5 space-y-4 shadow-xl">
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-sky-400">
                      {scen.scenario_id}
                    </span>
                    <span className="text-slate-600">•</span>
                    <SeverityBadge severity={scen.severity} />
                    <span className="font-mono text-xs text-rose-400 font-bold bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/80">
                      Risk Score: {scen.risk_score} / 100
                    </span>
                    <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-800">
                      {scen.confidence_pct}% Explainability Confidence (I05)
                    </Badge>
                    {scen.model_engine && (
                      <Badge variant="secondary" className="text-[10px] font-mono">
                        {scen.model_engine}
                      </Badge>
                    )}
                  </div>
                  <h2 className="text-base font-bold text-white">{scen.title}</h2>
                  <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">{scen.description}</p>
                </div>

                <div className="flex md:flex-col items-end gap-2 shrink-0">
                  <Button
                    onClick={() => navigate(`/orgs/${orgId}/graph`)}
                    variant="outline"
                    size="sm"
                    className="gap-1.5 text-xs text-sky-400 border-sky-800/80 hover:bg-sky-950/40"
                  >
                    <Network className="w-3.5 h-3.5" />
                    <span>Trace in Graph (I03)</span>
                  </Button>
                  <Button
                    onClick={() => navigate(`/orgs/${orgId}/planner`)}
                    size="sm"
                    className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500 text-white"
                  >
                    <span>Open Planner (I06)</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>

              {/* Source Finding IDs Tags & Affected Assets */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 bg-black/40 rounded-lg border border-slate-800 text-xs font-mono">
                <div>
                  <span className="text-[11px] text-slate-400 block mb-1 uppercase tracking-wider">
                    Contributing Source Findings (I02):
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {scen.source_finding_ids.map((findId) => (
                      <button
                        key={findId}
                        onClick={() => navigate(`/orgs/${orgId}/findings`)}
                        className="px-2 py-0.5 rounded bg-rose-950/80 border border-rose-800/80 text-rose-300 hover:text-white transition-colors text-[11px] flex items-center gap-1"
                      >
                        <ShieldAlert className="w-3 h-3 text-rose-400" />
                        <span>{findId}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-slate-400 block mb-1 uppercase tracking-wider">
                    Affected Infrastructure Nodes:
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {scen.affected_asset_ids.map((assetId) => (
                      <span
                        key={assetId}
                        className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px]"
                      >
                        {assetId}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Causal Chain Timeline (I04) */}
              <div className="p-3 bg-black/50 rounded-lg border border-slate-800 space-y-2">
                <div className="text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-sky-400" />
                  <span>Root-Cause Causal Sequence (I04)</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  {scen.causal_chain.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-slate-300">
                      <span className="w-5 h-5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="leading-snug">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Topology Uncertainty State (I05) */}
              {scen.topology_uncertainty && (
                <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/60 text-xs text-amber-200 flex items-start gap-2">
                  <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-amber-300 font-mono">
                      Topology Boundary Limitation (I05):
                    </span>{' '}
                    {scen.topology_uncertainty}
                  </div>
                </div>
              )}

              {/* Business Impact Footer */}
              <div className="p-3 rounded bg-rose-950/20 border border-rose-900/60 text-xs text-rose-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <strong>Business Impact:</strong> {scen.business_impact}
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  {scen.affected_asset_ids.length} Assets Exposed
                </div>
              </div>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};
