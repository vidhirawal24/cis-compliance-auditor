import React, { useState } from 'react';
import {
  AlertCircle,
  Search,
  Terminal,
} from 'lucide-react';
import { Input } from '../../components/ui/input';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { StatusBadge } from '../../components/common/StatusBadge';
import { EvidenceViewer } from '../../components/common/EvidenceViewer';
import { fixtureStore } from '../../api/store';
import { SeverityLevel } from '../../contracts/v1/enums';

export const FindingsShell: React.FC = () => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(fixtureStore.findings[0].finding_id);

  const findings = fixtureStore.findings;

  const filtered = findings.filter((f) => {
    const matchQuery =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.control_id.toLowerCase().includes(search.toLowerCase()) ||
      f.category.toLowerCase().includes(search.toLowerCase());
    const matchSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    return matchQuery && matchSev;
  });

  const selectedFinding = findings.find((f) => f.finding_id === selectedFindingId) || findings[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-rose-400" />
            Findings & Compliance Evidence Explorer (M36, E29)
          </h1>
          <p className="text-xs text-slate-400">
            Side-by-side expected vs actual comparison with immutable evidence hashes and actionable remediation.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2 pointer-events-none" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings by control, title, or category..."
            className="pl-9 h-8 text-xs"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-md border border-slate-800 text-xs">
          {['ALL', SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                selectedSeverity === sev
                  ? 'bg-sky-600 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Two-Pane Findings Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Pane: Findings List */}
        <div className="lg:col-span-5 rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <div className="p-3 bg-slate-950 border-b border-slate-800 text-xs font-semibold text-slate-300 flex justify-between">
            <span>Evaluated Findings ({filtered.length})</span>
            <span className="font-mono text-slate-500">CIS Invariant Scoring</span>
          </div>

          <div className="divide-y divide-slate-800/80 max-h-[600px] overflow-y-auto">
            {filtered.map((f) => (
              <div
                key={f.finding_id}
                onClick={() => setSelectedFindingId(f.finding_id)}
                className={`p-3 cursor-pointer transition-colors ${
                  selectedFindingId === f.finding_id
                    ? 'bg-sky-950/30 border-l-2 border-sky-500'
                    : 'hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-[11px] text-slate-400">{f.control_id}</span>
                  </div>
                  <StatusBadge status={f.status} hasException={!!f.exception} />
                </div>
                <h2 className="text-xs font-semibold text-white truncate">{f.title}</h2>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1 font-mono">
                  <span>Target: {f.asset_id.slice(0, 16)}...</span>
                  <span className="text-slate-500">{new Date(f.evaluated_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Pane: Expected vs Observed Side-by-Side Comparison (M36) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <span className="font-mono text-xs text-sky-400 font-bold">{selectedFinding.control_id}</span>
                  <span className="text-xs text-slate-500">• {selectedFinding.category}</span>
                </div>
                <h2 className="text-base font-bold text-white leading-snug">{selectedFinding.title}</h2>
              </div>
              <StatusBadge status={selectedFinding.status} hasException={!!selectedFinding.exception} />
            </div>

            {/* Expected vs Actual Side-by-Side Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
              <div className="p-3 rounded-lg bg-black/50 border border-emerald-900/40 space-y-1.5">
                <div className="text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wider">
                  Expected State (CIS Benchmark)
                </div>
                <pre className="text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedFinding.expected_state, null, 2)}
                </pre>
              </div>

              <div className="p-3 rounded-lg bg-black/50 border border-rose-900/40 space-y-1.5">
                <div className="text-[11px] font-mono font-bold text-rose-400 uppercase tracking-wider">
                  Observed State (Live Evidence)
                </div>
                <pre className="text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedFinding.observed_state, null, 2)}
                </pre>
              </div>
            </div>

            {/* Immutable Evidence Viewer */}
            <div className="space-y-1.5 pt-2">
              <div className="text-xs font-semibold text-slate-300">
                Collector Evidence & Cryptographic Hash (M12)
              </div>
              <EvidenceViewer evidence={selectedFinding.evidence_ref} />
            </div>

            {/* Actionable Remediation Guidance (M37) */}
            {selectedFinding.remediation_cli && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                  <Terminal className="w-4 h-4" />
                  <span>Actionable Remediation CLI Template (Read-Only Preview)</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  {selectedFinding.remediation_risk_warning ||
                    'Review and test via What-If Simulation before executing approval workflow.'}
                </p>
                <div className="p-2.5 bg-black/60 rounded border border-slate-800 font-mono text-xs text-sky-300 overflow-x-auto">
                  <pre className="whitespace-pre-wrap">{selectedFinding.remediation_cli}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

