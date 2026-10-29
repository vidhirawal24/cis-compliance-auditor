import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertCircle,
  Search,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  ShieldAlert,
  Info,
  CheckCircle2,
  FileCheck2,
} from 'lucide-react';
import { Input } from '../../components/ui/input';
import { Button } from '../../components/ui/button';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { StatusBadge } from '../../components/common/StatusBadge';
import { EvidenceViewer } from '../../components/common/EvidenceViewer';
import { fixtureStore } from '../../api/store';
import { SeverityLevel, EvaluationStatus } from '../../contracts/v1/enums';

export const FindingsShell: React.FC = () => {
  const [searchParams] = useSearchParams();
  const categoryParam = searchParams.get('category') || '';
  const statusParam = searchParams.get('status') || 'ALL';

  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>(statusParam);
  const [selectedAssetId, setSelectedAssetId] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>(categoryParam);
  const [copiedCli, setCopiedCli] = useState(false);

  const findings = fixtureStore.findings;
  const assets = fixtureStore.assets;
  const categories = Array.from(new Set(findings.map((f) => f.category)));

  // Sync category param if changed
  useEffect(() => {
    if (categoryParam) {
      setSelectedCategory(categoryParam);
    }
  }, [categoryParam]);

  // Selected finding ID defaults to first finding
  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    findings[0]?.finding_id || ''
  );

  // Filtered Findings
  const filtered = findings.filter((f) => {
    const matchQuery =
      search.trim() === '' ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.control_id.toLowerCase().includes(search.toLowerCase()) ||
      f.category.toLowerCase().includes(search.toLowerCase()) ||
      f.asset_id.toLowerCase().includes(search.toLowerCase());

    const matchSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    const matchStatus = selectedStatus === 'ALL' || f.status === selectedStatus;
    const matchAsset = selectedAssetId === 'ALL' || f.asset_id === selectedAssetId;
    const matchCategory = !selectedCategory || f.category === selectedCategory;

    return matchQuery && matchSev && matchStatus && matchAsset && matchCategory;
  });

  // Keep selected finding valid
  const selectedFinding =
    filtered.find((f) => f.finding_id === selectedFindingId) ||
    filtered[0] ||
    findings[0];

  const handleCopyCli = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-rose-400" />
            Findings & Compliance Evidence Explorer (M36, M37, E29)
          </h1>
          <p className="text-xs text-slate-400">
            Side-by-side expected vs observed state comparison with immutable cryptographic evidence and non-executable remediation CLI.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[220px] max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2 pointer-events-none" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search control, title, category, asset..."
            className="pl-9 h-8 text-xs"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5 text-xs">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="h-8 bg-slate-900 border border-slate-800 rounded px-2.5 text-xs text-slate-300 font-mono focus:ring-1 focus:ring-sky-500"
          >
            <option value="ALL">All Statuses (6 Invariant)</option>
            <option value={EvaluationStatus.PASS}>PASS</option>
            <option value={EvaluationStatus.FAIL}>FAIL</option>
            <option value={EvaluationStatus.NOT_APPLICABLE}>NOT APPLICABLE</option>
            <option value={EvaluationStatus.MANUAL_REVIEW}>MANUAL REVIEW</option>
            <option value={EvaluationStatus.ERROR}>ERROR</option>
            <option value={EvaluationStatus.NOT_ASSESSED}>NOT ASSESSED</option>
          </select>
        </div>

        {/* Asset Filter */}
        <div className="flex items-center gap-1.5 text-xs">
          <select
            value={selectedAssetId}
            onChange={(e) => setSelectedAssetId(e.target.value)}
            className="h-8 bg-slate-900 border border-slate-800 rounded px-2.5 text-xs text-slate-300 font-mono focus:ring-1 focus:ring-sky-500"
          >
            <option value="ALL">All Target Assets ({assets.length})</option>
            {assets.map((a) => (
              <option key={a.asset_id} value={a.asset_id}>
                {a.hostname} ({a.platform})
              </option>
            ))}
          </select>
        </div>

        {/* Category Filter Dropdown */}
        <div className="flex items-center gap-1.5 text-xs">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="h-8 bg-slate-900 border border-slate-800 rounded px-2.5 text-xs text-slate-300 font-mono focus:ring-1 focus:ring-sky-500"
          >
            <option value="">All Categories ({categories.length})</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-md border border-slate-800 text-xs ml-auto">
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
        <div className="lg:col-span-5 rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden flex flex-col h-[750px]">
          <div className="p-3 bg-slate-950 border-b border-slate-800 text-xs font-semibold text-slate-300 flex justify-between items-center shrink-0">
            <span>Evaluated Controls ({filtered.length} matching)</span>
            <span className="font-mono text-slate-500 text-[11px]">Strict Invariant Evaluation</span>
          </div>

          <div className="divide-y divide-slate-800/80 overflow-y-auto flex-1">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs space-y-2">
                <Info className="w-6 h-6 mx-auto text-slate-600" />
                <p>No findings match the selected filters.</p>
                <button
                  onClick={() => {
                    setSearch('');
                    setSelectedSeverity('ALL');
                    setSelectedStatus('ALL');
                    setSelectedAssetId('ALL');
                    setSelectedCategory('');
                  }}
                  className="text-sky-400 hover:underline text-[11px]"
                >
                  Reset all filters
                </button>
              </div>
            ) : (
              filtered.map((f) => {
                const isSelected = selectedFinding?.finding_id === f.finding_id;

                return (
                  <div
                    key={f.finding_id}
                    onClick={() => setSelectedFindingId(f.finding_id)}
                    className={`p-3 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-sky-950/30 border-l-2 border-sky-500'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1 gap-2">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-[11px] text-slate-400 font-bold">{f.control_id}</span>
                      </div>
                      <StatusBadge status={f.status} hasException={!!f.exception} />
                    </div>

                    <h2 className="text-xs font-semibold text-white truncate mt-1">{f.title}</h2>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1.5 font-mono">
                      <span className="truncate max-w-[200px]">Asset: {f.asset_id}</span>
                      <span className="text-slate-500">{new Date(f.evaluated_at).toLocaleDateString()}</span>
                    </div>

                    {f.exception && (
                      <div className="mt-1 text-[10px] font-mono text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/60 inline-flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3 shrink-0" />
                        <span>Policy Exception Active (Violation Retained)</span>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Pane: Expected vs Observed Side-by-Side Comparison (M36, M37) */}
        <div className="lg:col-span-7 space-y-4">
          {selectedFinding ? (
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 space-y-4">
              {/* Finding Header */}
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={selectedFinding.severity} />
                    <span className="font-mono text-xs text-sky-400 font-bold">{selectedFinding.control_id}</span>
                    <span className="text-xs text-slate-500">• {selectedFinding.category}</span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                      {selectedFinding.profile_level}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-white leading-snug">{selectedFinding.title}</h2>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Benchmark Pack: {selectedFinding.benchmark_pack_id} • Target: {selectedFinding.asset_id}
                  </div>
                </div>

                <StatusBadge status={selectedFinding.status} hasException={!!selectedFinding.exception} />
              </div>

              {/* Policy Exception Banner (E14) */}
              {selectedFinding.exception && (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-800/80 space-y-2 text-xs">
                  <div className="flex items-center gap-2 font-bold text-amber-300">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>Approved Policy Exception Manifest (E14)</span>
                  </div>
                  <div className="space-y-1 text-slate-300 text-[11px] pl-6 font-mono">
                    <div>
                      <span className="text-slate-400">Exception ID:</span> {selectedFinding.exception.exception_id}
                    </div>
                    <div>
                      <span className="text-slate-400">Approver:</span> {selectedFinding.exception.approver_email}
                    </div>
                    <div>
                      <span className="text-slate-400">Justification:</span> {selectedFinding.exception.reason}
                    </div>
                    <div>
                      <span className="text-slate-400">Expires At:</span>{' '}
                      {new Date(selectedFinding.exception.expires_at).toLocaleDateString()}
                    </div>
                  </div>
                  <div className="text-[10px] font-mono text-amber-400/90 pl-6 border-t border-amber-900/60 pt-1.5">
                    Strict Invariant Scoring: Policy exceptions grant operational tolerance, but this control is strictly retained as a violation in the compliance scoring denominator.
                  </div>
                </div>
              )}

              {/* Status Special Callouts: ERROR, NOT_ASSESSED, NOT_APPLICABLE */}
              {selectedFinding.status === EvaluationStatus.ERROR && (
                <div className="p-3 rounded-lg bg-red-950/40 border border-red-800 text-xs space-y-1 text-red-200">
                  <div className="font-bold flex items-center gap-1.5 text-red-300">
                    <ShieldAlert className="w-4 h-4" /> Collector Probe Error
                  </div>
                  <p className="text-[11px] text-red-300/90">
                    The automated collector encountered a communication or protocol failure while evaluating this control. Human review is recommended.
                  </p>
                </div>
              )}

              {selectedFinding.status === EvaluationStatus.NOT_ASSESSED && (
                <div className="p-3 rounded-lg bg-purple-950/40 border border-purple-800 text-xs space-y-1 text-purple-200">
                  <div className="font-bold flex items-center gap-1.5 text-purple-300">
                    <Info className="w-4 h-4" /> Control Not Assessed (Incomplete Capability Scope)
                  </div>
                  <p className="text-[11px] text-purple-300/90 font-mono">
                    Notice: Unassessed controls are NEVER scored as PASS. They are tracked as missing coverage until required capabilities or credentials are provided.
                  </p>
                </div>
              )}

              {selectedFinding.status === EvaluationStatus.PASS && (
                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800 text-xs space-y-1 text-emerald-200">
                  <div className="font-bold flex items-center gap-1.5 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4" /> Verified CIS Benchmark Compliance
                  </div>
                  <p className="text-[11px] text-emerald-300/90">
                    Observed configuration matches the CIS benchmark expected state. No remediation action required.
                  </p>
                </div>
              )}

              {/* Expected vs Actual Side-by-Side Grid (M36) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                <div className="p-3 rounded-lg bg-black/50 border border-emerald-900/50 space-y-2">
                  <div className="text-[11px] font-mono font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                    <FileCheck2 className="w-3.5 h-3.5" />
                    <span>Expected State (CIS Benchmark)</span>
                  </div>
                  <pre className="text-xs font-mono text-emerald-100/90 overflow-x-auto whitespace-pre-wrap bg-emerald-950/20 p-2.5 rounded border border-emerald-900/40">
                    {JSON.stringify(selectedFinding.expected_state, null, 2)}
                  </pre>
                </div>

                <div className="p-3 rounded-lg bg-black/50 border border-slate-800 space-y-2">
                  <div className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-sky-400" />
                    <span>Observed State (Live Evidence)</span>
                  </div>
                  <pre className={`text-xs font-mono overflow-x-auto whitespace-pre-wrap p-2.5 rounded border ${
                    selectedFinding.status === EvaluationStatus.PASS
                      ? 'text-emerald-100/90 bg-emerald-950/20 border-emerald-900/40'
                      : selectedFinding.status === EvaluationStatus.ERROR
                      ? 'text-red-200 bg-red-950/20 border-red-900/40'
                      : 'text-rose-200 bg-rose-950/20 border-rose-900/40'
                  }`}>
                    {JSON.stringify(selectedFinding.observed_state, null, 2)}
                  </pre>
                </div>
              </div>

              {/* Immutable Evidence Viewer (M12) */}
              <div className="space-y-1.5 pt-2">
                <div className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                  <span>Collector Evidence & Cryptographic Provenance (M12)</span>
                  <span className="font-mono text-[10px] text-slate-500">SHA-256 Verified</span>
                </div>
                <EvidenceViewer evidence={selectedFinding.evidence_ref} />
              </div>

              {/* Actionable Remediation Guidance (M37) */}
              {selectedFinding.remediation_cli ? (
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                      <Terminal className="w-4 h-4" />
                      <span>Actionable Remediation Guidance (Read-Only Preview) (M37)</span>
                    </div>

                    <Button
                      onClick={() => handleCopyCli(selectedFinding.remediation_cli || '')}
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs gap-1.5 text-slate-300 hover:text-white"
                    >
                      {copiedCli ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" /> Copy CLI
                        </>
                      )}
                    </Button>
                  </div>

                  {/* Risk Warning Alert */}
                  {selectedFinding.remediation_risk_warning && (
                    <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/60 text-amber-200 text-xs flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold">Risk Warning:</span> {selectedFinding.remediation_risk_warning}
                      </div>
                    </div>
                  )}

                  {/* Prerequisites List */}
                  {selectedFinding.remediation_prerequisites && selectedFinding.remediation_prerequisites.length > 0 && (
                    <div className="space-y-1 text-xs">
                      <div className="font-semibold text-slate-300">Operational Prerequisites:</div>
                      <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[11px] font-mono">
                        {selectedFinding.remediation_prerequisites.map((req, idx) => (
                          <li key={idx}>{req}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Non-Executable CLI Template Display */}
                  <div className="p-3 bg-black/80 rounded border border-slate-800 font-mono text-xs text-sky-300 overflow-x-auto">
                    <pre className="whitespace-pre-wrap">{selectedFinding.remediation_cli}</pre>
                  </div>

                  <p className="text-[10px] text-slate-500 font-mono">
                    Disclaimer: Browser client executes zero mutations directly. Remediation commands must be vetted via What-If Simulation and approved through the dual-operator workflow.
                  </p>
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-black/40 border border-slate-800 text-xs text-slate-400 italic">
                  {selectedFinding.status === EvaluationStatus.PASS
                    ? 'This control is fully compliant with the CIS benchmark. No configuration changes required.'
                    : selectedFinding.status === EvaluationStatus.NOT_APPLICABLE
                    ? 'This control is not applicable to the target platform or role. No remediation required.'
                    : selectedFinding.status === EvaluationStatus.MANUAL_REVIEW
                    ? 'This control requires human attestation or physical security verification.'
                    : 'Remediation guidance requires manual technical review.'}
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              Select a finding on the left to inspect expected vs observed states.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
