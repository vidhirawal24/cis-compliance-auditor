import React, { useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  BookOpen,
  Sliders,
  Sparkles,
  Shield,
  AlertTriangle,
  Plus,
  Trash2,
  X,
  ExternalLink,
  Search,
  Lock,
  ArrowRight,
  Info,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { useAuth } from '../../auth/context';
import { fixtureStore } from '../../api/store';
import { UserRole } from '../../contracts/v1/enums';
import { toast } from 'sonner';
import type { PolicyPack, PolicyRule, PolicyOverride } from '../../contracts/v1/types';

export const PolicyLibraryShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { role } = useAuth();

  const tabParam = searchParams.get('tab') as 'PACKS' | 'OVERRIDES' | 'UPGRADE_PREVIEW' | null;
  const [activeTab, setActiveTab] = useState<'PACKS' | 'OVERRIDES' | 'UPGRADE_PREVIEW'>(tabParam || 'PACKS');

  const setTab = (tab: 'PACKS' | 'OVERRIDES' | 'UPGRADE_PREVIEW') => {
    setActiveTab(tab);
    setSearchParams({ tab });
  };

  // State from store
  const policyPacks = fixtureStore.policyPacks;
  const [selectedPackId, setSelectedPackId] = useState<string>(policyPacks[0]?.policy_pack_id || 'cis-cisco-ios-v4');
  const [profileLevelFilter, setProfileLevelFilter] = useState<'ALL' | 'LEVEL_1' | 'LEVEL_2'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRule, setSelectedRule] = useState<PolicyRule | null>(null);

  // Overrides State
  const [overrides, setOverrides] = useState<PolicyOverride[]>([...fixtureStore.policyOverrides]);
  const [isAddingOverride, setIsAddingOverride] = useState(false);
  const [overridePackId, setOverridePackId] = useState(selectedPackId);
  const [overrideControlId, setOverrideControlId] = useState('');
  const [overrideValue, setOverrideValue] = useState('');
  const [overrideRationale, setOverrideRationale] = useState('');
  const [overrideApprover, setOverrideApprover] = useState('ciso@acmefinancial.com');
  const [overrideError, setOverrideError] = useState<string | null>(null);

  // Version Diff State
  const [diffPackId, setDiffPackId] = useState<string>('cis-cisco-ios-v4');

  // Role authorization: Auditors and Viewers are read-only; Owners, Admins, Approvers have edit rights
  const isAuthorizedEditor = [UserRole.OWNER, UserRole.ADMIN, UserRole.APPROVER].includes(role);

  // Active Pack & Rules
  const activePack: PolicyPack =
    policyPacks.find((p) => p.policy_pack_id === selectedPackId) || policyPacks[0];

  const packRules = activePack.rules || [];

  const filteredRules = packRules.filter((rule) => {
    const matchProfile =
      profileLevelFilter === 'ALL' || rule.profile_level === profileLevelFilter;
    const matchSearch =
      searchQuery.trim() === '' ||
      rule.control_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchProfile && matchSearch;
  });

  // Handle Add Override Submission
  const handleCreateOverride = (e: React.FormEvent) => {
    e.preventDefault();
    setOverrideError(null);

    if (!isAuthorizedEditor) {
      setOverrideError('Permission Denied: Read-only auditors cannot create baseline overrides.');
      return;
    }

    if (!overrideControlId.trim()) {
      setOverrideError('Control ID is required.');
      return;
    }

    if (!overrideValue.trim()) {
      setOverrideError('Override configuration value is required.');
      return;
    }

    if (overrideRationale.trim().length < 10) {
      setOverrideError('Business and operational rationale must be at least 10 characters.');
      return;
    }

    const targetPack = policyPacks.find((p) => p.policy_pack_id === overridePackId);
    const targetRule = targetPack?.rules?.find((r) => r.control_id === overrideControlId);

    const created = fixtureStore.createOverride({
      policy_pack_id: overridePackId,
      control_id: overrideControlId,
      rule_title: targetRule?.title || overrideControlId,
      benchmark_value: targetRule?.expected_value ? JSON.stringify(targetRule.expected_value) : 'Standard Default',
      override_value: overrideValue.trim(),
      rationale: overrideRationale.trim(),
      approved_by: overrideApprover.trim(),
    });

    setOverrides([...fixtureStore.policyOverrides]);
    setIsAddingOverride(false);
    setOverrideControlId('');
    setOverrideValue('');
    setOverrideRationale('');
    toast.success(`Organization override for ${created.control_id} successfully registered.`);
  };

  // Handle Delete Override
  const handleDeleteOverride = (overrideId: string) => {
    if (!isAuthorizedEditor) {
      toast.error('Permission Denied: Read-only auditors cannot delete baseline overrides.');
      return;
    }
    fixtureStore.deleteOverride(overrideId);
    setOverrides([...fixtureStore.policyOverrides]);
    toast.info('Organization override removed; benchmark standard baseline restored.');
  };

  // Selected Version Diff Data (E20, I19)
  const activeVersionDiff = fixtureStore.policyVersionDiffs[diffPackId] || null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-sky-400" />
            CIS Policy & Benchmark Library (M17, M18, M19)
          </h1>
          <p className="text-xs text-slate-400">
            Versioned, explainable CIS rule packs with profile levels (E11), organization threshold overrides (M18, M19), and upgrade impact simulation (E20, I19).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setTab('UPGRADE_PREVIEW')}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs text-sky-400 border-sky-800/80 hover:bg-sky-950/40"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Upgrade Impact Preview (E20)
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setTab('PACKS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'PACKS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Active Benchmark Packs (M17)
        </button>
        <button
          onClick={() => setTab('OVERRIDES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'OVERRIDES'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Custom Baseline Overrides (M18, M19) ({overrides.length})
        </button>
        <button
          onClick={() => setTab('UPGRADE_PREVIEW')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'UPGRADE_PREVIEW'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Version Diff & Upgrade Impact (E20, I19)
        </button>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* TAB 1: ACTIVE BENCHMARK PACKS (M17, E11, I19) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'PACKS' && (
        <div className="space-y-6">
          {/* Policy Pack Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {policyPacks.map((pack) => {
              const isSelected = pack.policy_pack_id === selectedPackId;
              return (
                <div
                  key={pack.policy_pack_id}
                  onClick={() => setSelectedPackId(pack.policy_pack_id)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'border-sky-500 bg-sky-950/30 ring-1 ring-sky-500/50'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <Shield className={`w-4 h-4 ${isSelected ? 'text-sky-400' : 'text-slate-500'}`} />
                    <Badge variant="outline" className="text-[10px] font-mono border-sky-800 text-sky-300">
                      {pack.version}
                    </Badge>
                  </div>
                  <h2 className="text-xs font-bold text-white leading-snug line-clamp-2">
                    {pack.name}
                  </h2>
                  <div className="text-[10px] text-slate-400 font-mono mt-2 flex items-center justify-between">
                    <span>{pack.platform}</span>
                    <span>{pack.rules?.length || pack.total_rules_count} Rules Defined</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Active Pack Rules Inspector */}
          <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
            <CardHeader className="border-b border-slate-800 pb-3">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <CardTitle className="text-sm font-bold text-white">
                      {activePack.name}
                    </CardTitle>
                    <Badge variant="secondary" className="text-[10px] font-mono">
                      {activePack.version}
                    </Badge>
                    <span className="text-xs text-slate-400 font-mono">
                      • {activePack.publisher}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Synthetic demonstration rules clearly labeled DEMO. Official copyrighted CIS benchmark texts are not reproduced.
                  </p>
                </div>

                {/* Profile Filter & Search */}
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {/* Profile Level Selector (E11) */}
                  <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800 font-mono text-xs">
                    <span className="text-[10px] text-slate-400 px-1">Profile:</span>
                    {(['ALL', 'LEVEL_1', 'LEVEL_2'] as const).map((lvl) => (
                      <button
                        key={lvl}
                        onClick={() => setProfileLevelFilter(lvl)}
                        className={`px-2 py-0.5 rounded text-[10px] font-bold transition-colors ${
                          profileLevelFilter === lvl
                            ? 'bg-sky-600 text-white'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        {lvl === 'ALL' ? 'ALL' : lvl === 'LEVEL_1' ? 'Level 1' : 'Level 2'}
                      </button>
                    ))}
                  </div>

                  {/* Search */}
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2 pointer-events-none" />
                    <Input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search rules..."
                      className="pl-8 h-7 text-xs w-44"
                    />
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <Table className="table-compact text-xs">
                <TableHeader>
                  <TableRow>
                    <TableHead>Control ID</TableHead>
                    <TableHead>Rule Title</TableHead>
                    <TableHead>Profile (E11)</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status & Overrides</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule) => {
                    const ruleOverride = overrides.find((o) => o.control_id === rule.control_id);
                    const hasWarning = !!rule.unsupported_content_warning;

                    return (
                      <TableRow
                        key={rule.rule_id}
                        onClick={() => setSelectedRule(rule)}
                        className="hover:bg-slate-800/40 cursor-pointer"
                      >
                        <TableCell className="font-mono font-bold text-sky-400">
                          {rule.control_id}
                        </TableCell>
                        <TableCell>
                          <div className="space-y-0.5">
                            <span className="font-semibold text-slate-200">{rule.title}</span>
                            {hasWarning && (
                              <div className="text-[10px] font-mono text-amber-400 flex items-center gap-1 mt-0.5">
                                <AlertTriangle className="w-3 h-3 shrink-0" />
                                <span>{rule.unsupported_content_warning}</span>
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${
                              rule.profile_level === 'LEVEL_1'
                                ? 'bg-sky-950/60 text-sky-300 border-sky-800'
                                : 'bg-purple-950/60 text-purple-300 border-purple-800'
                            }`}
                          >
                            {rule.profile_level}
                          </span>
                        </TableCell>
                        <TableCell className="text-slate-300">{rule.category}</TableCell>
                        <TableCell>
                          <SeverityBadge severity={rule.severity} />
                        </TableCell>
                        <TableCell>
                          {ruleOverride ? (
                            <span className="font-mono text-[10px] text-amber-300 bg-amber-950/80 px-1.5 py-0.5 rounded border border-amber-800 flex items-center gap-1 w-max">
                              <Sliders className="w-2.5 h-2.5" /> Org Override
                            </span>
                          ) : (
                            <span className="font-mono text-[10px] text-slate-400">
                              Benchmark Standard
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            onClick={() => setSelectedRule(rule)}
                            variant="outline"
                            size="sm"
                            className="h-6 text-[10px] px-2"
                          >
                            Inspect Detail
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* TAB 2: ORGANIZATIONAL BASELINE OVERRIDES (M18, M19) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'OVERRIDES' && (
        <div className="space-y-4">
          <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
            <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 gap-2 border-b border-slate-800">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-amber-400" />
                  <span>Organizational Baseline Overrides (M18, M19)</span>
                </CardTitle>
                <p className="text-xs text-slate-400 mt-0.5">
                  Custom organization parameter adjustments separated from upstream CIS benchmark baselines. Overriding preserves original baseline provenance.
                </p>
              </div>

              <div className="flex items-center gap-2">
                {!isAuthorizedEditor && (
                  <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono bg-slate-950 px-2 py-1 rounded border border-slate-800">
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    <span>Read-Only Auditor Mode</span>
                  </div>
                )}
                <Button
                  onClick={() => setIsAddingOverride(true)}
                  disabled={!isAuthorizedEditor}
                  size="sm"
                  className="text-xs gap-1.5 bg-sky-600 hover:bg-sky-500 text-white disabled:opacity-50"
                >
                  <Plus className="w-3.5 h-3.5" /> Add Organization Override
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {overrides.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs">
                  No active organizational overrides. Fleet is evaluated strictly against upstream CIS benchmark standards.
                </div>
              ) : (
                <Table className="table-compact text-xs">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Control ID</TableHead>
                      <TableHead>Benchmark Standard Setting</TableHead>
                      <TableHead>Organization Override Setting</TableHead>
                      <TableHead>Business Rationale & Approver</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {overrides.map((ovr) => (
                      <TableRow key={ovr.override_id} className="hover:bg-slate-800/40">
                        <TableCell className="font-mono font-bold text-sky-400">
                          {ovr.control_id}
                          <div className="text-[10px] text-slate-400 font-normal">
                            {ovr.rule_title}
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-xs text-slate-300 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                            {String(ovr.benchmark_value)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-xs text-amber-300 font-bold bg-amber-950/60 px-2 py-1 rounded border border-amber-800">
                            {String(ovr.override_value)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="space-y-0.5 max-w-sm">
                            <p className="text-slate-300 text-xs">{ovr.rationale}</p>
                            <div className="text-[10px] font-mono text-slate-400">
                              Approved by {ovr.approved_by} on {new Date(ovr.approved_at).toLocaleDateString()}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            onClick={() => handleDeleteOverride(ovr.override_id)}
                            disabled={!isAuthorizedEditor}
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs text-slate-400 hover:text-rose-400 disabled:opacity-30"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* TAB 3: BENCHMARK VERSION COMPARISON & UPGRADE IMPACT (E20, I19) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'UPGRADE_PREVIEW' && (
        <div className="space-y-6">
          {/* Pack Selector Header */}
          <Card className="border-slate-800 bg-slate-900/90 p-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-sky-400" />
                  <span>Benchmark Version Upgrade Impact Simulator (E20, I19)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Compare rules across versions and calculate predicted compliance impact before applying pack upgrades.
                </p>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400 font-mono">Benchmark Pack:</span>
                <select
                  aria-label="Benchmark Pack Diff Selector"
                  value={diffPackId}
                  onChange={(e) => setDiffPackId(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 font-mono"
                >
                  {policyPacks.map((pack) => (
                    <option key={pack.policy_pack_id} value={pack.policy_pack_id}>
                      {pack.name} ({pack.version})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </Card>

          {/* If Version Diff Data Exists */}
          {activeVersionDiff ? (
            <div className="space-y-6">
              {/* Upgrade KPI Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 rounded-lg bg-black/40 border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">
                    Version Transition
                  </div>
                  <div className="text-sm font-bold font-mono text-white flex items-center gap-2">
                    <span className="text-slate-400">{activeVersionDiff.from_version}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-sky-400" />
                    <span className="text-sky-400">{activeVersionDiff.to_version}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">CIS Benchmark Core Upgrade</div>
                </div>

                <div className="p-4 rounded-lg bg-black/40 border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">
                    New Rules Added
                  </div>
                  <div className="text-lg font-bold font-mono text-sky-400">
                    +{activeVersionDiff.added_rules.length} Rules
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    {activeVersionDiff.removed_rules.length} rules deprecated/removed
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-black/40 border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">
                    Modified Checks
                  </div>
                  <div className="text-lg font-bold font-mono text-amber-400">
                    {activeVersionDiff.modified_rules.length} Rules
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">Thresholds or severity changed</div>
                </div>

                <div className="p-4 rounded-lg bg-black/40 border border-rose-900/60 bg-rose-950/20 space-y-1">
                  <div className="text-[10px] font-mono text-rose-300 uppercase">
                    Predicted Compliance Delta
                  </div>
                  <div className="text-lg font-bold font-mono text-rose-400">
                    {activeVersionDiff.predicted_compliance_impact_pct}% Impact
                  </div>
                  <div className="text-[11px] text-rose-300/80 font-mono">
                    Affects {activeVersionDiff.affected_devices_count} production devices
                  </div>
                </div>
              </div>

              {/* Version Comparison Diff Breakdown Table */}
              <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
                <CardHeader className="pb-3 border-b border-slate-800">
                  <CardTitle className="text-sm font-semibold">
                    Rule-by-Rule Version Transition Manifest
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table className="table-compact text-xs">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Control ID</TableHead>
                        <TableHead>Rule Title</TableHead>
                        <TableHead>Change Details</TableHead>
                        <TableHead>Upgrade Impact Rationale</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {/* Added Rules */}
                      {activeVersionDiff.added_rules.map((rule) => (
                        <TableRow key={rule.rule_id} className="hover:bg-slate-800/40">
                          <TableCell>
                            <Badge variant="success" className="text-[10px] font-mono">
                              ADDED
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono font-bold text-sky-400">
                            {rule.control_id}
                          </TableCell>
                          <TableCell className="font-medium text-white">{rule.title}</TableCell>
                          <TableCell className="font-mono text-[11px] text-slate-300">
                            New check in {rule.profile_level}
                          </TableCell>
                          <TableCell className="text-slate-400 text-xs">
                            New requirement; devices must be audited against new cipher/key parameters.
                          </TableCell>
                        </TableRow>
                      ))}

                      {/* Modified Rules */}
                      {activeVersionDiff.modified_rules.map((rule) => (
                        <TableRow key={rule.control_id} className="hover:bg-slate-800/40">
                          <TableCell>
                            <Badge variant="warning" className="text-[10px] font-mono">
                              MODIFIED
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono font-bold text-amber-400">
                            {rule.control_id}
                          </TableCell>
                          <TableCell className="font-medium text-white">{rule.title}</TableCell>
                          <TableCell className="font-mono text-[11px]">
                            <span className="text-rose-400 line-through mr-1">
                              {String(rule.old_value)}
                            </span>
                            <span className="text-emerald-400 font-bold">
                              &rarr; {String(rule.new_value)}
                            </span>
                          </TableCell>
                          <TableCell className="text-slate-400 text-xs">
                            {rule.upgrade_impact}
                          </TableCell>
                        </TableRow>
                      ))}

                      {/* Removed Rules */}
                      {activeVersionDiff.removed_rules.map((rule) => (
                        <TableRow key={rule.control_id} className="hover:bg-slate-800/40">
                          <TableCell>
                            <Badge variant="destructive" className="text-[10px] font-mono">
                              DEPRECATED
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-slate-500 line-through">
                            {rule.control_id}
                          </TableCell>
                          <TableCell className="font-medium text-slate-400 line-through">
                            {rule.title}
                          </TableCell>
                          <TableCell className="text-slate-500 text-xs italic">
                            Superseded in {activeVersionDiff.to_version}
                          </TableCell>
                          <TableCell className="text-slate-400 text-xs">
                            {rule.rationale}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          ) : (
            /* Honest Missing/Insufficient Data State */
            <div className="p-8 rounded-lg border border-slate-800 bg-slate-900/60 text-center space-y-3">
              <Info className="w-8 h-8 text-sky-400 mx-auto" />
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-white">
                  No Benchmark Version Diff Available
                </h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  There is no recorded previous benchmark release diff for this policy pack. No breaking rule changes or upgrade transitions are registered.
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* MODAL: CONTROL DETAIL INSPECTION (M18) */}
      {/* ------------------------------------------------------------------ */}
      {selectedRule && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-sky-400">
                    {selectedRule.control_id}
                  </span>
                  <SeverityBadge severity={selectedRule.severity} />
                  <Badge variant="outline" className="text-[10px] font-mono">
                    {selectedRule.profile_level}
                  </Badge>
                </div>
                <h3 className="text-sm font-bold text-white">
                  Control Specification & Audit Logic: {selectedRule.title}
                </h3>
                <div className="text-xs text-slate-400 font-mono">{selectedRule.category}</div>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs max-h-96 overflow-y-auto">
              <div className="space-y-1">
                <div className="font-semibold text-slate-300">Description</div>
                <p className="text-slate-400 leading-relaxed">{selectedRule.description}</p>
              </div>

              <div className="space-y-1">
                <div className="font-semibold text-slate-300">Security Rationale</div>
                <p className="text-slate-400 leading-relaxed">{selectedRule.rationale}</p>
              </div>

              {selectedRule.unsupported_content_warning && (
                <div className="p-2.5 rounded bg-amber-950/40 border border-amber-900/60 text-amber-200 text-xs flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">Unsupported Content Notice:</span>{' '}
                    {selectedRule.unsupported_content_warning}
                  </div>
                </div>
              )}

              <div className="p-3 bg-black/50 rounded-lg border border-slate-800 space-y-1.5 font-mono">
                <div className="text-[11px] text-slate-400 flex items-center justify-between">
                  <span>Operator: {selectedRule.evaluation_operator}</span>
                  <span>Benchmark Expected Configuration</span>
                </div>
                <pre className="text-sky-300 text-xs overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(selectedRule.expected_value, null, 2)}
                </pre>
              </div>

              {(() => {
                const activeRuleOverride = overrides.find((o) => o.control_id === selectedRule.control_id);
                if (!activeRuleOverride) return null;
                return (
                  <div className="p-3 bg-amber-950/40 rounded-lg border border-amber-800/80 space-y-1.5">
                    <div className="text-[11px] text-amber-300 flex items-center justify-between font-mono">
                      <span className="font-semibold flex items-center gap-1.5">
                        <Sliders className="w-3.5 h-3.5 text-amber-400" />
                        Active Organization Baseline Override (M18)
                      </span>
                      <span className="text-[10px] text-amber-400">Approved by {activeRuleOverride.approved_by}</span>
                    </div>
                    <div className="text-amber-200 font-bold font-mono text-xs">
                      {String(activeRuleOverride.override_value)}
                    </div>
                    <p className="text-slate-300 text-xs leading-relaxed">
                      {activeRuleOverride.rationale}
                    </p>
                  </div>
                );
              })()}

              {selectedRule.remediation_cli_template && (
                <div className="space-y-1">
                  <div className="font-semibold text-slate-300">Remediation CLI Template</div>
                  <pre className="p-2.5 rounded bg-black/60 border border-slate-800 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                    {selectedRule.remediation_cli_template}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-800">
              <Button
                onClick={() => {
                  const controlId = selectedRule.control_id;
                  setSelectedRule(null);
                  navigate(`/orgs/${orgId}/findings?control=${controlId}`);
                }}
                variant="outline"
                size="sm"
                className="h-8 text-xs gap-1.5"
              >
                <ExternalLink className="w-3.5 h-3.5" /> Related Findings
              </Button>
              <Button
                onClick={() => setSelectedRule(null)}
                size="sm"
                className="h-8 text-xs bg-slate-800 hover:bg-slate-700 text-white"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* MODAL: CREATE POLICY OVERRIDE (M19) */}
      {/* ------------------------------------------------------------------ */}
      {isAddingOverride && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-amber-400" />
                <span>Configure Organization Baseline Override (M19)</span>
              </h3>
              <button
                onClick={() => setIsAddingOverride(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateOverride} className="space-y-4 text-xs">
              {overrideError && (
                <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs">
                  {overrideError}
                </div>
              )}

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Policy Benchmark Pack</label>
                <select
                  aria-label="Policy Benchmark Pack"
                  value={overridePackId}
                  onChange={(e) => {
                    setOverridePackId(e.target.value);
                    setOverrideControlId('');
                  }}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                >
                  {policyPacks.map((pack) => (
                    <option key={pack.policy_pack_id} value={pack.policy_pack_id}>
                      {pack.name} ({pack.version})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Target CIS Control</label>
                <select
                  aria-label="Target CIS Control"
                  value={overrideControlId}
                  onChange={(e) => setOverrideControlId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 font-mono"
                >
                  <option value="">-- Select Rule to Override --</option>
                  {(policyPacks.find((p) => p.policy_pack_id === overridePackId)?.rules || []).map(
                    (rule) => (
                      <option key={rule.control_id} value={rule.control_id}>
                        {rule.control_id}: {rule.title}
                      </option>
                    )
                  )}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">
                  Organization Override Value / Setting
                </label>
                <Input
                  aria-label="Organization Override Value"
                  value={overrideValue}
                  onChange={(e) => setOverrideValue(e.target.value)}
                  placeholder="e.g., 600s, 16 characters, or custom parameter"
                  className="h-8 text-xs font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">
                  Business & Operational Rationale (min 10 characters)
                </label>
                <textarea
                  aria-label="Override Rationale"
                  value={overrideRationale}
                  onChange={(e) => setOverrideRationale(e.target.value)}
                  placeholder="Justification for departing from upstream benchmark recommendation..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 focus:ring-1 focus:ring-sky-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Approver Corporate Email</label>
                <Input
                  aria-label="Approver Corporate Email"
                  value={overrideApprover}
                  onChange={(e) => setOverrideApprover(e.target.value)}
                  type="email"
                  className="h-8 text-xs font-mono"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <Button
                  type="button"
                  onClick={() => setIsAddingOverride(false)}
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  className="h-8 text-xs bg-sky-600 hover:bg-sky-500 text-white font-semibold"
                >
                  Save Override (M19)
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
