import React, { useState, useEffect } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  Radar,
  Play,
  Calendar,
  RotateCcw,
  ShieldCheck,
  AlertOctagon,
  Trash2,
  Plus,
  X,
  RefreshCw,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { fixtureStore } from '../../api/store';
import { toast } from 'sonner';
import type { ScanJob, ScanSchedule } from '../../contracts/v1/types';

export const ScanCenterShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const tabParam = searchParams.get('tab') as 'SCANS' | 'NEW_SCAN' | 'SCHEDULES' | null;
  const [activeTab, setActiveTab] = useState<'SCANS' | 'NEW_SCAN' | 'SCHEDULES'>(tabParam || 'SCANS');

  // Sync tab with URL
  useEffect(() => {
    if (tabParam && ['SCANS', 'NEW_SCAN', 'SCHEDULES'].includes(tabParam)) {
      setActiveTab(tabParam);
    }
  }, [tabParam]);

  const setTab = (tab: 'SCANS' | 'NEW_SCAN' | 'SCHEDULES') => {
    setActiveTab(tab);
    setSearchParams({ tab });
  };

  // State from store
  const [scans, setScans] = useState<ScanJob[]>([...fixtureStore.scans]);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([...fixtureStore.scanSchedules]);
  const assets = fixtureStore.assets;
  const policyPacks = fixtureStore.policyPacks;

  // Launch Wizard Form State
  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>(assets.map((a) => a.asset_id));
  const [selectedPolicyPackId, setSelectedPolicyPackId] = useState<string>(policyPacks[0]?.policy_pack_id || 'cis-multi-platform-v1');
  const [selectedProfileLevel, setSelectedProfileLevel] = useState<'LEVEL_1' | 'LEVEL_2'>('LEVEL_1');
  const [readOnlyConfirmed, setReadOnlyConfirmed] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [wizardError, setWizardError] = useState<string | null>(null);

  // Per-target Error Inspection Modal State
  const [inspectingScan, setInspectingScan] = useState<ScanJob | null>(null);

  // New Schedule Form Modal State
  const [isAddingSchedule, setIsAddingSchedule] = useState(false);
  const [scheduleName, setScheduleName] = useState('');
  const [cronExpression, setCronExpression] = useState('0 0 * * *');
  const [scheduleTargetGroup, setScheduleTargetGroup] = useState('All Production Assets');
  const [schedulePolicyPackId, setSchedulePolicyPackId] = useState('cis-multi-platform-v1');
  const [scheduleProfileLevel, setScheduleProfileLevel] = useState<'LEVEL_1' | 'LEVEL_2'>('LEVEL_1');
  const [scheduleError, setScheduleError] = useState<string | null>(null);

  // Toggle individual asset in wizard
  const toggleAssetSelection = (assetId: string) => {
    setSelectedAssetIds((prev) =>
      prev.includes(assetId) ? prev.filter((id) => id !== assetId) : [...prev, assetId]
    );
  };

  const selectAllAssets = () => {
    setSelectedAssetIds(assets.map((a) => a.asset_id));
  };

  const clearAssetSelection = () => {
    setSelectedAssetIds([]);
  };

  // Launch audit scan
  const handleLaunchScan = (e: React.FormEvent) => {
    e.preventDefault();
    setWizardError(null);

    if (selectedAssetIds.length === 0) {
      setWizardError('At least one target asset must be selected for the audit scope.');
      return;
    }

    if (!readOnlyConfirmed) {
      setWizardError('Mandatory confirmation of Read-Only Audit Execution is required prior to dispatch.');
      return;
    }

    setIsLaunching(true);

    const newScanId = `scan-${Date.now()}`;
    const newScan: ScanJob = {
      scan_id: newScanId,
      org_id: fixtureStore.defaultOrgId,
      status: 'RUNNING',
      read_only: true,
      requested_assets: selectedAssetIds.length,
      completed_assets: 0,
      failed_assets: 0,
      assessed_compliance_pct: 0,
      assessment_coverage_pct: 0,
      policy_pack_id: selectedPolicyPackId,
      profile_level: selectedProfileLevel,
      target_asset_ids: selectedAssetIds,
      started_at: new Date().toISOString(),
      trigger_type: 'MANUAL',
    };

    fixtureStore.scans.unshift(newScan);
    setScans([...fixtureStore.scans]);

    setTimeout(() => {
      setIsLaunching(false);
      setTab('SCANS');
      toast.success(`Audit Job ${newScanId} dispatched in read-only mode across ${selectedAssetIds.length} targets.`);

      // Simulate asynchronous worker completion
      setTimeout(() => {
        const found = fixtureStore.scans.find((s) => s.scan_id === newScanId);
        if (found) {
          found.status = 'COMPLETED';
          found.completed_assets = selectedAssetIds.length;
          found.assessed_compliance_pct = 76.5;
          found.assessment_coverage_pct = 88.0;
          found.completed_at = new Date().toISOString();
          setScans([...fixtureStore.scans]);
          toast.success(`Audit Job ${newScanId} completed. Assessed Compliance: 76.5%`);
        }
      }, 3500);
    }, 800);
  };

  // Retry a failed scan
  const handleRetryScan = (scanId: string) => {
    const retried = fixtureStore.retryScan(scanId);
    setScans([...fixtureStore.scans]);
    toast.info(`Retrying audit job ${scanId} as new job ${retried.scan_id}`);

    setTimeout(() => {
      retried.status = 'COMPLETED';
      retried.completed_assets = retried.requested_assets;
      retried.assessed_compliance_pct = 71.4;
      retried.assessment_coverage_pct = 85.0;
      retried.completed_at = new Date().toISOString();
      setScans([...fixtureStore.scans]);
      toast.success(`Retried Job ${retried.scan_id} completed successfully.`);
    }, 3000);
  };

  // Create Recurring Schedule (E04)
  const handleCreateSchedule = (e: React.FormEvent) => {
    e.preventDefault();
    setScheduleError(null);

    // Validate 5-field cron syntax
    const cronRegex = /^\S+\s+\S+\s+\S+\s+\S+\s+\S+$/;
    if (!cronRegex.test(cronExpression.trim())) {
      setScheduleError('Cron expression must follow standard 5-field syntax (e.g., "0 0 * * *").');
      return;
    }

    if (!scheduleName.trim()) {
      setScheduleError('Schedule name is required.');
      return;
    }

    const created = fixtureStore.createSchedule({
      name: scheduleName.trim(),
      cron_expression: cronExpression.trim(),
      target_asset_group: scheduleTargetGroup,
      policy_pack_id: schedulePolicyPackId,
      profile_level: scheduleProfileLevel,
    });

    setSchedules([...fixtureStore.scanSchedules]);
    setIsAddingSchedule(false);
    setScheduleName('');
    toast.success(`Recurring schedule "${created.name}" created successfully.`);
  };

  // Toggle Schedule Active/Inactive
  const handleToggleSchedule = (scheduleId: string) => {
    const updated = fixtureStore.toggleSchedule(scheduleId);
    setSchedules([...fixtureStore.scanSchedules]);
    toast.info(`Schedule "${updated.name}" is now ${updated.is_active ? 'ACTIVE' : 'INACTIVE'}.`);
  };

  // Delete Schedule
  const handleDeleteSchedule = (scheduleId: string) => {
    fixtureStore.deleteSchedule(scheduleId);
    setSchedules([...fixtureStore.scanSchedules]);
    toast.warning('Schedule deleted.');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Radar className="w-5 h-5 text-sky-400" />
            Audit Scan Center (M13, E04, E18)
          </h1>
          <p className="text-xs text-slate-400">
            Deterministic, read-only compliance collection and CIS benchmark rule evaluation engine.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setTab('NEW_SCAN')}
            size="sm"
            className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500 text-white"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Launch Audit Wizard
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setTab('SCANS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'SCANS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Audit History & Active Runs ({scans.length})
        </button>
        <button
          onClick={() => setTab('NEW_SCAN')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'NEW_SCAN'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Launch Audit (Wizard)
        </button>
        <button
          onClick={() => setTab('SCHEDULES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'SCHEDULES'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Recurring Schedules (E04) ({schedules.length})
        </button>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* TAB 1: SCANS LIST & ACTIVE RUNS */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'SCANS' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
            <Table className="table-compact">
              <TableHeader>
                <TableRow>
                  <TableHead>Scan ID</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Target Scope</TableHead>
                  <TableHead>Progress & Stats</TableHead>
                  <TableHead>Assessed Compliance %</TableHead>
                  <TableHead>Assessment Coverage %</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => {
                  const isRunning = scan.status === 'RUNNING';
                  const isFailed = scan.status === 'FAILED';

                  return (
                    <TableRow key={scan.scan_id} className="hover:bg-slate-800/40">
                      <TableCell className="font-mono font-bold text-white">
                        <div className="flex items-center gap-2">
                          {isRunning && <RefreshCw className="w-3.5 h-3.5 text-sky-400 animate-spin" />}
                          {scan.scan_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-emerald-300 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">
                          <ShieldCheck className="w-3 h-3" /> READ-ONLY
                        </span>
                      </TableCell>
                      <TableCell className="text-slate-300">
                        {scan.requested_assets} Targets ({scan.profile_level})
                      </TableCell>
                      <TableCell>
                        {isRunning ? (
                          <div className="space-y-1 w-32">
                            <div className="flex justify-between text-[10px] font-mono text-slate-400">
                              <span>Collecting...</span>
                              <span>{scan.completed_assets}/{scan.requested_assets}</span>
                            </div>
                            <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className="bg-sky-500 h-1.5 rounded-full transition-all duration-500"
                                style={{ width: `${(scan.completed_assets / scan.requested_assets) * 100}%` }}
                              />
                            </div>
                          </div>
                        ) : isFailed ? (
                          <span className="font-mono text-xs text-rose-400 font-semibold">
                            {scan.failed_assets} Failed Targets
                          </span>
                        ) : (
                          <span className="font-mono text-xs text-emerald-400">
                            {scan.completed_assets}/{scan.requested_assets} Complete
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        {isRunning ? (
                          <span className="text-slate-500 font-mono text-xs">Computing...</span>
                        ) : (
                          <span className="font-mono font-bold text-emerald-400">
                            {scan.assessed_compliance_pct}%
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        {isRunning ? (
                          <span className="text-slate-500 font-mono text-xs">Evaluating...</span>
                        ) : (
                          <span className="font-mono text-slate-300">
                            {scan.assessment_coverage_pct}%
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-[10px] text-slate-400 uppercase">
                          {scan.trigger_type}
                        </span>
                      </TableCell>
                      <TableCell>
                        {scan.status === 'COMPLETED' && (
                          <Badge variant="success" className="text-[10px]">
                            COMPLETED
                          </Badge>
                        )}
                        {scan.status === 'RUNNING' && (
                          <Badge variant="outline" className="text-[10px] border-sky-500 text-sky-400 bg-sky-950/40">
                            RUNNING
                          </Badge>
                        )}
                        {scan.status === 'FAILED' && (
                          <Badge variant="destructive" className="text-[10px]">
                            FAILED
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {isFailed && (
                            <>
                              <Button
                                onClick={() => setInspectingScan(scan)}
                                variant="outline"
                                size="sm"
                                className="h-6 text-[10px] px-2 text-rose-300 border-rose-800 hover:bg-rose-950/40"
                              >
                                View Errors
                              </Button>
                              <Button
                                onClick={() => handleRetryScan(scan.scan_id)}
                                variant="outline"
                                size="sm"
                                className="h-6 text-[10px] px-2 gap-1 text-sky-400 border-sky-800 hover:bg-sky-950/40"
                              >
                                <RotateCcw className="w-3 h-3" /> Retry
                              </Button>
                            </>
                          )}
                          <Button
                            onClick={() => navigate(`/orgs/${orgId}/scans/${scan.scan_id}`)}
                            variant="secondary"
                            size="sm"
                            className="h-6 text-[10px] px-2"
                          >
                            Run Details
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* TAB 2: AUDIT LAUNCH WIZARD (M13, E08, E18) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'NEW_SCAN' && (
        <Card className="max-w-2xl mx-auto border-slate-800 bg-slate-900/90 shadow-2xl">
          <CardHeader className="border-b border-slate-800 pb-4">
            <CardTitle className="text-base font-bold text-white flex items-center gap-2">
              <Play className="w-4 h-4 text-sky-400 fill-current" />
              <span>Multi-Target Audit Scan Dispatcher (M13, E08, E18)</span>
            </CardTitle>
            <p className="text-xs text-slate-400">
              Configure target inventory scope, policy benchmark baseline, and confirm read-only probe execution.
            </p>
          </CardHeader>
          <CardContent className="pt-4">
            <form onSubmit={handleLaunchScan} className="space-y-5 text-xs">
              {wizardError && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/80 text-rose-300 text-xs flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{wizardError}</span>
                </div>
              )}

              {/* Step 1: Target Asset Scope */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="font-semibold text-slate-200">
                    Target Asset Scope ({selectedAssetIds.length} of {assets.length} selected)
                  </label>
                  <div className="flex items-center gap-2 text-[11px]">
                    <button
                      type="button"
                      onClick={selectAllAssets}
                      className="text-sky-400 hover:text-sky-300 font-mono"
                    >
                      Select All
                    </button>
                    <span className="text-slate-600">•</span>
                    <button
                      type="button"
                      onClick={clearAssetSelection}
                      className="text-slate-400 hover:text-slate-300 font-mono"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="border border-slate-800 rounded-lg bg-black/40 max-h-48 overflow-y-auto divide-y divide-slate-800/60 p-1">
                  {assets.map((asset) => {
                    const isSelected = selectedAssetIds.includes(asset.asset_id);
                    return (
                      <label
                        key={asset.asset_id}
                        className={`flex items-center justify-between p-2 rounded cursor-pointer transition-colors ${
                          isSelected ? 'bg-sky-950/30' : 'hover:bg-slate-800/30'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleAssetSelection(asset.asset_id)}
                            className="rounded text-sky-500 focus:ring-sky-500"
                          />
                          <div>
                            <div className="font-mono font-semibold text-slate-200 text-xs">{asset.hostname}</div>
                            <div className="text-[10px] text-slate-400 font-mono">
                              {asset.primary_ip} • {asset.platform}
                            </div>
                          </div>
                        </div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase">{asset.criticality}</span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Step 2: Policy Pack Selection */}
              <div className="space-y-2">
                <label className="font-semibold text-slate-200">Policy Benchmark Pack (M13)</label>
                <select
                  value={selectedPolicyPackId}
                  onChange={(e) => setSelectedPolicyPackId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:ring-1 focus:ring-sky-500"
                >
                  {policyPacks.map((pack) => (
                    <option key={pack.policy_pack_id} value={pack.policy_pack_id}>
                      {pack.name} ({pack.total_rules_count} rules)
                    </option>
                  ))}
                </select>
              </div>

              {/* Step 3: CIS Benchmark Profile Level */}
              <div className="space-y-2">
                <label className="font-semibold text-slate-200">CIS Benchmark Profile Level (E11)</label>
                <div className="grid grid-cols-2 gap-3">
                  <label
                    onClick={() => setSelectedProfileLevel('LEVEL_1')}
                    className={`flex items-start gap-2.5 p-3 rounded-lg border cursor-pointer transition-colors ${
                      selectedProfileLevel === 'LEVEL_1'
                        ? 'border-sky-500 bg-sky-950/40'
                        : 'border-slate-800 bg-slate-950/40 hover:bg-slate-900'
                    }`}
                  >
                    <input
                      type="radio"
                      name="profile"
                      checked={selectedProfileLevel === 'LEVEL_1'}
                      onChange={() => setSelectedProfileLevel('LEVEL_1')}
                      className="mt-0.5 text-sky-500"
                    />
                    <div>
                      <div className="font-bold text-white">Level 1 - Baseline</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Prudent practical security with minimal disruption to corporate services.
                      </div>
                    </div>
                  </label>

                  <label
                    onClick={() => setSelectedProfileLevel('LEVEL_2')}
                    className={`flex items-start gap-2.5 p-3 rounded-lg border cursor-pointer transition-colors ${
                      selectedProfileLevel === 'LEVEL_2'
                        ? 'border-sky-500 bg-sky-950/40'
                        : 'border-slate-800 bg-slate-950/40 hover:bg-slate-900'
                    }`}
                  >
                    <input
                      type="radio"
                      name="profile"
                      checked={selectedProfileLevel === 'LEVEL_2'}
                      onChange={() => setSelectedProfileLevel('LEVEL_2')}
                      className="mt-0.5 text-sky-500"
                    />
                    <div>
                      <div className="font-bold text-white">Level 2 - Defense-in-Depth</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        High-security tier controls; potential operational or usability impact.
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Step 4: Mandatory Read-Only Audit Execution Confirmation Checkbox (E18) */}
              <div className="p-3.5 bg-slate-950 rounded-lg border border-sky-900/60 space-y-2">
                <label className="flex items-start gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={readOnlyConfirmed}
                    onChange={(e) => setReadOnlyConfirmed(e.target.checked)}
                    className="mt-0.5 rounded text-sky-500 focus:ring-sky-500"
                    required
                  />
                  <div className="text-slate-300 text-xs leading-relaxed">
                    <span className="font-bold text-white">Confirm Read-Only Audit Execution (E18):</span>{' '}
                    I acknowledge that this assessment will execute strictly read-only collection probes (`collect(read_only=True)`) through SSH, WinRM, and REST APIs, and will make zero mutations to device configurations.
                  </div>
                </label>
              </div>

              <Button
                type="submit"
                disabled={!readOnlyConfirmed || isLaunching || selectedAssetIds.length === 0}
                className="w-full gap-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold h-9"
              >
                {isLaunching ? (
                  <>
                    <RotateCcw className="w-3.5 h-3.5 animate-spin" /> Dispatching Read-Only Collectors...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" /> Dispatch Audit Job ({selectedAssetIds.length} Targets)
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* TAB 3: RECURRING SCHEDULES (E04) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'SCHEDULES' && (
        <div className="space-y-4">
          <Card className="border-slate-800 bg-slate-900/90">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div>
                <CardTitle className="text-sm font-semibold">Active Cron Audit Schedules (E04)</CardTitle>
                <p className="text-xs text-slate-400">
                  Automated background recurring audits dispatched by Celery workers.
                </p>
              </div>
              <Button
                onClick={() => setIsAddingSchedule(true)}
                size="sm"
                className="text-xs gap-1.5 bg-sky-600 hover:bg-sky-500 text-white"
              >
                <Plus className="w-3.5 h-3.5" /> Add Schedule
              </Button>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {schedules.map((sched) => (
                  <div
                    key={sched.schedule_id}
                    className="p-3.5 bg-black/40 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="font-bold text-white flex items-center gap-2">
                        <span>{sched.name}</span>
                        <Badge
                          variant={sched.is_active ? 'success' : 'secondary'}
                          className="text-[10px]"
                        >
                          {sched.is_active ? 'ACTIVE' : 'PAUSED'}
                        </Badge>
                      </div>
                      <div className="text-slate-400 font-mono text-[11px] flex items-center gap-2">
                        <span className="text-sky-400 bg-sky-950/60 px-1.5 py-0.5 rounded border border-sky-800/80">
                          Cron: {sched.cron_expression}
                        </span>
                        <span>• Target: {sched.target_asset_group}</span>
                        <span>• {sched.profile_level}</span>
                      </div>
                      <div className="text-slate-500 text-[10px]">
                        Next run: {new Date(sched.next_run_at).toLocaleString()} UTC
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        onClick={() => handleToggleSchedule(sched.schedule_id)}
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs"
                      >
                        {sched.is_active ? 'Pause' : 'Activate'}
                      </Button>
                      <Button
                        onClick={() => handleDeleteSchedule(sched.schedule_id)}
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs text-slate-400 hover:text-rose-400"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* MODAL: CREATE SCHEDULE (E04) */}
      {/* ------------------------------------------------------------------ */}
      {isAddingSchedule && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Calendar className="w-4 h-4 text-sky-400" />
                <span>Create Recurring Audit Schedule (E04)</span>
              </h3>
              <button
                onClick={() => setIsAddingSchedule(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSchedule} className="space-y-4 text-xs">
              {scheduleError && (
                <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs">
                  {scheduleError}
                </div>
              )}

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Schedule Name</label>
                <Input
                  value={scheduleName}
                  onChange={(e) => setScheduleName(e.target.value)}
                  placeholder="e.g., Nightly Core Network Audit"
                  className="h-8 text-xs"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Cron Expression (5 Fields)</label>
                <Input
                  value={cronExpression}
                  onChange={(e) => setCronExpression(e.target.value)}
                  placeholder="0 0 * * * (Midnight daily)"
                  className="h-8 text-xs font-mono"
                  required
                />
                <p className="text-[10px] text-slate-400 font-mono">
                  Format: minute hour day-of-month month day-of-week
                </p>
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-300">Target Asset Group or Tag</label>
                <Input
                  value={scheduleTargetGroup}
                  onChange={(e) => setScheduleTargetGroup(e.target.value)}
                  placeholder="e.g., All Production Assets, pci-scope"
                  className="h-8 text-xs"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="font-semibold text-slate-300">Policy Pack</label>
                  <select
                    value={schedulePolicyPackId}
                    onChange={(e) => setSchedulePolicyPackId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                  >
                    {policyPacks.map((pack) => (
                      <option key={pack.policy_pack_id} value={pack.policy_pack_id}>
                        {pack.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="font-semibold text-slate-300">Profile Level</label>
                  <select
                    value={scheduleProfileLevel}
                    onChange={(e) => setScheduleProfileLevel(e.target.value as 'LEVEL_1' | 'LEVEL_2')}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                  >
                    <option value="LEVEL_1">Level 1 - Baseline</option>
                    <option value="LEVEL_2">Level 2 - Deep</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <Button
                  type="button"
                  onClick={() => setIsAddingSchedule(false)}
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
                  Save Schedule
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* MODAL: PER-TARGET SCAN ERRORS INSPECTION */}
      {/* ------------------------------------------------------------------ */}
      {inspectingScan && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-rose-400" />
                  <span>Target Execution Faults: {inspectingScan.scan_id}</span>
                </h3>
                <p className="text-[11px] text-slate-400 font-mono">
                  {inspectingScan.failed_assets} of {inspectingScan.requested_assets} target probes failed
                </p>
              </div>
              <button
                onClick={() => setInspectingScan(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 max-h-72 overflow-y-auto">
              {inspectingScan.target_errors && inspectingScan.target_errors.length > 0 ? (
                inspectingScan.target_errors.map((err, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-rose-950/20 border border-rose-900/60 rounded-lg space-y-1 text-xs"
                  >
                    <div className="font-mono font-bold text-rose-300">
                      Target: {err.hostname || err.asset_id}
                    </div>
                    <div className="font-mono text-[11px] text-slate-300">
                      Asset ID: {err.asset_id}
                    </div>
                    <div className="p-2 bg-black/60 rounded font-mono text-[11px] text-rose-200 overflow-x-auto">
                      {err.error}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-slate-400 text-xs italic">
                  No individual target error logs found.
                </div>
              )}
            </div>

            <div className="flex justify-between items-center pt-2 border-t border-slate-800">
              <Button
                onClick={() => {
                  const id = inspectingScan.scan_id;
                  setInspectingScan(null);
                  handleRetryScan(id);
                }}
                size="sm"
                className="h-8 text-xs bg-sky-600 hover:bg-sky-500 text-white gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" /> Retry Failed Scan
              </Button>
              <Button
                onClick={() => setInspectingScan(null)}
                variant="outline"
                size="sm"
                className="h-8 text-xs"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
