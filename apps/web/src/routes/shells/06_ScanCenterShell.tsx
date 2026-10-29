import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Radar, Play, Calendar, RotateCcw, ShieldCheck } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { Badge } from '../../components/ui/badge';
import { fixtureStore } from '../../api/store';

export const ScanCenterShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'SCANS' | 'NEW_SCAN' | 'SCHEDULES'>('SCANS');
  const [readOnlyConfirmed, setReadOnlyConfirmed] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);

  const scans = fixtureStore.scans;

  const handleLaunchScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!readOnlyConfirmed) return;
    setIsLaunching(true);
    setTimeout(() => {
      setIsLaunching(false);
      setActiveTab('SCANS');
    }, 1000);
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
            Automated read-only compliance collection and deterministic rule evaluation queue.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setActiveTab('NEW_SCAN')}
            size="sm"
            className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Launch Audit Wizard
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('SCANS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'SCANS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Audit History & Active Runs
        </button>
        <button
          onClick={() => setActiveTab('NEW_SCAN')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'NEW_SCAN'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Launch Audit (Wizard)
        </button>
        <button
          onClick={() => setActiveTab('SCHEDULES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'SCHEDULES'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Recurring Schedules (E04)
        </button>
      </div>

      {/* Scans List Tab */}
      {activeTab === 'SCANS' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Scan ID</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Target Scope</TableHead>
                <TableHead>Assessed Compliance %</TableHead>
                <TableHead>Assessment Coverage %</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.scan_id}>
                  <TableCell className="font-mono font-bold text-white">{scan.scan_id}</TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-emerald-300 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">
                      <ShieldCheck className="w-3 h-3" /> READ-ONLY
                    </span>
                  </TableCell>
                  <TableCell className="text-slate-300">
                    {scan.requested_assets} Targets ({scan.profile_level})
                  </TableCell>
                  <TableCell>
                    <span className="font-mono font-bold text-emerald-400">{scan.assessed_compliance_pct}%</span>
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-slate-300">{scan.assessment_coverage_pct}%</span>
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-[10px] text-slate-400">{scan.trigger_type}</span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="success" className="text-[10px]">
                      {scan.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      onClick={() => navigate(`/orgs/${orgId}/scans/${scan.scan_id}`)}
                      variant="outline"
                      size="sm"
                      className="h-6 text-[10px] px-2"
                    >
                      View Run Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* New Scan Wizard */}
      {activeTab === 'NEW_SCAN' && (
        <Card className="max-w-xl mx-auto border-slate-800 bg-slate-900/90 shadow-2xl">
          <CardHeader>
            <CardTitle>Launch Central Multi-Target Audit (M13, E08)</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
              <div className="space-y-1.5">
                <label className="font-medium text-slate-300">Target Asset Scope</label>
                <div className="p-3 bg-black/40 rounded border border-slate-800 space-y-2">
                  <div className="font-semibold text-slate-200">
                    All 11 Registered Assets Selected (Windows, Linux, Firewalls, Switches)
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Centralized dispatcher utilizes Nornir, WinRM, and Paramiko collectors.
                  </div>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="font-medium text-slate-300">CIS Benchmark Profile Level (E11)</label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="flex items-center gap-2 p-2.5 rounded border border-sky-600 bg-sky-950/30 cursor-pointer">
                    <input type="radio" name="profile" defaultChecked className="text-sky-500" />
                    <div>
                      <div className="font-bold text-white">Level 1 - Baseline</div>
                      <div className="text-[10px] text-slate-400">Prudent practical security with minimal operational impact</div>
                    </div>
                  </label>
                  <label className="flex items-center gap-2 p-2.5 rounded border border-slate-800 bg-slate-900/40 cursor-pointer">
                    <input type="radio" name="profile" className="text-sky-500" />
                    <div>
                      <div className="font-bold text-white">Level 2 - Defense-in-Depth</div>
                      <div className="text-[10px] text-slate-400">High-security environments; potential usability impact</div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Mandatory Read-Only Confirmation Checkbox (E18) */}
              <div className="p-3 bg-slate-950 rounded-lg border border-sky-900/60 space-y-2">
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
                    I acknowledge that this assessment will execute strictly read-only collection probes (`collect(read_only=True)`) and will make zero mutations to device configurations.
                  </div>
                </label>
              </div>

              <Button
                type="submit"
                disabled={!readOnlyConfirmed || isLaunching}
                className="w-full gap-2 bg-sky-600 hover:bg-sky-500 text-white"
              >
                {isLaunching ? (
                  <>
                    <RotateCcw className="w-3.5 h-3.5 animate-spin" /> Dispatching Collectors...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" /> Dispatch Audit Job (DEMO)
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Schedules Tab */}
      {activeTab === 'SCHEDULES' && (
        <Card className="border-slate-800 bg-slate-900/90">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-semibold">Active Cron Audit Schedules (E04)</CardTitle>
            <Button size="sm" variant="outline" className="text-xs gap-1.5">
              <Calendar className="w-3.5 h-3.5" /> Add Schedule
            </Button>
          </CardHeader>
          <CardContent>
            <div className="p-3 bg-black/40 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono">
              <div>
                <div className="font-bold text-white">Daily Midnight Full Fleet Audit</div>
                <div className="text-slate-400 text-[11px]">Cron: 0 0 * * * • Target: All Production (Level 1)</div>
              </div>
              <div className="text-right">
                <span className="text-emerald-400 font-semibold">ACTIVE</span>
                <div className="text-slate-500 text-[10px]">Next Run: Tonight at 00:00 UTC</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

