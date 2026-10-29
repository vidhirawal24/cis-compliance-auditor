import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  Server,
  Radar,
  ArrowUpRight,
  AlertTriangle,
  Play,
  TrendingUp,
  BarChart3,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  HelpCircle,
  MinusCircle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';
import { StatCard } from '../../components/common/StatCard';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { Button } from '../../components/ui/button';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { fixtureStore } from '../../api/store';
import { EvaluationStatus, SeverityLevel } from '../../contracts/v1/enums';

export const OverviewShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const currentScan = fixtureStore.scans[0];
  const assets = fixtureStore.assets;
  const findings = fixtureStore.findings;
  const trends = fixtureStore.complianceTrends;

  // Counts by Severity
  const criticalCount = findings.filter((f) => f.severity === SeverityLevel.CRITICAL).length;
  const highCount = findings.filter((f) => f.severity === SeverityLevel.HIGH).length;
  const mediumCount = findings.filter((f) => f.severity === SeverityLevel.MEDIUM).length;
  const lowCount = findings.filter((f) => f.severity === SeverityLevel.LOW).length;

  // Counts by Evaluation Status (Immutable 6 Statuses)
  const passCount = findings.filter((f) => f.status === EvaluationStatus.PASS).length;
  const failCount = findings.filter((f) => f.status === EvaluationStatus.FAIL).length;
  const naCount = findings.filter((f) => f.status === EvaluationStatus.NOT_APPLICABLE).length;
  const manualCount = findings.filter((f) => f.status === EvaluationStatus.MANUAL_REVIEW).length;
  const errorCount = findings.filter((f) => f.status === EvaluationStatus.ERROR).length;
  const notAssessedCount = findings.filter((f) => f.status === EvaluationStatus.NOT_ASSESSED).length;

  // Severity Distribution for Pie Chart
  const severityChartData = [
    { name: 'Critical', value: criticalCount, color: '#f43f5e' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ].filter((d) => d.value > 0);

  // Platform Breakdown Data
  const platformPostureData = [
    {
      category: 'Windows',
      passed: assets.filter((a) => a.platform.includes('windows') && a.last_scan_status === EvaluationStatus.PASS).length,
      failed: assets.filter((a) => a.platform.includes('windows') && a.last_scan_status === EvaluationStatus.FAIL).length,
    },
    {
      category: 'Linux',
      passed: assets.filter((a) => (a.platform.includes('ubuntu') || a.platform.includes('rhel')) && a.last_scan_status === EvaluationStatus.PASS).length,
      failed: assets.filter((a) => (a.platform.includes('ubuntu') || a.platform.includes('rhel')) && a.last_scan_status === EvaluationStatus.FAIL).length,
    },
    {
      category: 'Cisco IOS',
      passed: assets.filter((a) => a.platform.includes('cisco_ios') && a.last_scan_status === EvaluationStatus.PASS).length,
      failed: assets.filter((a) => a.platform.includes('cisco_ios') && a.last_scan_status === EvaluationStatus.FAIL).length,
    },
    {
      category: 'Firewalls',
      passed: assets.filter((a) => (a.platform.includes('fortinet') || a.platform.includes('checkpoint') || a.platform.includes('palo_alto') || a.platform.includes('sophos') || a.platform.includes('cisco_asa')) && a.last_scan_status === EvaluationStatus.PASS).length,
      failed: assets.filter((a) => (a.platform.includes('fortinet') || a.platform.includes('checkpoint') || a.platform.includes('palo_alto') || a.platform.includes('sophos') || a.platform.includes('cisco_asa')) && a.last_scan_status === EvaluationStatus.FAIL).length,
    },
  ];

  // Category Risk Summary
  const categories = Array.from(new Set(findings.map((f) => f.category)));
  const categorySummary = categories.map((cat) => {
    const catFindings = findings.filter((f) => f.category === cat);
    const hasCritical = catFindings.some((f) => f.severity === SeverityLevel.CRITICAL);
    const hasHigh = catFindings.some((f) => f.severity === SeverityLevel.HIGH);
    const highestSev = hasCritical ? SeverityLevel.CRITICAL : hasHigh ? SeverityLevel.HIGH : SeverityLevel.MEDIUM;
    return {
      name: cat,
      total: catFindings.length,
      highestSev,
      fails: catFindings.filter((f) => f.status === EvaluationStatus.FAIL).length,
    };
  });

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Security Posture & Compliance Overview
          </h1>
          <p className="text-xs text-slate-400">
            Real-time deterministic posture computed across {assets.length} registered assets against CIS Benchmarks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/scans?tab=NEW_SCAN`)}
            size="sm"
            className="gap-2 bg-sky-600 hover:bg-sky-500 text-white"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Launch Audit Scan
          </Button>
          <Button
            onClick={() => navigate(`/orgs/${orgId}/reports`)}
            variant="outline"
            size="sm"
            className="gap-1.5"
          >
            <ArrowUpRight className="w-3.5 h-3.5" />
            Export Dossier
          </Button>
        </div>
      </div>

      {/* Scoring Invariant KPI Cards: Compliance and Coverage shown SEPARATELY */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="ASSESSED COMPLIANCE"
          value={`${currentScan.assessed_compliance_pct}%`}
          subtitle="Formula: PASS / (PASS + FAIL)"
          change={{ value: 2.9, trend: 'up', period: 'vs last week' }}
          icon={ShieldCheck}
          badge={{ text: 'PASS RATE', variant: 'success' }}
        />

        <StatCard
          title="ASSESSMENT COVERAGE"
          value={`${currentScan.assessment_coverage_pct}%`}
          subtitle="Assessed rules / Total applicable rules"
          change={{ value: 2.6, trend: 'up', period: 'coverage expansion' }}
          icon={Radar}
          badge={{ text: 'AUDITED', variant: 'outline' }}
        />

        <StatCard
          title="REGISTERED ASSETS"
          value={assets.length}
          subtitle="Windows, Linux, Firewalls, Cisco"
          icon={Server}
          badge={{ text: '11 ACTIVE', variant: 'outline' }}
        />

        <StatCard
          title="ACTIVE FINDINGS"
          value={findings.length}
          subtitle={`${criticalCount} Critical • ${highCount} High`}
          icon={ShieldAlert}
          badge={{ text: 'REQUIRES ACTION', variant: 'destructive' }}
        />
      </div>

      {/* Evaluation Status Invariant Banner (All 6 Immutable Statuses) */}
      <Card className="border-slate-800 bg-slate-900/90">
        <CardHeader className="py-3 px-4 border-b border-slate-800">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <CardTitle className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <span>CIS Benchmark Rule Evaluation Manifest (6 Invariant Statuses)</span>
            </CardTitle>
            <span className="text-[11px] font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/80">
              Integrity Rule: NOT_ASSESSED is NEVER counted as PASS
            </span>
          </div>
        </CardHeader>
        <CardContent className="p-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-900/60 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-emerald-400 font-semibold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                </div>
                <div className="text-lg font-bold font-mono text-emerald-200 mt-1">{passCount}</div>
              </div>
              <span className="text-[10px] text-emerald-400/80 font-mono">Compliant</span>
            </div>

            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-rose-400 font-semibold flex items-center gap-1.5">
                  <XCircle className="w-3.5 h-3.5" /> FAIL
                </div>
                <div className="text-lg font-bold font-mono text-rose-200 mt-1">{failCount}</div>
              </div>
              <span className="text-[10px] text-rose-400/80 font-mono">Violated</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-slate-400 font-semibold flex items-center gap-1.5">
                  <MinusCircle className="w-3.5 h-3.5" /> NOT APPLICABLE
                </div>
                <div className="text-lg font-bold font-mono text-slate-200 mt-1">{naCount}</div>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">Excluded</span>
            </div>

            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-900/60 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-amber-400 font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> MANUAL REVIEW
                </div>
                <div className="text-lg font-bold font-mono text-amber-200 mt-1">{manualCount}</div>
              </div>
              <span className="text-[10px] text-amber-400/80 font-mono">Human Signoff</span>
            </div>

            <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/60 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-red-400 font-semibold flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5" /> ERROR
                </div>
                <div className="text-lg font-bold font-mono text-red-200 mt-1">{errorCount}</div>
              </div>
              <span className="text-[10px] text-red-400/80 font-mono">Collector Fault</span>
            </div>

            <div className="p-3 rounded-lg bg-purple-950/40 border border-purple-900/60 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono text-purple-300 font-semibold flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5" /> NOT ASSESSED
                </div>
                <div className="text-lg font-bold font-mono text-purple-200 mt-1">{notAssessedCount}</div>
              </div>
              <span className="text-[10px] text-purple-400/80 font-mono">Excluded from PASS</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recharts Intelligence: 30-Day Trend (E07) & Severity Breakdown (M35) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Compliance Trend Line Chart (E07) */}
        <Card className="lg:col-span-8 border-slate-800 bg-slate-900/90">
          <CardHeader className="pb-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" />
                <span>30-Day Posture Historical Trend (E07)</span>
              </CardTitle>
              <span className="text-xs font-mono text-slate-400">
                Assessed Compliance % vs Assessment Coverage %
              </span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-64 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <LineChart data={trends} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis domain={[50, 100]} stroke="#64748b" tick={{ fontSize: 11 }} unit="%" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#090d16', borderColor: '#334155', fontSize: '12px' }}
                    labelStyle={{ color: '#94a3b8', fontWeight: 'bold' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                  <Line
                    type="monotone"
                    dataKey="assessed_compliance_pct"
                    name="Assessed Compliance % (PASS Rate)"
                    stroke="#10b981"
                    strokeWidth={2.5}
                    dot={{ fill: '#10b981', r: 3 }}
                    activeDot={{ r: 6 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="assessment_coverage_pct"
                    name="Assessment Coverage % (Applicable)"
                    stroke="#38bdf8"
                    strokeWidth={2}
                    strokeDasharray="4 4"
                    dot={{ fill: '#38bdf8', r: 3 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs text-slate-400 font-mono">
              <span>Start: 58.4% Compliance (30d ago)</span>
              <span className="text-emerald-400 font-bold">Current: {currentScan.assessed_compliance_pct}% (+14.3%)</span>
            </div>
          </CardContent>
        </Card>

        {/* Severity Distribution Donut / List (M35) */}
        <Card className="lg:col-span-4 border-slate-800 bg-slate-900/90 flex flex-col justify-between">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center justify-between">
              <span className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-rose-400" />
                <span>Severity Breakdown (M35)</span>
              </span>
              <span className="text-xs font-mono text-slate-400 font-normal">
                {findings.length} Total Findings
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <PieChart>
                  <Pie
                    data={severityChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#090d16', borderColor: '#334155', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800">
                <SeverityBadge severity={SeverityLevel.CRITICAL} />
                <span className="font-mono font-bold text-rose-400">{criticalCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800">
                <SeverityBadge severity={SeverityLevel.HIGH} />
                <span className="font-mono font-bold text-orange-400">{highCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800">
                <SeverityBadge severity={SeverityLevel.MEDIUM} />
                <span className="font-mono font-bold text-yellow-400">{mediumCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-black/40 border border-slate-800">
                <SeverityBadge severity={SeverityLevel.LOW} />
                <span className="font-mono font-bold text-blue-400">{lowCount}</span>
              </div>
            </div>

            <Button
              onClick={() => navigate(`/orgs/${orgId}/findings`)}
              variant="outline"
              size="sm"
              className="w-full text-xs mt-1"
            >
              Explore All Findings ({findings.length})
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Platform Posture Breakdown & Category Risk Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Platform Breakdown Stacked Bar Chart */}
        <Card className="lg:col-span-5 border-slate-800 bg-slate-900/90">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center justify-between">
              <span>Platform Family Compliance Posture</span>
              <span className="text-xs font-mono text-slate-400">11 Assets</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <BarChart data={platformPostureData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="category" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#090d16', borderColor: '#334155', fontSize: '11px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar dataKey="passed" name="Compliant (PASS)" fill="#10b981" stackId="a" />
                  <Bar dataKey="failed" name="Non-Compliant (FAIL)" fill="#f43f5e" stackId="a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Heterogeneous fleet posture audited via unified read-only abstraction (Nornir, WinRM, Paramiko).
            </p>
          </CardContent>
        </Card>

        {/* Category Risk Table */}
        <Card className="lg:col-span-7 border-slate-800 bg-slate-900/90">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold">CIS Benchmark Category Risk Distribution</CardTitle>
              <Button
                onClick={() => navigate(`/orgs/${orgId}/findings`)}
                variant="ghost"
                size="sm"
                className="text-xs h-7 text-sky-400"
              >
                View Explorer &rarr;
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <Table className="table-compact text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Control Category</TableHead>
                  <TableHead>Max Severity</TableHead>
                  <TableHead>Active Violations</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {categorySummary.slice(0, 5).map((cat) => (
                  <TableRow key={cat.name}>
                    <TableCell className="font-medium text-slate-200">{cat.name}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={cat.highestSev} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono font-bold text-rose-400">{cat.fails} Failures</span>{' '}
                      <span className="text-slate-500 font-mono text-[10px]">({cat.total} total)</span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        onClick={() => navigate(`/orgs/${orgId}/findings?category=${encodeURIComponent(cat.name)}`)}
                        variant="outline"
                        size="sm"
                        className="h-6 text-[10px] px-2"
                      >
                        Filter
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Cross-Device Risk Scenario & Recent Scan Manifest */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Cross-Device Risk Scenario Callout (I02, I05) */}
        <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-900/60 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1.5 text-xs">
            <div className="font-bold text-rose-200 text-sm">
              High-Risk Attack Path Detected (Cross-Device Scenario)
            </div>
            <p className="text-slate-300 text-xs leading-relaxed">
              Perimeter ASA firewall wildcard ACL directly exposes edge router telnet management port and app server root SSH.
            </p>
            <div className="pt-1">
              <Button
                onClick={() => navigate(`/orgs/${orgId}/risk-scenarios`)}
                variant="outline"
                size="sm"
                className="text-xs text-rose-300 border-rose-800 hover:bg-rose-950/40"
              >
                Inspect Risk Chain & What-If Simulation &rarr;
              </Button>
            </div>
          </div>
        </div>

        {/* Recent Audit Job Manifest (M13, E04) */}
        <div className="p-4 rounded-lg bg-black/40 border border-slate-800 flex flex-col justify-between gap-3 text-xs">
          <div className="flex items-center justify-between">
            <div className="font-mono font-bold text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Manifest: {currentScan.scan_id}
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
              READ-ONLY AUDIT VERIFIED
            </span>
          </div>

          <div className="text-slate-400 font-mono text-[11px]">
            Completed {new Date(currentScan.completed_at || '').toLocaleTimeString()} UTC • 11 Heterogeneous Targets Evaluated
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
            <div>
              <span className="text-emerald-400 font-mono font-bold">{currentScan.assessed_compliance_pct}% Pass</span>{' '}
              <span className="text-slate-500 font-mono">({currentScan.assessment_coverage_pct}% Covered)</span>
            </div>
            <Button
              onClick={() => navigate(`/orgs/${orgId}/scans/${currentScan.scan_id}`)}
              variant="secondary"
              size="sm"
              className="text-xs h-7"
            >
              View Run Logs
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
