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
} from 'lucide-react';
import { StatCard } from '../../components/common/StatCard';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { Button } from '../../components/ui/button';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { fixtureStore } from '../../api/store';
import { SeverityLevel } from '../../contracts/v1/enums';

export const OverviewShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const currentScan = fixtureStore.scans[0];
  const assets = fixtureStore.assets;
  const findings = fixtureStore.findings;

  const criticalCount = findings.filter((f) => f.severity === SeverityLevel.CRITICAL).length;
  const highCount = findings.filter((f) => f.severity === SeverityLevel.HIGH).length;
  const mediumCount = findings.filter((f) => f.severity === SeverityLevel.MEDIUM).length;
  const lowCount = findings.filter((f) => f.severity === SeverityLevel.LOW).length;

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Security Posture & Compliance Overview
          </h1>
          <p className="text-xs text-slate-400">
            Real-time deterministic posture computed across {assets.length} registered assets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/scans/new`)}
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
          subtitle="44 assessed of 52 rules"
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

      {/* Severity Breakdown & Quick Ticker */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Card */}
        <Card className="lg:col-span-1 border-slate-800 bg-slate-900/90">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center justify-between">
              <span>Severity Breakdown (M35)</span>
              <span className="text-xs font-mono text-slate-400 font-normal">7 Total</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between p-2.5 rounded bg-black/40 border border-slate-800">
              <SeverityBadge severity={SeverityLevel.CRITICAL} />
              <span className="font-mono text-sm font-bold text-rose-400">{criticalCount}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-black/40 border border-slate-800">
              <SeverityBadge severity={SeverityLevel.HIGH} />
              <span className="font-mono text-sm font-bold text-orange-400">{highCount}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-black/40 border border-slate-800">
              <SeverityBadge severity={SeverityLevel.MEDIUM} />
              <span className="font-mono text-sm font-bold text-yellow-400">{mediumCount}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-black/40 border border-slate-800">
              <SeverityBadge severity={SeverityLevel.LOW} />
              <span className="font-mono text-sm font-bold text-blue-400">{lowCount}</span>
            </div>

            <Button
              onClick={() => navigate(`/orgs/${orgId}/findings`)}
              variant="outline"
              size="sm"
              className="w-full text-xs mt-2"
            >
              Explore All Findings
            </Button>
          </CardContent>
        </Card>

        {/* Scan Status & Asset Posture Grid */}
        <Card className="lg:col-span-2 border-slate-800 bg-slate-900/90">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center justify-between">
              <span>Recent Audit Job Manifest (M13, E04)</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                READ-ONLY SCAN VERIFIED
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-black/40 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="font-mono font-bold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    {currentScan.scan_id}
                  </div>
                  <div className="text-slate-400 font-mono text-[11px]">
                    Completed {new Date(currentScan.completed_at || '').toLocaleTimeString()} • 11 Targets Audited
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-emerald-400 font-mono font-bold">{currentScan.assessed_compliance_pct}% Pass</div>
                    <div className="text-slate-500 font-mono text-[10px]">{currentScan.assessment_coverage_pct}% Covered</div>
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

              {/* Cross-Device Risk Scenario Callout (I02, I05) */}
              <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-900/60 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <div className="font-bold text-rose-200">
                    High-Risk Attack Path Detected (Cross-Device Scenario)
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    Perimeter ASA firewall wildcard ACL directly exposes edge router telnet management port and app server root SSH.
                  </p>
                  <Button
                    onClick={() => navigate(`/orgs/${orgId}/risk-scenarios`)}
                    variant="link"
                    className="text-xs text-rose-400 hover:text-rose-300 font-semibold"
                  >
                    Inspect Risk Chain & What-If Simulation &rarr;
                  </Button>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

