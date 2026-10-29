import React, { useState } from 'react';
import { BookOpen, Sliders, Sparkles, Shield } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';

export const PolicyLibraryShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'PACKS' | 'OVERRIDES' | 'UPGRADE_PREVIEW'>('PACKS');

  const policyPacks = [
    {
      id: 'cis-cisco-ios-v4',
      name: 'CIS Cisco IOS 17.x Benchmark',
      version: 'v4.0.0',
      platform: 'Cisco IOS/IOS-XE',
      rulesCount: 88,
      status: 'ACTIVE',
    },
    {
      id: 'cis-ubuntu-22-v2',
      name: 'CIS Ubuntu Linux 22.04 LTS Benchmark',
      version: 'v2.1.0',
      platform: 'Ubuntu 22.04',
      rulesCount: 142,
      status: 'ACTIVE',
    },
    {
      id: 'cis-win11-v3',
      name: 'CIS Microsoft Windows 11 Enterprise Benchmark',
      version: 'v3.0.0',
      platform: 'Windows 11',
      rulesCount: 198,
      status: 'ACTIVE',
    },
    {
      id: 'cis-fortigate-v2',
      name: 'CIS Fortinet FortiGate 7.x Benchmark',
      version: 'v2.0.0',
      platform: 'FortiOS',
      rulesCount: 64,
      status: 'ACTIVE',
    },
  ];

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
            Versioned, explainable rule packs with organization overrides and upgrade impact simulation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setActiveTab('UPGRADE_PREVIEW')}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs text-sky-400 border-sky-800/80 hover:bg-sky-950/40"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Benchmark Upgrade Impact Preview (I19)
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('PACKS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'PACKS'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Active Benchmark Packs (M17)
        </button>
        <button
          onClick={() => setActiveTab('OVERRIDES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'OVERRIDES'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Custom Baseline Overrides (M18)
        </button>
        <button
          onClick={() => setActiveTab('UPGRADE_PREVIEW')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'UPGRADE_PREVIEW'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Upgrade Impact Preview (I19)
        </button>
      </div>

      {/* Packs Tab */}
      {activeTab === 'PACKS' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {policyPacks.map((pack) => (
            <Card key={pack.id} className="border-slate-800 bg-slate-900/90 p-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-white">{pack.name}</h2>
                    <span className="font-mono text-[11px] text-slate-400">Platform: {pack.platform}</span>
                  </div>
                </div>
                <Badge variant="outline" className="font-mono text-xs text-sky-300 border-sky-800">
                  {pack.version}
                </Badge>
              </div>

              <div className="p-2.5 rounded bg-black/40 border border-slate-800 flex items-center justify-between text-xs font-mono mb-4">
                <span className="text-slate-400">Total Evaluators:</span>
                <span className="font-bold text-white">{pack.rulesCount} Rules (L1/L2)</span>
              </div>

              <div className="flex justify-end gap-2">
                <Button variant="outline" size="sm" className="text-xs h-7">
                  Inspect Rule YAML (M17)
                </Button>
                <Button size="sm" className="text-xs h-7">
                  Configure Profiles (E11)
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Overrides Tab */}
      {activeTab === 'OVERRIDES' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Sliders className="w-4 h-4 text-amber-400" />
              Organizational Threshold Overrides (M18)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-3">
            <p className="text-xs text-slate-400 leading-relaxed">
              Define organization-specific policy adjustments separate from upstream CIS benchmark rules.
              Changing an override creates an attributable version history event without corrupting benchmark source integrity.
            </p>

            <div className="p-3 bg-black/40 rounded border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-white font-bold">VTY Idle Session Timeout (CIS 2.1.2)</span>
                <span className="text-amber-400 font-bold">Org Override: 10 mins (CIS standard: 5 mins)</span>
              </div>
              <div className="text-[11px] text-slate-500">
                Justification: Approved by CISO for remote NOC operations (Ticket SEC-8891)
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Upgrade Impact Preview Tab */}
      {activeTab === 'UPGRADE_PREVIEW' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4 space-y-4">
          <CardHeader className="p-0 pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-sky-400" />
              Benchmark Upgrade Impact Preview (I19)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-4 text-xs">
            <p className="text-slate-400 leading-relaxed">
              Simulate the effect of upgrading CIS Cisco IOS Benchmark from <span className="font-mono text-white">v3.2.0</span> to <span className="font-mono text-sky-400">v4.0.0</span> against current fleet configurations before publishing the pack.
            </p>

            <div className="grid grid-cols-3 gap-3 p-3 bg-black/40 rounded border border-slate-800 text-center font-mono">
              <div>
                <div className="text-slate-500 text-[10px]">NEW RULES ADDED</div>
                <div className="text-sky-400 font-bold text-sm">+14 Rules</div>
              </div>
              <div>
                <div className="text-slate-500 text-[10px]">MODIFIED CHECKS</div>
                <div className="text-amber-400 font-bold text-sm">8 Rules</div>
              </div>
              <div>
                <div className="text-slate-500 text-[10px]">PREDICTED COMPLIANCE DELTA</div>
                <div className="text-rose-400 font-bold text-sm">-3.8% Impact</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

