import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Server,
  ArrowLeft,
  Key,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { StatusBadge } from '../../components/common/StatusBadge';
import { fixtureStore } from '../../api/store';

export const AssetDetailShell: React.FC = () => {
  const { orgId, assetId } = useParams<{ orgId: string; assetId: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'INTERFACES' | 'FINDINGS' | 'SNAPSHOTS'>('OVERVIEW');

  const asset = fixtureStore.assets.find((a) => a.asset_id === assetId) || fixtureStore.assets[0];
  const findings = fixtureStore.findings.filter((f) => f.asset_id === asset.asset_id);
  const interfaces = fixtureStore.switchInterfaces;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/assets`)}
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white font-mono">{asset.hostname}</h1>
              <Badge variant="secondary" className="font-mono text-[10px] uppercase">
                {asset.platform}
              </Badge>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              IP: {asset.primary_ip} • Site: {asset.site} • {asset.vendor} {asset.model}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-black/50 border border-slate-800 font-mono text-xs text-slate-300">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-500">Vault Pointer:</span>
            <span className="font-semibold">{asset.credential_reference_id}</span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'OVERVIEW'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          System Overview
        </button>
        <button
          onClick={() => setActiveTab('INTERFACES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'INTERFACES'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Interfaces & L2/L3 (M11)
        </button>
        <button
          onClick={() => setActiveTab('FINDINGS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'FINDINGS'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Findings ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('SNAPSHOTS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'SNAPSHOTS'
            ? 'border-sky-500 text-sky-400 bg-sky-950/20'
            : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Snapshots & Drift (E06)
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'OVERVIEW' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="border-slate-800 bg-slate-900/90">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Server className="w-4 h-4 text-sky-400" />
                Device Specification & Collector Facts
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/60 font-mono">
                <span className="text-slate-400">Firmware / Kernel:</span>
                <span className="text-slate-200">{asset.os_or_firmware_version}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60 font-mono">
                <span className="text-slate-400">Environment:</span>
                <span className="text-slate-200 capitalize">{asset.environment}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60 font-mono">
                <span className="text-slate-400">Criticality:</span>
                <span className="text-rose-400 font-bold">{asset.criticality}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60 font-mono">
                <span className="text-slate-400">Collection Channel:</span>
                <span className="text-slate-200">Authorized SSH/WinRM (Read-Only)</span>
              </div>
              <div className="flex justify-between py-1 font-mono">
                <span className="text-slate-400">Last Assessed:</span>
                <span className="text-slate-200">{asset.last_assessed_at || 'Never'}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-900/90">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Compliance Posture Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-3 bg-black/40 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs text-slate-400">Asset Audit Result</div>
                  <div className="text-sm font-bold font-mono text-rose-400 flex items-center gap-1.5 mt-0.5">
                    <AlertTriangle className="w-4 h-4" /> 1 Non-Compliant Finding
                  </div>
                </div>
                <Button
                  onClick={() => setActiveTab('FINDINGS')}
                  size="sm"
                  variant="outline"
                  className="text-xs h-7"
                >
                  Review Rule
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'INTERFACES' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Interface</TableHead>
                <TableHead>MAC Address</TableHead>
                <TableHead>IPv4 Address</TableHead>
                <TableHead>VLAN</TableHead>
                <TableHead>Management</TableHead>
                <TableHead>Port Security</TableHead>
                <TableHead>Admin State</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {interfaces.map((intf) => (
                <TableRow key={intf.interface_id}>
                  <TableCell className="font-mono font-bold">{intf.name}</TableCell>
                  <TableCell className="font-mono text-slate-400">{intf.mac_address}</TableCell>
                  <TableCell className="font-mono">{intf.ipv4_address || '—'}</TableCell>
                  <TableCell>
                    <span className={`font-mono text-xs ${intf.vlan_id === 1 ? 'text-rose-400 font-bold' : 'text-slate-300'}`}>
                      VLAN {intf.vlan_id} {intf.vlan_id === 1 && '(M30 Violation)'}
                    </span>
                  </TableCell>
                  <TableCell>
                    {intf.is_management ? (
                      <Badge variant="warning" className="text-[10px]">MGMT</Badge>
                    ) : (
                      <span className="text-slate-500 text-xs">Data</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {intf.port_security_enabled ? (
                      <Badge variant="success" className="text-[10px]">ENABLED (Max {intf.max_mac_count})</Badge>
                    ) : (
                      <Badge variant="destructive" className="text-[10px]">DISABLED (M27)</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {intf.is_unused_disabled ? (
                      <span className="text-slate-400 font-mono text-xs">Shutdown</span>
                    ) : (
                      <span className="text-amber-400 font-mono text-xs font-semibold">Enabled</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {activeTab === 'FINDINGS' && (
        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="p-8 text-center border border-slate-800 rounded-lg text-slate-400 text-xs">
              No failed controls recorded for this target in the last scan.
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.finding_id}
                className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-xs text-slate-400">{f.control_id}</span>
                  </div>
                  <h2 className="text-sm font-semibold text-white">{f.title}</h2>
                  <p className="text-xs text-slate-400">{f.category}</p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <StatusBadge status={f.status} hasException={!!f.exception} />
                  <Button
                    onClick={() => navigate(`/orgs/${orgId}/findings/${f.finding_id}`)}
                    size="sm"
                    className="text-xs h-7"
                  >
                    View Diff & Evidence
                  </Button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'SNAPSHOTS' && (
        <Card className="border-slate-800 bg-slate-900/90">
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Configuration Snapshots Archive</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="p-3 bg-black/40 rounded-lg border border-slate-800 flex items-center justify-between font-mono text-xs">
              <div>
                <div className="text-white font-bold">snap-2026-1029-01 (Current Effective)</div>
                <div className="text-slate-500 text-[11px]">SHA256: 7a8b9c0d1e2f3a4b... (Encrypted AES-GCM)</div>
              </div>
              <Badge variant="outline" className="text-[10px]">LIVE BASELINE</Badge>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

