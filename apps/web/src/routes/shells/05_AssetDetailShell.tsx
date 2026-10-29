import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Server,
  ArrowLeft,
  Key,
  Shield,
  AlertTriangle,
  Edit3,
  Trash2,
  CheckCircle2,
  HelpCircle,
  ShieldCheck,
  X,
  FileCode,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { StatusBadge } from '../../components/common/StatusBadge';
import { ConfirmDialog } from '../../components/common/ConfirmDialog';
import { useApi } from '../../api/context';
import { fixtureStore } from '../../api/store';
import type { Asset } from '../../contracts/v1/types';

const editAssetSchema = z.object({
  hostname: z.string().min(1, 'Hostname is required').max(255),
  site: z.string().min(1, 'Site identifier is required'),
  environment: z.enum(['production', 'staging', 'lab']),
  criticality: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  tags: z.string(), // Comma-separated for easy edit
  credential_reference_id: z.string().min(1, 'Vault pointer is required'),
});

type EditAssetFormData = z.infer<typeof editAssetSchema>;

export const AssetDetailShell: React.FC = () => {
  const { orgId, assetId } = useParams<{ orgId: string; assetId: string }>();
  const navigate = useNavigate();
  const api = useApi();

  const initialAsset = fixtureStore.assets.find((a) => a.asset_id === assetId) || fixtureStore.assets[0];
  const [asset, setAsset] = useState<Asset>(initialAsset);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'INTERFACES' | 'FINDINGS' | 'SNAPSHOTS'>('OVERVIEW');
  const [showEditModal, setShowEditModal] = useState(false);
  const [showRetireConfirm, setShowRetireConfirm] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const findings = fixtureStore.findings.filter((f) => f.asset_id === asset.asset_id);
  const interfaces = fixtureStore.switchInterfaces;

  // Edit Asset Form
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<EditAssetFormData>({
    resolver: zodResolver(editAssetSchema),
    defaultValues: {
      hostname: asset.hostname,
      site: asset.site,
      environment: asset.environment,
      criticality: asset.criticality,
      tags: asset.tags.join(', '),
      credential_reference_id: asset.credential_reference_id,
    },
  });

  const onUpdateAsset = async (data: EditAssetFormData) => {
    try {
      const updatedTags = data.tags.split(',').map((t) => t.trim()).filter(Boolean);
      const res = await api.updateAsset(asset.asset_id, {
        hostname: data.hostname,
        site: data.site,
        environment: data.environment,
        criticality: data.criticality,
        tags: updatedTags,
        credential_reference_id: data.credential_reference_id,
      });
      setAsset(res.data);
      setShowEditModal(false);
      setNotice(`Asset ${res.data.hostname} updated successfully.`);
    } catch (err: unknown) {
      setNotice(`Update failed: ${(err as Error)?.message}`);
    }
  };

  const onRetireAsset = async () => {
    try {
      await api.retireAsset(asset.asset_id);
      navigate(`/orgs/${orgId}/assets`);
    } catch (err: unknown) {
      setNotice(`Retire failed: ${(err as Error)?.message}`);
    }
  };

  // Supported vs Unsupported Capabilities for this target
  const supportedCapabilities = [
    { id: 'cap-01', name: 'Interface ACL & VLAN Inspection', rule: 'CIS 1.1 - 1.4' },
    { id: 'cap-02', name: 'Cryptographic Protocol Enforcement (SSH v2, TLS 1.3)', rule: 'CIS 2.1 - 2.3' },
    { id: 'cap-03', name: 'NTP Cryptographic Authentication', rule: 'CIS 3.1' },
    { id: 'cap-04', name: 'AAA TACACS+ / RADIUS Authorization Audit', rule: 'CIS 4.1 - 4.4' },
  ];

  const unsupportedCapabilities = [
    {
      id: 'uncap-01',
      name: 'BGP Route Hijack Protection (ROA)',
      reason: 'Requires Advanced Routing firmware package; not licensed on this target.',
    },
    {
      id: 'uncap-02',
      name: 'Hardware CoPP Rate-Limiter ASIC Counters',
      reason: 'Collector facts indicate virtualized switch hypervisor emulation.',
    },
  ];

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
            title="Back to Asset Inventory"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white font-mono">{asset.hostname}</h1>
              <Badge variant="secondary" className="font-mono text-[10px] uppercase">
                {asset.platform}
              </Badge>
              <span className="text-[11px] font-mono capitalize px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {asset.environment}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              IP: {asset.primary_ip} • Site: {asset.site} • {asset.vendor} {asset.model}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Masked OpenBao Vault Reference Pointer */}
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-black/50 border border-slate-800 font-mono text-xs text-slate-300">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-500">Vault:</span>
            <span className="font-semibold text-amber-300 truncate max-w-[160px]" title={asset.credential_reference_id}>
              {asset.credential_reference_id}
            </span>
          </div>

          <Button
            onClick={() => setShowEditModal(true)}
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1.5"
          >
            <Edit3 className="w-3.5 h-3.5" />
            Edit
          </Button>

          <Button
            onClick={() => setShowRetireConfirm(true)}
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-slate-400 hover:text-rose-400 gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Retire
          </Button>
        </div>
      </div>

      {/* Notice */}
      {notice && (
        <div className="p-3 bg-sky-950/80 border border-sky-800 rounded-lg text-xs text-sky-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice(null)} className="text-slate-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'OVERVIEW'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          System Overview
        </button>
        <button
          onClick={() => setActiveTab('INTERFACES')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'INTERFACES'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Interfaces & L2/L3 (M11)
        </button>
        <button
          onClick={() => setActiveTab('FINDINGS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'FINDINGS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Findings ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('SNAPSHOTS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'SNAPSHOTS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Snapshots & Drift (E06)
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'OVERVIEW' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Specs & Facts */}
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
                  <span className="text-slate-200">Authorized SSH (Read-Only)</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60 font-mono">
                  <span className="text-slate-400">Tags (E03):</span>
                  <span className="text-sky-300">{asset.tags.join(', ')}</span>
                </div>
                <div className="flex justify-between py-1 font-mono">
                  <span className="text-slate-400">Last Assessed:</span>
                  <span className="text-slate-200">{asset.last_assessed_at || 'Never'}</span>
                </div>
              </CardContent>
            </Card>

            {/* Compliance Posture Summary */}
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
                    <div className="text-xs text-slate-400">Latest Audit Result</div>
                    <div className="text-sm font-bold font-mono text-rose-400 flex items-center gap-1.5 mt-0.5">
                      <AlertTriangle className="w-4 h-4" /> {findings.length} Non-Compliant Findings
                    </div>
                  </div>
                  <Button
                    onClick={() => setActiveTab('FINDINGS')}
                    size="sm"
                    variant="outline"
                    className="text-xs h-7"
                  >
                    Review Rules
                  </Button>
                </div>

                {/* OpenBao Vault Secret Reference Info */}
                <div className="p-3 bg-black/40 rounded-lg border border-slate-800 text-xs space-y-1">
                  <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5 text-amber-400" />
                    OpenBao Secret Path Pointer (E15)
                  </div>
                  <p className="font-mono text-[11px] text-amber-300 truncate">
                    {asset.credential_reference_id}
                  </p>
                  <p className="text-[10px] text-slate-500">
                    Rotated via HashiCorp/OpenBao AppRole. Secret material is never exposed to browser memory.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Supported vs Unsupported Capabilities (Clearly Labeled) */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="border-slate-800 bg-slate-900/90">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" />
                  Supported CIS Capabilities ({supportedCapabilities.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {supportedCapabilities.map((cap) => (
                  <div
                    key={cap.id}
                    className="p-2.5 bg-black/30 border border-slate-800/80 rounded flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="text-white font-medium">{cap.name}</div>
                      <div className="text-[10px] text-slate-500 font-mono">{cap.rule}</div>
                    </div>
                    <Badge variant="success" className="text-[9px]">ACTIVE</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="border-slate-800 bg-slate-900/90">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                  <HelpCircle className="w-4 h-4" />
                  Unsupported / Excluded Capabilities ({unsupportedCapabilities.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {unsupportedCapabilities.map((uncap) => (
                  <div
                    key={uncap.id}
                    className="p-2.5 bg-black/30 border border-amber-950/40 rounded text-xs space-y-1"
                  >
                    <div className="text-slate-300 font-medium flex items-center justify-between">
                      <span>{uncap.name}</span>
                      <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-800">
                        EXCLUDED
                      </Badge>
                    </div>
                    <p className="text-[10px] text-slate-500">{uncap.reason}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* TAB 2: INTERFACES */}
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
                  <TableCell className="font-mono font-bold text-white text-xs">{intf.name}</TableCell>
                  <TableCell className="font-mono text-slate-400 text-xs">{intf.mac_address}</TableCell>
                  <TableCell className="font-mono text-xs">{intf.ipv4_address || '—'}</TableCell>
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

      {/* TAB 3: FINDINGS */}
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

      {/* TAB 4: SNAPSHOTS & DRIFT (E06) */}
      {activeTab === 'SNAPSHOTS' && (
        <Card className="border-slate-800 bg-slate-900/90">
          <CardHeader>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileCode className="w-4 h-4 text-sky-400" />
              Configuration Snapshots & Baseline Archive (E06)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="p-3 bg-black/40 rounded-lg border border-slate-800 flex items-center justify-between font-mono text-xs">
              <div>
                <div className="text-white font-bold">snap-2026-1029-01 (Current Effective Baseline)</div>
                <div className="text-slate-500 text-[11px]">
                  SHA256: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b
                </div>
                <div className="text-emerald-400 text-[10px] mt-0.5">Encrypted AES-GCM (OpenBao Key Managed)</div>
              </div>
              <Badge variant="outline" className="text-[10px] text-sky-400 border-sky-800">
                ACTIVE BASELINE
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}

      {/* MODAL: Edit Asset */}
      {showEditModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative">
            <button
              onClick={() => setShowEditModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
                <Edit3 className="w-4 h-4" />
              </div>
              <h3 className="text-base font-bold text-white">Edit Managed Asset</h3>
            </div>

            <form onSubmit={handleSubmit(onUpdateAsset)} className="space-y-3" noValidate>
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Hostname</label>
                <Input
                  {...register('hostname')}
                  aria-invalid={!!errors.hostname}
                  className="h-8 text-xs font-mono"
                />
                {errors.hostname && (
                  <p className="text-[11px] text-red-400">{errors.hostname.message}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Site</label>
                  <Input {...register('site')} className="h-8 text-xs" />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Environment</label>
                  <select
                    {...register('environment')}
                    className="w-full h-8 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="lab">Lab / Testing</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Criticality</label>
                <select
                  {...register('criticality')}
                  className="w-full h-8 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Tags (comma-separated, E03)</label>
                <Input {...register('tags')} className="h-8 text-xs font-mono" />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                  <Key className="w-3 h-3 text-amber-400" />
                  OpenBao Secret Path Pointer (E15)
                </label>
                <Input
                  {...register('credential_reference_id')}
                  className="h-8 text-xs font-mono text-amber-300"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowEditModal(false)}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={isSubmitting} size="sm" className="text-xs gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  {isSubmitting ? 'Saving...' : 'Save Changes'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CONFIRM DIALOG: Retire Asset */}
      {showRetireConfirm && (
        <ConfirmDialog
          isOpen={showRetireConfirm}
          title="Retire Asset from Active Inventory?"
          description={`Are you sure you want to retire ${asset.hostname} (${asset.primary_ip})? Future audit scans will skip this target. All historical compliance snapshots and proof packages remain permanently preserved.`}
          danger
          onConfirm={onRetireAsset}
          onClose={() => setShowRetireConfirm(false)}
        />
      )}
    </div>
  );
};
