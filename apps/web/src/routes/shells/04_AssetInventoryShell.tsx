import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Server,
  Search,
  Plus,
  Key,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Radio,
  Trash2,
  X,
  ShieldCheck,
  Check,
} from 'lucide-react';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Badge } from '../../components/ui/badge';
import { EmptyState } from '../../components/common/EmptyState';
import { ConfirmDialog } from '../../components/common/ConfirmDialog';
import { useApi } from '../../api/context';
import { fixtureStore } from '../../api/store';
import { EvaluationStatus, PlatformFamily } from '../../contracts/v1/enums';
import type { Asset, DiscoveredCandidate } from '../../contracts/v1/types';
import { assetFormSchema, discoveryFormSchema } from '../../contracts/v1/schemas';

type AssetFormData = z.infer<typeof assetFormSchema>;
type DiscoveryFormData = z.infer<typeof discoveryFormSchema>;

export const AssetInventoryShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const api = useApi();

  const [assets, setAssets] = useState<Asset[]>(fixtureStore.assets);
  const [search, setSearch] = useState('');
  const [platformFilter, setPlatformFilter] = useState<string>('ALL');
  const [envFilter, setEnvFilter] = useState<string>('ALL');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);

  // Modal States
  const [showOnboardModal, setShowOnboardModal] = useState(false);
  const [showDiscoveryModal, setShowDiscoveryModal] = useState(false);
  const [onboardStep, setOnboardStep] = useState<1 | 2 | 3 | 4>(1);
  const [discoveryCandidates, setDiscoveryCandidates] = useState<DiscoveredCandidate[] | null>(null);
  const [retireTarget, setRetireTarget] = useState<Asset | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // 1. Asset Onboarding Form (E18)
  const {
    register: registerAsset,
    handleSubmit: handleAssetSubmit,
    setValue: setAssetValue,
    watch: watchAsset,
    trigger: triggerAsset,
    reset: resetAssetForm,
    formState: { errors: assetErrors, isSubmitting: isOnboarding },
  } = useForm<AssetFormData>({
    resolver: zodResolver(assetFormSchema),
    defaultValues: {
      hostname: '',
      primary_ip: '',
      platform: PlatformFamily.CISCO_IOS_SWITCH,
      vendor: 'Cisco Systems',
      model: 'Catalyst 9300',
      os_or_firmware_version: 'IOS-XE 17.09.03a',
      site: 'HQ-DataCenter-US',
      environment: 'production',
      criticality: 'HIGH',
      tags: ['core', 'network'],
      credential_reference_id: 'vault://secret/infra/cisco-core',
    },
  });

  const watchedPlatform = watchAsset('platform');

  const handleNextStep1 = async () => {
    const valid = await triggerAsset(['hostname', 'primary_ip', 'platform', 'vendor']);
    if (valid) setOnboardStep(2);
  };

  const handleNextStep2 = async () => {
    const valid = await triggerAsset(['site', 'environment', 'criticality']);
    if (valid) setOnboardStep(3);
  };

  const handleNextStep3 = async () => {
    const valid = await triggerAsset(['credential_reference_id']);
    if (valid) setOnboardStep(4);
  };

  // 2. Subnet Discovery Form (E02)
  const {
    register: registerDiscovery,
    handleSubmit: handleDiscoverySubmit,
    reset: resetDiscoveryForm,
    formState: { errors: discoveryErrors, isSubmitting: isDiscovering },
  } = useForm<DiscoveryFormData>({
    resolver: zodResolver(discoveryFormSchema),
    defaultValues: {
      cidr_ranges: ['192.168.10.0/24'],
      ports_to_probe: [22, 443, 80, 445],
      scope_consent_confirmed: true,
    },
  });

  // Filter Assets
  const filteredAssets = assets.filter((a) => {
    const matchesSearch =
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.primary_ip.includes(search) ||
      a.vendor.toLowerCase().includes(search.toLowerCase()) ||
      a.model.toLowerCase().includes(search.toLowerCase());

    const matchesPlatform = platformFilter === 'ALL' || a.platform === platformFilter;
    const matchesEnv = envFilter === 'ALL' || a.environment === envFilter;
    const matchesTag = !selectedTag || a.tags.includes(selectedTag);

    return matchesSearch && matchesPlatform && matchesEnv && matchesTag;
  });

  // All unique tags for tag filter pills (E03)
  const allTags = Array.from(new Set(assets.flatMap((a) => a.tags)));

  // Submit Device Onboarding (E18)
  const onSaveAsset = async (data: AssetFormData) => {
    try {
      const res = await api.createAsset(orgId || 'demo-org', data);
      setAssets([...fixtureStore.assets]);
      setShowOnboardModal(false);
      resetAssetForm();
      setOnboardStep(1);
      setActionNotice(`Asset ${res.data.hostname} successfully onboarded with vault pointer.`);
    } catch (err: unknown) {
      setActionNotice(`Onboarding failed: ${(err as Error)?.message}`);
    }
  };

  // Submit Subnet Discovery Sweep (E02)
  const onRunDiscovery = async (data: DiscoveryFormData) => {
    try {
      const res = await api.previewDiscovery({
        cidr_ranges: data.cidr_ranges,
        ports_to_probe: data.ports_to_probe,
        scope_consent_confirmed: data.scope_consent_confirmed,
      });
      setDiscoveryCandidates(res.data);
    } catch (err: unknown) {
      setActionNotice(`Discovery sweep failed: ${(err as Error)?.message}`);
    }
  };

  // Convert candidate to onboarding
  const handleOnboardCandidate = (candidate: DiscoveredCandidate) => {
    setAssetValue('primary_ip', candidate.ip);
    setAssetValue('hostname', `cand-${candidate.ip.replace(/\./g, '-')}.local`);
    if (candidate.estimated_platform) {
      setAssetValue('platform', candidate.estimated_platform);
    }
    if (candidate.mac_vendor) {
      setAssetValue('vendor', candidate.mac_vendor);
    }
    setShowDiscoveryModal(false);
    setShowOnboardModal(true);
    setOnboardStep(1);
  };

  // Retire Asset
  const handleConfirmRetire = async () => {
    if (!retireTarget) return;
    try {
      await api.retireAsset(retireTarget.asset_id);
      setAssets([...fixtureStore.assets]);
      setActionNotice(`Asset ${retireTarget.hostname} retired from active compliance monitoring.`);
      setRetireTarget(null);
    } catch (err: unknown) {
      setActionNotice(`Retirement failed: ${(err as Error)?.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-sky-400" />
            Asset Inventory (E01)
          </h1>
          <p className="text-xs text-slate-400">
            {assets.length} managed targets enrolled with centralized OpenBao credential references (E15).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => {
              setDiscoveryCandidates(null);
              resetDiscoveryForm();
              setShowDiscoveryModal(true);
            }}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
          >
            <Radio className="w-3.5 h-3.5 text-sky-400" />
            Authorized Discovery (E02)
          </Button>
          <Button
            onClick={() => {
              resetAssetForm();
              setOnboardStep(1);
              setShowOnboardModal(true);
            }}
            variant="default"
            size="sm"
            className="gap-1.5 text-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            Onboard Device (E18)
          </Button>
        </div>
      </div>

      {/* Action Notice */}
      {actionNotice && (
        <div className="p-3 bg-sky-950/80 border border-sky-800 rounded-lg text-xs text-sky-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
            <span>{actionNotice}</span>
          </div>
          <button onClick={() => setActionNotice(null)} className="text-slate-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px] max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2 pointer-events-none" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search hostname, IP, vendor, model..."
            className="pl-9 h-8 text-xs"
          />
        </div>

        {/* Platform Filter */}
        <select
          value={platformFilter}
          onChange={(e) => setPlatformFilter(e.target.value)}
          className="h-8 px-2.5 rounded-md border border-slate-700 bg-slate-900 text-xs text-slate-200"
          aria-label="Filter by Platform"
        >
          <option value="ALL">All Platforms</option>
          <option value={PlatformFamily.CISCO_IOS_SWITCH}>Cisco IOS / XE</option>
          <option value={PlatformFamily.FORTINET_FORTIOS}>Fortinet FortiOS</option>
          <option value={PlatformFamily.CHECKPOINT_GAIA}>Check Point Gaia</option>
          <option value={PlatformFamily.SOPHOS_SFOS}>Sophos Firewall</option>
          <option value={PlatformFamily.PALO_ALTO_PANOS}>Palo Alto PAN-OS</option>
          <option value={PlatformFamily.UBUNTU_22_04}>Ubuntu Linux</option>
          <option value={PlatformFamily.WINDOWS_SERVER_2019}>Windows Server</option>
        </select>

        {/* Environment Filter */}
        <select
          value={envFilter}
          onChange={(e) => setEnvFilter(e.target.value)}
          className="h-8 px-2.5 rounded-md border border-slate-700 bg-slate-900 text-xs text-slate-200"
          aria-label="Filter by Environment"
        >
          <option value="ALL">All Environments</option>
          <option value="production">Production</option>
          <option value="staging">Staging</option>
          <option value="lab">Lab / Testing</option>
        </select>

        {/* Reset Filters */}
        {(search || platformFilter !== 'ALL' || envFilter !== 'ALL' || selectedTag) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch('');
              setPlatformFilter('ALL');
              setEnvFilter('ALL');
              setSelectedTag(null);
            }}
            className="h-8 text-xs text-slate-400 hover:text-white"
          >
            Clear Filters
          </Button>
        )}
      </div>

      {/* Device Tags Filter Pills (E03 Custom Device Grouping & Tagging) */}
      <div className="flex items-center gap-1.5 flex-wrap text-xs">
        <span className="text-[11px] text-slate-500 font-mono flex items-center gap-1 mr-1">
          <Filter className="w-3 h-3" /> Tags:
        </span>
        {allTags.map((tag) => (
          <button
            key={tag}
            onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
            className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors border ${
              selectedTag === tag
                ? 'bg-sky-600 border-sky-500 text-white font-bold'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            #{tag}
          </button>
        ))}
      </div>

      {/* High-Density Asset Table */}
      {filteredAssets.length === 0 ? (
        <EmptyState
          title="No Matching Devices Found"
          description="Adjust your search criteria, environment filter, or onboard a new device to this workspace."
          action={{
            label: 'Onboard Device',
            onClick: () => {
              resetAssetForm();
              setShowOnboardModal(true);
            },
          }}
        />
      ) : (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Hostname & IP</TableHead>
                <TableHead>Platform / OS</TableHead>
                <TableHead>Vendor & Model</TableHead>
                <TableHead>Environment & Site</TableHead>
                <TableHead>Tags (E03)</TableHead>
                <TableHead>Vault Ref (E15)</TableHead>
                <TableHead>Audit Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAssets.map((asset) => (
                <TableRow key={asset.asset_id}>
                  <TableCell>
                    <div className="font-mono font-bold text-white text-xs">{asset.hostname}</div>
                    <div className="font-mono text-[11px] text-slate-400">{asset.primary_ip}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="font-mono text-[10px] uppercase">
                      {asset.platform}
                    </Badge>
                    <div className="text-[10px] text-slate-400 truncate max-w-[140px]" title={asset.os_or_firmware_version}>
                      {asset.os_or_firmware_version}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium text-slate-200">{asset.vendor}</div>
                    <div className="text-[11px] text-slate-400">{asset.model}</div>
                  </TableCell>
                  <TableCell>
                    <span className="text-[11px] font-mono capitalize text-slate-300">{asset.environment}</span>
                    <div className="text-[10px] text-slate-500">{asset.site}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {asset.tags.map((tag) => (
                        <span key={tag} className="text-[9px] font-mono bg-slate-800 text-slate-300 px-1 py-0.2 rounded border border-slate-700">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="inline-flex items-center gap-1 font-mono text-[10px] text-slate-400 bg-black/50 px-1.5 py-0.5 rounded border border-slate-800">
                      <Key className="w-2.5 h-2.5 text-amber-400 shrink-0" />
                      <span className="truncate max-w-[120px]" title={asset.credential_reference_id}>
                        {asset.credential_reference_id}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {asset.last_scan_status === EvaluationStatus.PASS ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono font-semibold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                      </span>
                    ) : asset.last_scan_status === EvaluationStatus.FAIL ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-mono font-semibold">
                        <XCircle className="w-3.5 h-3.5" /> FAIL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] text-slate-400 font-mono">
                        NOT SCANNED
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="inline-flex items-center gap-1">
                      <Button
                        onClick={() => navigate(`/orgs/${orgId}/assets/${asset.asset_id}`)}
                        variant="outline"
                        size="sm"
                        className="h-6 text-[10px] px-2"
                      >
                        Details
                      </Button>
                      <Button
                        onClick={() => setRetireTarget(asset)}
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 text-slate-400 hover:text-rose-400"
                        title="Retire Asset"
                      >
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* MODAL 1: Device Onboarding Wizard (E18) */}
      {showOnboardModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="max-w-xl w-full bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative">
            <button
              onClick={() => setShowOnboardModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
                <Server className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Device Onboarding Wizard (E18)</h3>
                <p className="text-xs text-slate-400">Step {onboardStep} of 4</p>
              </div>
            </div>

            {/* Stepper Tabs */}
            <div className="grid grid-cols-4 gap-2 mb-6 font-mono text-[10px] text-center border-b border-slate-800 pb-3">
              <div className={onboardStep === 1 ? 'text-sky-400 font-bold' : 'text-slate-500'}>1. Specs</div>
              <div className={onboardStep === 2 ? 'text-sky-400 font-bold' : 'text-slate-500'}>2. Site & Risk</div>
              <div className={onboardStep === 3 ? 'text-sky-400 font-bold' : 'text-slate-500'}>3. OpenBao Vault</div>
              <div className={onboardStep === 4 ? 'text-sky-400 font-bold' : 'text-slate-500'}>4. Probe Check</div>
            </div>

            <form onSubmit={handleAssetSubmit(onSaveAsset)} className="space-y-4" noValidate>
              {/* STEP 1: Specs */}
              {onboardStep === 1 && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Hostname</label>
                      <Input
                        placeholder="e.g. CORE-SW-01.acme.local"
                        {...registerAsset('hostname')}
                        aria-invalid={!!assetErrors.hostname}
                        className="h-8 text-xs font-mono"
                      />
                      {assetErrors.hostname && (
                        <p className="text-[11px] text-red-400">{assetErrors.hostname.message}</p>
                      )}
                    </div>

                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Primary IPv4</label>
                      <Input
                        placeholder="e.g. 192.168.10.1"
                        {...registerAsset('primary_ip')}
                        aria-invalid={!!assetErrors.primary_ip}
                        className="h-8 text-xs font-mono"
                      />
                      {assetErrors.primary_ip && (
                        <p className="text-[11px] text-red-400">{assetErrors.primary_ip.message}</p>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Platform Family</label>
                      <select
                        {...registerAsset('platform')}
                        className="w-full h-8 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white"
                      >
                        <option value={PlatformFamily.CISCO_IOS_SWITCH}>Cisco IOS / IOS-XE</option>
                        <option value={PlatformFamily.FORTINET_FORTIOS}>Fortinet FortiOS</option>
                        <option value={PlatformFamily.CHECKPOINT_GAIA}>Check Point Gaia</option>
                        <option value={PlatformFamily.SOPHOS_SFOS}>Sophos Firewall</option>
                        <option value={PlatformFamily.PALO_ALTO_PANOS}>Palo Alto PAN-OS</option>
                        <option value={PlatformFamily.UBUNTU_22_04}>Ubuntu Linux</option>
                        <option value={PlatformFamily.WINDOWS_SERVER_2019}>Windows Server</option>
                      </select>
                    </div>

                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Vendor</label>
                      <Input
                        placeholder="e.g. Cisco Systems"
                        {...registerAsset('vendor')}
                        className="h-8 text-xs"
                      />
                      {assetErrors.vendor && (
                        <p className="text-[11px] text-red-400">{assetErrors.vendor.message}</p>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Hardware Model</label>
                      <Input
                        placeholder="e.g. Catalyst 9300"
                        {...registerAsset('model')}
                        className="h-8 text-xs"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Firmware / OS Version</label>
                      <Input
                        placeholder="e.g. 17.09.03a"
                        {...registerAsset('os_or_firmware_version')}
                        className="h-8 text-xs font-mono"
                      />
                    </div>
                  </div>

                  <div className="flex justify-end pt-3">
                    <Button type="button" onClick={handleNextStep1} size="sm" className="text-xs">
                      Continue to Site & Risk
                    </Button>
                  </div>
                </div>
              )}

              {/* STEP 2: Site, Environment & Criticality */}
              {onboardStep === 2 && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Site Identifier</label>
                      <Input
                        placeholder="e.g. HQ-DataCenter-US"
                        {...registerAsset('site')}
                        className="h-8 text-xs"
                      />
                      {assetErrors.site && (
                        <p className="text-[11px] text-red-400">{assetErrors.site.message}</p>
                      )}
                    </div>

                    <div className="space-y-1">
                      <label className="text-xs font-medium text-slate-300">Environment</label>
                      <select
                        {...registerAsset('environment')}
                        className="w-full h-8 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white"
                      >
                        <option value="production">Production</option>
                        <option value="staging">Staging</option>
                        <option value="lab">Lab / Testing</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-medium text-slate-300">Asset Criticality</label>
                    <select
                      {...registerAsset('criticality')}
                      className="w-full h-8 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white"
                    >
                      <option value="CRITICAL">CRITICAL (Direct Backbone / Perimeter)</option>
                      <option value="HIGH">HIGH (Aggregation / Core Switch)</option>
                      <option value="MEDIUM">MEDIUM (Access Layer Switch)</option>
                      <option value="LOW">LOW (Management Jump Host)</option>
                    </select>
                  </div>

                  <div className="flex justify-between pt-3">
                    <Button type="button" variant="ghost" onClick={() => setOnboardStep(1)} size="sm" className="text-xs">
                      Back
                    </Button>
                    <Button type="button" onClick={handleNextStep2} size="sm" className="text-xs">
                      Continue to Vault Pointer
                    </Button>
                  </div>
                </div>
              )}

              {/* STEP 3: OpenBao Vault Secret Reference (E15) */}
              {onboardStep === 3 && (
                <div className="space-y-4">
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-amber-400" />
                      OpenBao Secret Path Pointer (E15)
                    </label>
                    <Input
                      placeholder="vault://secret/infra/cisco-core-01"
                      {...registerAsset('credential_reference_id')}
                      aria-invalid={!!assetErrors.credential_reference_id}
                      className="h-8 text-xs font-mono text-amber-300"
                    />
                    {assetErrors.credential_reference_id && (
                      <p className="text-[11px] text-red-400">{assetErrors.credential_reference_id.message}</p>
                    )}
                  </div>

                  <div className="p-3 bg-black/40 border border-slate-800 rounded text-xs space-y-2">
                    <div className="flex items-center gap-1.5 font-semibold text-amber-400 text-[11px]">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Zero-Plaintext Secret Architecture Guarantee
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Under E15, BaselineGuard frontend NEVER accepts or holds raw passwords, SSH private keys, or API tokens. Only registered OpenBao secret path pointers are stored.
                    </p>
                  </div>

                  <div className="flex justify-between pt-3">
                    <Button type="button" variant="ghost" onClick={() => setOnboardStep(2)} size="sm" className="text-xs">
                      Back
                    </Button>
                    <Button type="button" onClick={handleNextStep3} size="sm" className="text-xs">
                      Continue to Capability Pre-Check
                    </Button>
                  </div>
                </div>
              )}

              {/* STEP 4: Capability & Pre-Check */}
              {onboardStep === 4 && (
                <div className="space-y-4">
                  <div className="p-3 bg-black/50 border border-slate-800 rounded text-xs space-y-2">
                    <div className="font-semibold text-white flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Read-Only Capability Pre-Check: {watchedPlatform}
                    </div>
                    <ul className="space-y-1 text-[11px] text-slate-300 font-mono">
                      <li className="flex items-center gap-1.5 text-emerald-400">
                        <Check className="w-3.5 h-3.5" /> SSH Port 22 Accessible (Read-Only session)
                      </li>
                      <li className="flex items-center gap-1.5 text-emerald-400">
                        <Check className="w-3.5 h-3.5" /> CIS Level 1 & Level 2 benchmark rules available
                      </li>
                      <li className="flex items-center gap-1.5 text-emerald-400">
                        <Check className="w-3.5 h-3.5" /> Cryptographic evidence hashing (SHA-256) ready
                      </li>
                    </ul>
                  </div>

                  <div className="flex justify-between pt-3">
                    <Button type="button" variant="ghost" onClick={() => setOnboardStep(3)} size="sm" className="text-xs">
                      Back
                    </Button>
                    <Button type="submit" disabled={isOnboarding} size="sm" className="text-xs gap-1.5">
                      <Plus className="w-3.5 h-3.5" />
                      {isOnboarding ? 'Enrolling...' : 'Complete Device Onboarding'}
                    </Button>
                  </div>
                </div>
              )}
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Authorized Subnet Discovery Sweep (E02) */}
      {showDiscoveryModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="max-w-2xl w-full bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative">
            <button
              onClick={() => setShowDiscoveryModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
                <Radio className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Authorized Subnet Discovery Sweep (E02)</h3>
                <p className="text-xs text-slate-400">Non-intrusive port detection for unmanaged candidates</p>
              </div>
            </div>

            <form onSubmit={handleDiscoverySubmit(onRunDiscovery)} className="space-y-4" noValidate>
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Authorized Subnet Range (CIDR)</label>
                <Input
                  placeholder="e.g. 192.168.10.0/24"
                  {...registerDiscovery('cidr_ranges.0')}
                  aria-invalid={!!discoveryErrors.cidr_ranges}
                  className="h-8 text-xs font-mono"
                />
                {discoveryErrors.cidr_ranges && (
                  <p className="text-[11px] text-red-400">{discoveryErrors.cidr_ranges.message}</p>
                )}
              </div>

              {/* Mandatory Consent Checkbox */}
              <div className="p-3 bg-black/40 border border-slate-800 rounded text-xs space-y-2">
                <label className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    {...registerDiscovery('scope_consent_confirmed')}
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-sky-500"
                  />
                  <span className="text-[11px] text-slate-300 font-medium">
                    I confirm that our organization has authorized ownership or explicit written authorization to probe this subnet range (Strictly read-only ping & port probe).
                  </span>
                </label>
                {discoveryErrors.scope_consent_confirmed && (
                  <p className="text-[11px] text-red-400">{discoveryErrors.scope_consent_confirmed.message}</p>
                )}
              </div>

              <div className="flex justify-end gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowDiscoveryModal(false)}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={isDiscovering} size="sm" className="text-xs gap-1.5">
                  <Radio className="w-3.5 h-3.5" />
                  {isDiscovering ? 'Probing...' : 'Run Authorized Sweep'}
                </Button>
              </div>
            </form>

            {/* Discovery Candidates Table */}
            {discoveryCandidates && (
              <div className="mt-6 space-y-3 pt-4 border-t border-slate-800">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">Discovered Candidates ({discoveryCandidates.length})</span>
                  <span className="text-slate-500 font-mono text-[10px]">Pending Onboarding (Unassessed)</span>
                </div>

                <div className="rounded border border-slate-800 bg-black/40 overflow-hidden">
                  <Table className="table-compact">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Candidate IP</TableHead>
                        <TableHead>Open Ports</TableHead>
                        <TableHead>Vendor / Inferred Platform</TableHead>
                        <TableHead>Response</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {discoveryCandidates.map((c) => (
                        <TableRow key={c.ip}>
                          <TableCell className="font-mono text-white text-xs">{c.ip}</TableCell>
                          <TableCell className="font-mono text-xs text-sky-400">
                            {c.open_ports.join(', ')}
                          </TableCell>
                          <TableCell className="text-xs">
                            <span className="text-slate-300">{c.mac_vendor || 'Unknown'}</span>
                            <div className="text-[10px] text-slate-500 uppercase">{c.estimated_platform || 'Generic'}</div>
                          </TableCell>
                          <TableCell className="font-mono text-[11px] text-slate-400">
                            {c.response_time_ms}ms
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              onClick={() => handleOnboardCandidate(c)}
                              size="sm"
                              className="h-6 text-[10px] px-2"
                            >
                              Onboard
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* CONFIRM DIALOG: Retire Asset */}
      {retireTarget && (
        <ConfirmDialog
          isOpen={!!retireTarget}
          title="Retire Asset from Active Inventory?"
          description={`Are you sure you want to retire ${retireTarget.hostname} (${retireTarget.primary_ip})? The asset will be excluded from future automated scans. Historical compliance evidence and proof packages remain permanently preserved.`}
          danger
          onConfirm={handleConfirmRetire}
          onClose={() => setRetireTarget(null)}
        />
      )}
    </div>
  );
};
