import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Server, Search, Plus, Key, Filter, CheckCircle2, XCircle } from 'lucide-react';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Badge } from '../../components/ui/badge';
import { fixtureStore } from '../../api/store';
import { EvaluationStatus } from '../../contracts/v1/enums';

export const AssetInventoryShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const assets = fixtureStore.assets;

  const filteredAssets = assets.filter(
    (a) =>
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.primary_ip.includes(search) ||
      a.vendor.toLowerCase().includes(search.toLowerCase()) ||
      a.platform.toLowerCase().includes(search.toLowerCase())
  );

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
            {assets.length} managed targets registered with authorized credential references.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/assets/discover`)}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
          >
            <Filter className="w-3.5 h-3.5" />
            Authorized Discovery (E02)
          </Button>
          <Button
            onClick={() => navigate(`/orgs/${orgId}/assets/import`)}
            variant="default"
            size="sm"
            className="gap-1.5 text-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Asset
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2 pointer-events-none" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by hostname, IP, vendor, or platform..."
            className="pl-9 h-8 text-xs"
          />
        </div>
      </div>

      {/* High-Density Asset Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
        <Table className="table-compact">
          <TableHeader>
            <TableRow>
              <TableHead>Hostname & IP</TableHead>
              <TableHead>Platform / OS</TableHead>
              <TableHead>Vendor & Model</TableHead>
              <TableHead>Environment & Site</TableHead>
              <TableHead>Tags</TableHead>
              <TableHead>Credential Ref</TableHead>
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
                    <span className="truncate max-w-[100px]" title={asset.credential_reference_id}>
                      {asset.credential_reference_id}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  {asset.last_scan_status === EvaluationStatus.PASS ? (
                    <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono font-semibold">
                      <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-mono font-semibold">
                      <XCircle className="w-3.5 h-3.5" /> FAIL
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    onClick={() => navigate(`/orgs/${orgId}/assets/${asset.asset_id}`)}
                    variant="outline"
                    size="sm"
                    className="h-6 text-[10px] px-2"
                  >
                    Details
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
};

