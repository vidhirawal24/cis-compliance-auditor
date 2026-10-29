import React, { useState } from 'react';
import { FileText, Download, Clock, GitCompare } from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { ConfigDiff } from '../../components/common/ConfigDiff';
import { fixtureStore } from '../../api/store';
import { formatBytes } from '../../lib/utils';

export const ReportsHistoryShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'REPORTS' | 'DRIFT'>('REPORTS');
  const reports = fixtureStore.reports;
  const driftEvents = fixtureStore.driftEvents;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-400" />
            Compliance Reports & Drift Timeline (M38, E05, E28)
          </h1>
          <p className="text-xs text-slate-400">
            Export canonical audit records in 4 formats and inspect configuration drift deltas.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button size="sm" className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500">
            <Download className="w-3.5 h-3.5" />
            Generate New Report (M38)
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('REPORTS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'REPORTS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Export Center (PDF, HTML, CSV, JSON)
        </button>
        <button
          onClick={() => setActiveTab('DRIFT')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'DRIFT'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Configuration Drift Events (E05)
        </button>
      </div>

      {/* Reports Tab */}
      {activeTab === 'REPORTS' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Report Document Title</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Signed URL Expiry</TableHead>
                <TableHead>Generated At</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.map((rep) => (
                <TableRow key={rep.report_id}>
                  <TableCell className="font-semibold text-white">{rep.title}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {rep.format}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-slate-400">
                    {formatBytes(rep.file_size_bytes)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-amber-400">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" /> 24 Hours Remaining
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-slate-400">
                    {new Date(rep.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      onClick={() => window.open(rep.download_url, '_blank')}
                      size="sm"
                      variant="outline"
                      className="h-6 text-[10px] gap-1 px-2"
                    >
                      <Download className="w-3 h-3" /> Download
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Drift Tab */}
      {activeTab === 'DRIFT' && (
        <div className="space-y-4">
          {driftEvents.map((drift) => (
            <Card key={drift.event_id} className="border-slate-800 bg-slate-900/90 p-4 space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <GitCompare className="w-4 h-4 text-amber-400" />
                  <span className="font-mono font-bold text-white text-xs">{drift.hostname}</span>
                  <Badge variant="warning" className="text-[10px] font-mono">
                    UNAUTHORIZED DRIFT DETECTED
                  </Badge>
                </div>
                <span className="font-mono text-xs text-slate-400">
                  {new Date(drift.detected_at).toLocaleString()}
                </span>
              </div>

              <ConfigDiff diffText={drift.diff_preview} title="Snapshot Delta (Baseline vs Current Effective)" />
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

