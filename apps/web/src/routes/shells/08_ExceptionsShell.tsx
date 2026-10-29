import React, { useState } from 'react';
import { FileCheck2, Plus, Clock, UserCheck } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';

export const ExceptionsShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'EXCEPTIONS' | 'MANUAL_REVIEWS'>('EXCEPTIONS');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-sky-400" />
            Exceptions & Manual Reviews (E12, E14)
          </h1>
          <p className="text-xs text-slate-400">
            Time-boxed policy exceptions with business justification and human attestation workflow.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button size="sm" className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500">
            <Plus className="w-3.5 h-3.5" />
            Request Policy Exception (E14)
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('EXCEPTIONS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'EXCEPTIONS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Time-Boxed Policy Exceptions (E14)
        </button>
        <button
          onClick={() => setActiveTab('MANUAL_REVIEWS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${activeTab === 'MANUAL_REVIEWS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
        >
          Manual Review Queue (E12)
        </button>
      </div>

      {/* Exceptions Tab */}
      {activeTab === 'EXCEPTIONS' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Exception ID</TableHead>
                <TableHead>Target Finding</TableHead>
                <TableHead>Target Host</TableHead>
                <TableHead>Approver</TableHead>
                <TableHead>Business Justification</TableHead>
                <TableHead>Expires In</TableHead>
                <TableHead className="text-right">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="font-mono font-bold text-sky-400">exc-2026-901</TableCell>
                <TableCell className="font-mono text-xs">CIS-WIN11-2.3.17 (UAC Prompt)</TableCell>
                <TableCell className="font-mono text-xs">DEMO-W11-EXEC-01</TableCell>
                <TableCell className="font-mono text-xs">ciso@acmefinancial.com</TableCell>
                <TableCell className="text-slate-300 text-xs max-w-xs truncate">
                  Legacy automated deployment software compatibility in C-suite suite
                </TableCell>
                <TableCell className="font-mono text-xs text-amber-400">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" /> 32 Days
                  </span>
                </TableCell>
                <TableCell className="text-right">
                  <Badge variant="success" className="text-[10px]">ACTIVE OVERLAY</Badge>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
      )}

      {/* Manual Reviews Tab */}
      {activeTab === 'MANUAL_REVIEWS' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-amber-400" />
              Human Attestation Controls (E12)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-3">
            <div className="p-3 bg-black/40 rounded-lg border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
              <div className="space-y-1">
                <div className="font-bold text-white font-mono">
                  CIS-WIN2019-1.1.1: Physical Console Enclosure & Access Locks
                </div>
                <div className="text-slate-400 text-[11px]">
                  Requires visual confirmation and badge access audit for Server Room B Rack 4.
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" className="text-xs h-7">
                  Attach Photo Evidence
                </Button>
                <Button size="sm" className="text-xs h-7 bg-emerald-600 hover:bg-emerald-500">
                  Attest & Sign Off
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

