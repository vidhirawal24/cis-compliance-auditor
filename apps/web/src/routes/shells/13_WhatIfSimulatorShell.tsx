import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { FlaskConical, ShieldCheck, CheckCircle2, ArrowRight, ShieldAlert } from 'lucide-react';
import { Card, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { fixtureStore } from '../../api/store';

export const WhatIfSimulatorShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const sim = fixtureStore.whatIfSimulation;
  const contracts = fixtureStore.safetyContracts;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-sky-400" />
            What-If Simulator & Service Safety (I11, I12, I13)
          </h1>
          <p className="text-xs text-slate-400">
            Batfish network emulation predicting change reachability against mandatory service contracts prior to execution.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigate(`/orgs/${orgId}/approvals`)}
            size="sm"
            className="gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white"
          >
            <span>Proceed to Approval Review (E23)</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Simulation Verdict Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Formal Simulation Verdict (I11)</div>
          <div className="text-xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5" />
            {sim.verdict}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Batfish Network Emulation</div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Model Coverage (I20)</div>
          <div className="text-xl font-bold font-mono text-sky-400">
            {sim.model_coverage_pct}%
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Vendor behavior verified in model</div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Safety Contracts Evaluated (I12)</div>
          <div className="text-xl font-bold font-mono text-white">
            {sim.safety_contracts_evaluated} Tested / {sim.safety_contracts_violated} Violated
          </div>
          <div className="text-[11px] text-emerald-400 mt-1">Zero contract violations</div>
        </Card>

        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Blast-Radius Estimate (I13)</div>
          <div className="text-xl font-bold font-mono text-amber-400">
            {sim.blast_radius_asset_count} Endpoints
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Bounded impact scope</div>
        </Card>
      </div>

      {/* Service-Safety Contracts Table (I12, I14) */}
      <Card className="border-slate-800 bg-slate-900/90 p-4 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            Service-Safety Contracts Evaluation (I12)
          </CardTitle>
          <span className="text-[11px] font-mono text-slate-400">Mandatory Violations Block Approval (I14)</span>
        </div>

        <div className="rounded-lg border border-slate-800 bg-black/40 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Contract Name</TableHead>
                <TableHead>Source CIDR</TableHead>
                <TableHead>Destination CIDR</TableHead>
                <TableHead>Port / Proto</TableHead>
                <TableHead>Mandatory (I14)</TableHead>
                <TableHead className="text-right">Simulation Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {contracts.map((c) => (
                <TableRow key={c.contract_id}>
                  <TableCell className="font-semibold text-white">{c.name}</TableCell>
                  <TableCell className="font-mono">{c.source_cidr}</TableCell>
                  <TableCell className="font-mono">{c.destination_cidr}</TableCell>
                  <TableCell className="font-mono">{c.port_range} / {c.protocol}</TableCell>
                  <TableCell>
                    <Badge variant={c.mandatory ? 'destructive' : 'secondary'} className="text-[10px]">
                      {c.mandatory ? 'MANDATORY' : 'OPTIONAL'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono font-bold text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" /> PRESERVED (PASS)
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Card>
    </div>
  );
};

