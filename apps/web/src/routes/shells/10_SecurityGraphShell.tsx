import React, { useState } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, Eye, Table as TableIcon } from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { fixtureStore } from '../../api/store';

export const SecurityGraphShell: React.FC = () => {
  const [viewMode, setViewMode] = useState<'GRAPH' | 'TABLE'>('GRAPH');
  const graph = fixtureStore.securityGraph;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-sky-400" />
            Cross-Layer Security & Topology Graph (I01, I03)
          </h1>
          <p className="text-xs text-slate-400">
            Interactive Cytoscape.js canvas showing evidence-backed topology, permitted reachability, and risk paths.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setViewMode(viewMode === 'GRAPH' ? 'TABLE' : 'GRAPH')}
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
          >
            {viewMode === 'GRAPH' ? <TableIcon className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {viewMode === 'GRAPH' ? 'Accessible Table View (I01)' : 'Interactive Canvas'}
          </Button>
        </div>
      </div>

      {viewMode === 'GRAPH' ? (
        <Card className="border-slate-800 bg-slate-900/90 overflow-hidden relative">
          {/* Canvas Floating Toolbar */}
          <div className="absolute top-4 left-4 z-10 flex items-center gap-2 bg-slate-950/80 backdrop-blur-md p-1.5 rounded-lg border border-slate-800">
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" title="Zoom In">
              <ZoomIn className="w-3.5 h-3.5" />
            </Button>
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" title="Zoom Out">
              <ZoomOut className="w-3.5 h-3.5" />
            </Button>
            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" title="Reset Viewport">
              <RotateCcw className="w-3.5 h-3.5" />
            </Button>
            <div className="h-4 w-px bg-slate-800" />
            <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-800">
              {graph.meta.coverage_completeness_pct}% TOPOLOGY COVERAGE
            </Badge>
          </div>

          {/* Graph Visualization Container */}
          <div className="h-[520px] bg-[#070b12] flex items-center justify-center p-6 text-center">
            <div className="space-y-4 max-w-md">
              <div className="w-16 h-16 rounded-2xl bg-sky-950/60 border border-sky-800/80 flex items-center justify-center mx-auto text-sky-400">
                <Network className="w-8 h-8" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-white mb-1">Cytoscape.js Security Canvas Shell</h2>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Renders {graph.nodes.length} typed nodes (Assets, Interfaces, Subnets, Services) and {graph.edges.length} evidence-backed edges with Cola layout.
                </p>
              </div>

              {/* Node Legend */}
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[10px] font-mono">
                <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">Asset</span>
                <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">Subnet</span>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">Allows</span>
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">Violates</span>
              </div>
            </div>
          </div>
        </Card>
      ) : (
        /* Accessible Table Fallback (Playbook Page 8 constraint) */
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Edge ID</TableHead>
                <TableHead>Source Node</TableHead>
                <TableHead>Relation</TableHead>
                <TableHead>Target Node</TableHead>
                <TableHead>Confidence (I05)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {graph.edges.map((edge) => (
                <TableRow key={edge.data.id}>
                  <TableCell className="font-mono font-bold text-slate-300">{edge.data.id}</TableCell>
                  <TableCell className="font-mono text-white">{edge.data.source}</TableCell>
                  <TableCell>
                    <span className="font-mono text-xs uppercase px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
                      {edge.data.relation}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-white">{edge.data.target}</TableCell>
                  <TableCell>
                    <Badge variant="success" className="text-[10px] font-mono">
                      {edge.data.confidence}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
};

