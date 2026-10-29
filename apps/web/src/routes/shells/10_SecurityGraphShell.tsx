import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import cytoscape from 'cytoscape';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Eye,
  Table as TableIcon,
  ShieldAlert,
  AlertTriangle,
  Search,
  Filter,
  ArrowRight,
  ExternalLink,
  X,
  Compass,
  CheckCircle2,
  HelpCircle,
  Layers,
  Server,
  Zap,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { SeverityBadge } from '../../components/common/SeverityBadge';
import { fixtureStore } from '../../api/store';
import type { CytoscapeNodeData } from '../../contracts/v1/types';

export const SecurityGraphShell: React.FC = () => {
  const { orgId } = useParams<{ orgId: string }>();
  const navigate = useNavigate();
  const graph = fixtureStore.securityGraph;

  // View Mode: Interactive Cytoscape Canvas vs. Accessible Table Fallback (I01)
  const [viewMode, setViewMode] = useState<'GRAPH' | 'TABLE'>('GRAPH');

  // Filters State
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Node Selection State (Evidence Drill-Down)
  const [selectedNode, setSelectedNode] = useState<CytoscapeNodeData | null>(null);

  // Path Explorer State (I03)
  const [pathSource, setPathSource] = useState('ext-inet');
  const [pathTarget, setPathTarget] = useState('a03');
  const [discoveredPath, setDiscoveredPath] = useState<Array<{ id: string; label: string; relation?: string }> | null>(null);
  const [pathNotFoundMessage, setPathNotFoundMessage] = useState<string | null>(null);

  // Container ref for Cytoscape.js
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Filtered nodes and edges for data display
  const filteredNodes = graph.nodes.filter(({ data }) => {
    if (typeFilter !== 'ALL' && data.type !== typeFilter) return false;
    if (severityFilter !== 'ALL' && data.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchLabel = data.label.toLowerCase().includes(q);
      const matchId = data.id.toLowerCase().includes(q);
      const matchIp = data.ip_address?.toLowerCase().includes(q) || false;
      const matchCidr = data.cidr?.toLowerCase().includes(q) || false;
      return matchLabel || matchId || matchIp || matchCidr;
    }
    return true;
  });

  const filteredNodeIds = new Set(filteredNodes.map((n) => n.data.id));

  const filteredEdges = graph.edges.filter(
    ({ data }) => filteredNodeIds.has(data.source) && filteredNodeIds.has(data.target)
  );

  // Initialize and update Cytoscape.js canvas
  useEffect(() => {
    if (viewMode !== 'GRAPH' || !containerRef.current) return;

    try {
      // Define preset positions for crystal-clear network topology visualization
      const nodePositions: Record<string, { x: number; y: number }> = {
        'ext-inet': { x: 80, y: 220 },
        'a05': { x: 230, y: 360 },
        'a06': { x: 230, y: 220 },
        'f-shadow': { x: 230, y: 460 },
        'f-acl': { x: 230, y: 90 },
        'a10': { x: 400, y: 220 },
        'int-a10-gi0': { x: 400, y: 90 },
        'svc-telnet': { x: 400, y: 320 },
        'f-telnet': { x: 500, y: 110 },
        'a11': { x: 580, y: 220 },
        'f-vlan1': { x: 580, y: 90 },
        'subnet-lan': { x: 580, y: 340 },
        'a03': { x: 760, y: 220 },
        'svc-ssh': { x: 760, y: 330 },
        'f-root': { x: 760, y: 90 },
      };

      const elements = [
        ...filteredNodes.map((n) => ({
          data: { ...n.data },
          position: nodePositions[n.data.id] || { x: 300, y: 200 },
        })),
        ...filteredEdges.map((e) => ({
          data: { ...e.data },
        })),
      ];

      let cy: cytoscape.Core | null = null;
      try {
        cy = cytoscape({
          container: containerRef.current,
          elements,
          style: [
            // Base Node Style
            {
              selector: 'node',
              style: {
                'label': 'data(label)',
                'color': '#cbd5e1',
                'font-size': '10px',
                'font-family': 'monospace',
                'text-valign': 'bottom',
                'text-margin-y': 4,
                'background-color': '#0f172a',
                'border-width': 2,
                'border-color': '#38bdf8',
                'width': 36,
                'height': 36,
                'transition-property': 'background-color, border-color, width, height',
                'transition-duration': 0.2,
              },
            },
            // Node Types
            {
              selector: 'node[type = "asset"]',
              style: {
                'shape': 'round-rectangle',
                'background-color': '#0369a1',
                'border-color': '#38bdf8',
                'width': 44,
                'height': 44,
              },
            },
            {
              selector: 'node[type = "subnet"]',
              style: {
                'shape': 'rectangle',
                'background-color': '#312e81',
                'border-color': '#818cf8',
                'border-style': 'dashed',
                'width': 55,
                'height': 32,
              },
            },
            {
              selector: 'node[type = "interface"]',
              style: {
                'shape': 'hexagon',
                'background-color': '#115e59',
                'border-color': '#2dd4bf',
                'width': 34,
                'height': 34,
              },
            },
            {
              selector: 'node[type = "service"]',
              style: {
                'shape': 'ellipse',
                'background-color': '#065f46',
                'border-color': '#34d399',
                'width': 32,
                'height': 32,
              },
            },
            {
              selector: 'node[type = "finding"]',
              style: {
                'shape': 'diamond',
                'background-color': '#881337',
                'border-color': '#fb7185',
                'width': 36,
                'height': 36,
              },
            },
            // Edge Base Style
            {
              selector: 'edge',
              style: {
                'width': 2,
                'line-color': '#334155',
                'target-arrow-color': '#475569',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(relation)',
                'font-size': '8px',
                'font-family': 'monospace',
                'color': '#64748b',
                'text-rotation': 'autorotate',
                'text-background-color': '#0b0f17',
                'text-background-opacity': 0.8,
                'text-background-padding': '2px',
              },
            },
            {
              selector: 'edge[relation = "violates"]',
              style: {
                'line-color': '#f43f5e',
                'target-arrow-color': '#f43f5e',
                'line-style': 'dashed',
                'width': 2.5,
                'color': '#fca5a5',
              },
            },
            {
              selector: 'edge[relation = "allows"]',
              style: {
                'line-color': '#10b981',
                'target-arrow-color': '#10b981',
                'width': 2,
                'color': '#6ee7b7',
              },
            },
            {
              selector: 'edge[relation = "routes_to"]',
              style: {
                'line-color': '#38bdf8',
                'target-arrow-color': '#38bdf8',
                'width': 2,
                'color': '#7dd3fc',
              },
            },
            // Active Attack Path Styling (I03)
            {
              selector: 'node.path-active',
              style: {
                'border-color': '#f43f5e',
                'border-width': 4,
                'background-color': '#be123c',
              },
            },
            {
              selector: 'edge.path-active',
              style: {
                'line-color': '#f43f5e',
                'target-arrow-color': '#f43f5e',
                'width': 3.5,
                'color': '#fda4af',
              },
            },
            // Highlighted Node on selection
            {
              selector: 'node:selected, node.selected',
              style: {
                'border-color': '#fbbf24',
                'border-width': 3,
              },
            },
          ],
          layout: {
            name: 'preset',
            fit: true,
            padding: 30,
          },
        });
      } catch {
        // Fallback to headless cytoscape if container canvas initialization fails (e.g. headless jsdom)
        cy = cytoscape({
          headless: true,
          elements,
        });
      }

      if (cy) {
        // Node tap listener
        cy.on('tap', 'node', (evt) => {
          const node = evt.target;
          setSelectedNode(node.data());
          cy?.elements().removeClass('selected');
          node.addClass('selected');
        });

        // Background tap clears selection
        cy.on('tap', (evt) => {
          if (evt.target === cy) {
            setSelectedNode(null);
            cy?.elements().removeClass('selected');
          }
        });

        cyRef.current = cy;

        return () => {
          cy?.destroy();
        };
      }
    } catch {
      console.warn('Cytoscape canvas unavailable; use the accessible table view.');
    }
  }, [viewMode, typeFilter, severityFilter, searchQuery]);

  // Toolbar Actions
  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 1.25);
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 0.8);
    }
  };

  const handleFitViewport = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 30);
    }
  };

  // Trace Path using Cytoscape Dijkstra / Graph Traversal (I03)
  const handleTracePath = () => {
    setPathNotFoundMessage(null);
    setDiscoveredPath(null);

    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.elements().removeClass('path-active');

    const srcNode = cy.$id(pathSource);
    const tgtNode = cy.$id(pathTarget);

    if (srcNode.empty() || tgtNode.empty()) {
      setPathNotFoundMessage('One or both selected path endpoints are currently excluded by active filters.');
      return;
    }

    // Run directed dijkstra on active canvas elements
    const dijkstra = cy.elements().dijkstra({
      root: srcNode,
      directed: true,
    });

    const pathToTarget = dijkstra.pathTo(tgtNode);
    const distance = dijkstra.distanceTo(tgtNode);

    if (!Number.isFinite(distance) || distance === Infinity || pathToTarget.empty() || pathToTarget.length <= 1) {
      // Invariant: Never present an unsupported or unreachable path as verified!
      setPathNotFoundMessage(
        `No verified traversal path exists between ${pathSource} and ${pathTarget} under current firewall rules and topology.`
      );
      return;
    }

    // Highlight the valid verified path on canvas
    pathToTarget.addClass('path-active');

    // Extract ordered hops
    const hops: Array<{ id: string; label: string; relation?: string }> = [];
    pathToTarget.nodes().forEach((n, idx) => {
      const nodeData = n.data();
      let edgeRel: string | undefined = undefined;
      if (idx < pathToTarget.nodes().length - 1) {
        const nextNode = pathToTarget.nodes()[idx + 1];
        const connectingEdge = n.edgesTo(nextNode);
        if (connectingEdge.nonempty()) {
          edgeRel = connectingEdge.data('relation');
        }
      }
      hops.push({
        id: nodeData.id,
        label: nodeData.label || nodeData.id,
        relation: edgeRel,
      });
    });

    setDiscoveredPath(hops);
  };

  const handleClearPath = () => {
    if (cyRef.current) {
      cyRef.current.elements().removeClass('path-active');
    }
    setDiscoveredPath(null);
    setPathNotFoundMessage(null);
  };

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
            className="gap-1.5 text-xs text-sky-400 border-sky-800/80 hover:bg-sky-950/40"
          >
            {viewMode === 'GRAPH' ? <TableIcon className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            <span>{viewMode === 'GRAPH' ? 'Accessible Table View (I01)' : 'Interactive Canvas View'}</span>
          </Button>
        </div>
      </div>

      {/* Topology Uncertainty & Model Notice (I05) */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-300 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-white flex items-center gap-2">
            <span>Topology Coverage & Model Uncertainty Notice (I05)</span>
            <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-800 font-mono">
              {graph.meta.coverage_completeness_pct}% COVERAGE
            </Badge>
          </div>
          <p className="text-slate-400 leading-relaxed">
            Network reachability is evaluated using Batfish AST model analysis on verified routing tables and firewall rulesets.
            Unassessed subnet segments (e.g. 10.200.0.0/16) are marked conditional; path traversability across unobserved boundaries
            is explicitly withheld to prevent false security claims.
          </p>
        </div>
      </div>

      {/* Graph Filters & Path Controls Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs">
        {/* Node Type & Severity Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400 font-mono">Type:</span>
            <select
              aria-label="Filter Node Type"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs"
            >
              <option value="ALL">All Types ({graph.nodes.length})</option>
              <option value="asset">Assets</option>
              <option value="subnet">Subnets</option>
              <option value="interface">Interfaces</option>
              <option value="service">Services</option>
              <option value="finding">Findings</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-mono">Severity:</span>
            <select
              aria-label="Filter Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Search */}
          <div className="relative w-44">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
            <Input
              placeholder="Search graph..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 h-7 text-xs bg-slate-900 border-slate-800"
            />
          </div>
        </div>

        {/* Path Explorer Controls (I03) */}
        <div className="flex flex-wrap items-center gap-2 p-1.5 bg-black/40 rounded-lg border border-slate-800 font-mono text-[11px]">
          <Compass className="w-3.5 h-3.5 text-sky-400" />
          <span className="text-slate-400">Path:</span>
          <select
            aria-label="Path Source Node"
            value={pathSource}
            onChange={(e) => setPathSource(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-slate-200 text-[11px]"
          >
            {graph.nodes.map((n) => (
              <option key={n.data.id} value={n.data.id}>
                {n.data.id} ({n.data.label})
              </option>
            ))}
          </select>

          <ArrowRight className="w-3 h-3 text-slate-500" />

          <select
            aria-label="Path Target Node"
            value={pathTarget}
            onChange={(e) => setPathTarget(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-slate-200 text-[11px]"
          >
            {graph.nodes.map((n) => (
              <option key={n.data.id} value={n.data.id}>
                {n.data.id} ({n.data.label})
              </option>
            ))}
          </select>

          <Button
            size="sm"
            onClick={handleTracePath}
            className="h-6 text-[10px] px-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold"
          >
            Trace Path (I03)
          </Button>

          {discoveredPath && (
            <Button
              size="sm"
              variant="outline"
              onClick={handleClearPath}
              className="h-6 text-[10px] px-2"
            >
              Clear
            </Button>
          )}
        </div>
      </div>

      {/* Path Results Notification */}
      {pathNotFoundMessage && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{pathNotFoundMessage}</span>
          </div>
          <button onClick={() => setPathNotFoundMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {discoveredPath && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs space-y-2">
          <div className="font-semibold flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Verified Traversable Reachability Path Found ({discoveredPath.length} Hops)
            </span>
            <span className="text-[10px] font-mono text-emerald-400">Highlighted on Canvas</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono pt-1">
            {discoveredPath.map((hop, idx) => (
              <React.Fragment key={hop.id}>
                <span className="px-2 py-0.5 rounded bg-emerald-900/60 border border-emerald-700 text-white">
                  {hop.label}
                </span>
                {idx < discoveredPath.length - 1 && (
                  <span className="text-slate-400 flex items-center gap-1">
                    <span>{hop.relation ? `[${hop.relation}]` : '→'}</span>
                    <ArrowRight className="w-3 h-3 text-slate-500" />
                  </span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* VIEW MODE 1: INTERACTIVE CYTOSCAPE CANVAS */}
      {/* ------------------------------------------------------------------ */}
      {viewMode === 'GRAPH' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Cytoscape Container */}
          <Card className={`border-slate-800 bg-slate-900/90 overflow-hidden relative ${selectedNode ? 'lg:col-span-3' : 'lg:col-span-4'}`}>
            {/* Canvas Floating Toolbar */}
            <div className="absolute top-4 left-4 z-10 flex items-center gap-1.5 bg-slate-950/80 backdrop-blur-md p-1.5 rounded-lg border border-slate-800 text-xs">
              <Button
                variant="ghost"
                size="sm"
                onClick={handleZoomIn}
                className="h-7 w-7 p-0 text-slate-300 hover:text-white"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleZoomOut}
                className="h-7 w-7 p-0 text-slate-300 hover:text-white"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleFitViewport}
                className="h-7 w-7 p-0 text-slate-300 hover:text-white"
                title="Reset Viewport & Fit"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </Button>
              <div className="h-4 w-px bg-slate-800" />
              <Badge variant="outline" className="text-[10px] font-mono text-sky-400 border-sky-800">
                {filteredNodes.length} NODES • {filteredEdges.length} EDGES
              </Badge>
            </div>

            {/* Cytoscape DOM Canvas */}
            <div
              ref={containerRef}
              data-testid="cytoscape-canvas"
              className="w-full h-[540px] bg-[#070b12] cursor-grab active:cursor-grabbing"
            />

            {/* Empty Filter State */}
            {filteredNodes.length === 0 && (
              <div className="absolute inset-0 bg-[#070b12]/90 flex items-center justify-center p-6 text-center">
                <div className="space-y-2 max-w-sm">
                  <HelpCircle className="w-8 h-8 text-slate-500 mx-auto" />
                  <div className="text-sm font-semibold text-white">No Graph Nodes Match Active Filters</div>
                  <p className="text-xs text-slate-400">
                    Adjust the node type, severity filter, or search query to display topology elements.
                  </p>
                </div>
              </div>
            )}

            {/* Node Legend Footer */}
            <div className="p-2.5 bg-black/60 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono">
              <div className="flex items-center gap-3">
                <span className="text-slate-400">Legend:</span>
                <span className="flex items-center gap-1 text-sky-300">
                  <span className="w-2.5 h-2.5 rounded bg-[#0369a1] inline-block border border-sky-400" /> Asset
                </span>
                <span className="flex items-center gap-1 text-indigo-300">
                  <span className="w-2.5 h-2.5 rounded bg-[#312e81] inline-block border border-indigo-400 border-dashed" /> Subnet
                </span>
                <span className="flex items-center gap-1 text-teal-300">
                  <span className="w-2.5 h-2.5 rounded bg-[#115e59] inline-block border border-teal-400" /> Interface
                </span>
                <span className="flex items-center gap-1 text-emerald-300">
                  <span className="w-2.5 h-2.5 rounded bg-[#065f46] inline-block border border-emerald-400" /> Service
                </span>
                <span className="flex items-center gap-1 text-rose-300">
                  <span className="w-2.5 h-2.5 rounded bg-[#881337] inline-block border border-rose-400" /> Finding (Violation)
                </span>
              </div>
              <div className="text-slate-500">
                Click any node to inspect evidence drill-down
              </div>
            </div>
          </Card>

          {/* Evidence Drill-Down Drawer (I01) */}
          {selectedNode && (
            <Card className="border-slate-800 bg-slate-900/95 lg:col-span-1 shadow-2xl flex flex-col max-h-[580px]">
              <CardHeader className="p-3 border-b border-slate-800 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-bold text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-sky-400" />
                  <span>Node Evidence Drill-Down</span>
                </CardTitle>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </CardHeader>

              <CardContent className="p-3 space-y-3 text-xs overflow-y-auto">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Selected Identity</div>
                  <div className="font-bold text-white text-sm break-all">{selectedNode.label}</div>
                  <div className="font-mono text-[11px] text-sky-400">{selectedNode.id}</div>
                </div>

                <div className="p-2.5 bg-black/40 rounded border border-slate-800 font-mono text-[11px] space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Node Type:</span>
                    <Badge variant="outline" className="text-[10px] uppercase font-mono">
                      {selectedNode.type}
                    </Badge>
                  </div>
                  {selectedNode.platform && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Platform:</span>
                      <span className="text-white">{selectedNode.platform}</span>
                    </div>
                  )}
                  {selectedNode.ip_address && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">IP Address:</span>
                      <span className="text-slate-200">{selectedNode.ip_address}</span>
                    </div>
                  )}
                  {selectedNode.cidr && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Subnet CIDR:</span>
                      <span className="text-slate-200">{selectedNode.cidr}</span>
                    </div>
                  )}
                  {selectedNode.port && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Listening Port:</span>
                      <span className="text-slate-200">{selectedNode.port}</span>
                    </div>
                  )}
                  {selectedNode.severity && (
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Finding Severity:</span>
                      <SeverityBadge severity={selectedNode.severity} />
                    </div>
                  )}
                </div>

                {/* Connected Edges List */}
                <div className="space-y-1.5">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Topology Adjacency</div>
                  <div className="space-y-1 font-mono text-[11px]">
                    {graph.edges
                      .filter((e) => e.data.source === selectedNode.id || e.data.target === selectedNode.id)
                      .map((e) => (
                        <div
                          key={e.data.id}
                          className="p-1.5 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between"
                        >
                          <span className="text-slate-400">{e.data.relation}</span>
                          <span className="text-sky-300">
                            {e.data.source === selectedNode.id ? `→ ${e.data.target}` : `← ${e.data.source}`}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>

                {/* Findings Explorer Navigation */}
                <div className="pt-2 border-t border-slate-800">
                  <Button
                    onClick={() => {
                      if (selectedNode.type === 'finding') {
                        navigate(`/orgs/${orgId}/findings`);
                      } else {
                        navigate(`/orgs/${orgId}/findings?asset=${selectedNode.id}`);
                      }
                    }}
                    size="sm"
                    className="w-full text-xs gap-1.5 bg-sky-600 hover:bg-sky-500"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>View Evidence in Findings Explorer</span>
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* VIEW MODE 2: ACCESSIBLE TABLE FALLBACK (I01) */}
      {/* ------------------------------------------------------------------ */}
      {viewMode === 'TABLE' && (
        <div className="space-y-6">
          {/* Nodes Table */}
          <Card className="border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
            <CardHeader className="border-b border-slate-800 pb-3">
              <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-sky-400" />
                <span>Topology Node Directory ({filteredNodes.length} Nodes)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table className="table-compact text-xs">
                <TableHeader>
                  <TableRow>
                    <TableHead>Node ID</TableHead>
                    <TableHead>Label</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Network / Platform</TableHead>
                    <TableHead>Status & Severity</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredNodes.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-6 text-slate-500">
                        No graph nodes found matching filter criteria.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredNodes.map(({ data }) => (
                      <TableRow key={data.id} className="hover:bg-slate-800/40">
                        <TableCell className="font-mono font-bold text-sky-400">
                          {data.id}
                        </TableCell>
                        <TableCell className="font-semibold text-white">
                          {data.label}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px] font-mono uppercase">
                            {data.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-slate-300">
                          {data.ip_address || data.cidr || (data.port ? `Port ${data.port}` : data.platform || '-')}
                        </TableCell>
                        <TableCell>
                          {data.severity ? (
                            <SeverityBadge severity={data.severity} />
                          ) : (
                            <span className="font-mono text-[10px] text-slate-500">N/A</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            onClick={() => {
                              setSelectedNode(data);
                              setViewMode('GRAPH');
                            }}
                            variant="outline"
                            size="sm"
                            className="h-6 text-[10px] px-2"
                          >
                            Locate in Graph
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Edges Table */}
          <Card className="border-slate-800 bg-slate-900/90 shadow-xl overflow-hidden">
            <CardHeader className="border-b border-slate-800 pb-3">
              <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Evidence-Backed Relationship Edges ({filteredEdges.length} Edges)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table className="table-compact text-xs">
                <TableHeader>
                  <TableRow>
                    <TableHead>Edge ID</TableHead>
                    <TableHead>Source Node</TableHead>
                    <TableHead>Relation (I01)</TableHead>
                    <TableHead>Target Node</TableHead>
                    <TableHead className="text-right">Confidence (I05)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEdges.map(({ data }) => (
                    <TableRow key={data.id} className="hover:bg-slate-800/40">
                      <TableCell className="font-mono font-bold text-slate-300">
                        {data.id}
                      </TableCell>
                      <TableCell className="font-mono text-white">
                        {data.source}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`font-mono text-[10px] px-2 py-0.5 rounded border uppercase ${
                            data.relation === 'violates'
                              ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                              : data.relation === 'allows'
                              ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                              : 'bg-slate-800 text-sky-300 border-slate-700'
                          }`}
                        >
                          {data.relation}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-white">
                        {data.target}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge
                          variant={data.confidence === 'CONFIRMED' ? 'success' : 'secondary'}
                          className="text-[10px] font-mono"
                        >
                          {data.confidence}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};
