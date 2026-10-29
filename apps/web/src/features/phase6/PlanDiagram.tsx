import { useState } from 'react';
import { ReactFlow, Background, Controls, MarkerType, Position, type Node, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { SecurityGraphData } from '../../contracts/v1/types';
import type { Candidate } from './model';
import { Button } from '../../components/ui/button';

// I10: pan, zoom and selection are interactive; dependency order is read-only.
export function PlanDiagram({ candidate }: { candidate: Candidate }) {
  const [selected, setSelected] = useState<string | null>(null);
  const nodes: Node[] = candidate.plan.actions.map((a, index) => ({ id: a.action_id, initialWidth: 250, initialHeight: 110, handles: [{ type: 'source', position: Position.Bottom, x: 125, y: 110 }, { type: 'target', position: Position.Top, x: 125, y: 0 }], position: { x: index * 300, y: 70 }, data: { label: `${a.sequence_order}. ${a.vendor}: ${a.title} (${a.status})` }, style: { background: '#111827', color: '#f1f5f9', border: '1px solid #38bdf8', width: 250, height: 110 }, selected: selected === a.action_id }));
  const edges: Edge[] = candidate.dependencies.map(d => ({ id: `${d.source}-${d.target}`, source: d.source, target: d.target, label: 'Requires verified predecessor', markerEnd: { type: MarkerType.ArrowClosed } }));
  const action = candidate.plan.actions.find(a => a.action_id === selected);
  if (!nodes.length) return <p>No remediation steps supplied.</p>;
  return <section aria-label="Selected plan dependencies" className="space-y-3">
    <div style={{ height: 340 }} className="border border-slate-700 rounded bg-slate-950">
      <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} nodesConnectable={false} edgesReconnectable={false} onNodeClick={(_, node) => setSelected(node.id)} colorMode="dark"><Background /><Controls /></ReactFlow>
    </div>
    <h3>Accessible steps and dependencies</h3>
    <ol className="space-y-2">{candidate.plan.actions.map(a => <li key={a.action_id}><Button variant="outline" aria-pressed={selected === a.action_id} onClick={() => setSelected(a.action_id)}>{a.sequence_order}. {a.vendor}: {a.title}</Button> <span>{a.status} / Risk weight: {a.risk_weight}</span></li>)}</ol>
    <ul>{candidate.dependencies.map(d => <li key={d.target}>{d.source} to {d.target}: {d.reason}</li>)}</ul>
    {!candidate.dependencies.length && <p>Dependency data not supplied; ordering alone does not establish dependencies.</p>}
    {action && <article aria-label="Selected step details" className="p-4 border border-sky-700 rounded"><h3>{action.title}</h3><p>Target: {action.asset_id} / {action.vendor} / {action.status}</p><p>Prerequisites: {action.prerequisites.join('; ') || 'Not supplied'}</p><p>Recovery: {action.recovery_plan ?? 'Not supplied'}</p><p>Read-only command preview</p><pre className="overflow-auto">{action.command_template}</pre></article>}
  </section>;
}

// I13: highlight supplied service impacts without inferring downstream disruption.
export function BlastRadiusDiagram({ graph, affectedServices, showImpact }: { graph: SecurityGraphData; affectedServices: string[]; showImpact: boolean }) {
  const infrastructure = graph.nodes.filter(n => n.data.type !== 'finding');
  const ids = new Set(infrastructure.map(n => n.data.id));
  const impacted = new Set(infrastructure.filter(n => showImpact && n.data.type === 'service' && n.data.port !== undefined && affectedServices.some(s => s.startsWith(`${n.data.port}/`))).map(n => n.data.id));
  if (!infrastructure.length) return <p>No topology supplied for blast-radius visualization. Downstream dependencies unknown.</p>;
  return <section aria-label="Blast radius and service dependencies"><h3>Service impact overlay (DEMO)</h3><p>Amber: hypothetical affected service from the supplied simulation. Gray: impact unknown. Connections represent supplied topology, not confirmed disruption.</p><div style={{ height: 320 }} className="border border-slate-700 rounded"><ReactFlow colorMode="dark" fitView nodesConnectable={false} nodesDraggable={false} nodes={infrastructure.map((n, i) => ({ id: n.data.id, position: { x: (i % 4) * 240, y: Math.floor(i / 4) * 110 }, data: { label: `${n.data.label}: ${impacted.has(n.data.id) ? 'hypothetical impact' : 'impact unknown'}` }, style: { background: '#111827', color: '#f1f5f9', border: `2px solid ${impacted.has(n.data.id) ? '#f59e0b' : '#64748b'}` } }))} edges={graph.edges.filter(e => ids.has(e.data.source) && ids.has(e.data.target)).map(e => ({ id: e.data.id, source: e.data.source, target: e.data.target, label: `${e.data.relation} / ${e.data.confidence}`, style: { strokeDasharray: e.data.confidence === 'CONFIRMED' ? undefined : '5 5' } }))}><Background /><Controls /></ReactFlow></div><ul>{infrastructure.filter(n => n.data.type === 'service').map(n => <li key={n.data.id}>{n.data.label}: {impacted.has(n.data.id) ? 'hypothetical affected service' : 'impact unknown'}</li>)}</ul></section>;
}
