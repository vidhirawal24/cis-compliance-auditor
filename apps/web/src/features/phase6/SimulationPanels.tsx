import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import { serviceSafetyContractFormSchema } from '../../contracts/v1/schemas';
import { SimulationVerdict as V } from '../../contracts/v1/enums';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';

const cidr = z.string().refine(value => {
  const [address, prefix, extra] = value.split('/');
  return !extra && /^\d+$/.test(prefix ?? '') && +prefix >= 0 && +prefix <= 32 && z.string().ip({ version: 'v4' }).safeParse(address).success;
}, 'Valid IPv4 CIDR required');
export const contractDraftSchema = serviceSafetyContractFormSchema.extend({
  source_cidr: cidr, destination_cidr: cidr,
  port_range: z.string().refine(value => {
    if (!/^\d+(-\d+)?$/.test(value)) return false;
    const [start, end = start] = value.split('-').map(Number);
    return start >= 1 && end <= 65535 && start <= end;
  }, 'Ports must be 1-65535 in ascending order'),
});
type Draft = z.infer<typeof contractDraftSchema>;
export function ContractEditor({ onDirty }: { onDirty: () => void }) {
  const [saved, setSaved] = useState(false);
  const { register, handleSubmit, formState: { errors } } = useForm<Draft>({ resolver: zodResolver(contractDraftSchema), defaultValues: { name: '', description: '', source_cidr: '', destination_cidr: '', port_range: '22', protocol: 'TCP', mandatory: true } });
  return <form aria-label="Service-safety contract draft" className="space-y-3" onChange={() => { onDirty(); setSaved(false); }} onSubmit={handleSubmit(() => { onDirty(); setSaved(true); })}>
    <h2>Service-safety contract editor (I12)</h2><p>Local draft only. Saving and evaluating changed contracts require unsupported backend operations. Any edit invalidates the preview and blocks approval for this session.</p>
    <div className="grid md:grid-cols-2 gap-3">{(['name', 'description', 'source_cidr', 'destination_cidr', 'port_range'] as const).map(field => <label key={field}>{field.replace(/_/g, ' ')}<Input aria-invalid={!!errors[field]} {...register(field)} />{errors[field] && <span role="alert">{errors[field]?.message}</span>}</label>)}</div>
    <label>Protocol <select {...register('protocol')} className="bg-slate-900 border p-2"><option>TCP</option><option>UDP</option><option>ICMP</option><option>ANY</option></select></label>
    <label className="block"><input type="checkbox" {...register('mandatory')} /> Mandatory in draft</label>
    <Button type="submit" variant="outline">Validate local draft</Button>{saved && <p role="status">Draft valid. Not persisted or simulated; approval remains blocked.</p>}
  </form>;
}
const meanings: Record<V, string> = {
  SAFE_IN_MODEL: 'Required reachability appears preserved within this model. Real devices have not been verified.',
  VIOLATES_CONTRACT: 'A service-safety contract is violated. Approval is blocked without a client override.',
  UNSUPPORTED: 'The model cannot represent the requested vendor behavior. No safety conclusion is available.',
  INSUFFICIENT_EVIDENCE: 'Missing topology or evidence prevents a safety conclusion. Approval is blocked.',
};
export function SafetyVerdict({ verdict }: { verdict: V }) {
  const variant = { SAFE_IN_MODEL: 'success', VIOLATES_CONTRACT: 'destructive', UNSUPPORTED: 'secondary', INSUFFICIENT_EVIDENCE: 'warning' } as const;
  return <div role="status"><Badge variant={variant[verdict]}>{verdict}</Badge><p>{meanings[verdict]}</p></div>;
}
// I11: explicitly synthetic service model, not discovered network reachability.
export function ServiceComparison({ violated }: { violated: boolean }) {
  return <div className="grid md:grid-cols-2 gap-4">{['Baseline', 'Candidate'].map((label, index) => {
    const state = index && violated ? 'SSH unreachable -- contract violation' : 'SSH reachable in DEMO model';
    return <section key={label} aria-label={`${label} service diagram`}><h3>{label}</h3><p>{state}</p><div style={{ height: 230 }} className="border rounded border-slate-700"><ReactFlow fitView nodesConnectable={false} nodesDraggable={false} colorMode="dark" nodes={[
      { id: 'admin', position: { x: 0, y: 20 }, data: { label: 'DEMO admin subnet' } },
      { id: 'ssh', position: { x: 240, y: 20 }, data: { label: 'DEMO management SSH' } },
    ]} edges={[{ id: 'reachability', source: 'admin', target: 'ssh', label: state, style: { stroke: index && violated ? '#f43f5e' : '#38bdf8' } }]}><Background /><Controls /></ReactFlow></div></section>;
  })}</div>;
}
