import { useQuery } from '@tanstack/react-query';
import { useApi } from '../../api/context';

// I15 presentation only: read historical DEMO telemetry; no execution controls.
export function RolloutPreview() {
  const api = useApi();
  const result = useQuery({ queryKey: ['phase6-rollout', api], queryFn: async () => (await api.getChange('chg-2026-7701')).data, retry: false });
  return <section aria-label="DEMO staged rollout"><h2>Rollout presentation (I15)</h2>
    <p>Historical DEMO telemetry, separate from the selected hypothetical plan. No rollout has been started by this workflow.</p>
    {result.isPending ? <p role="status">Loading staged rollout...</p> : result.isError ? <p role="alert">Rollout telemetry unavailable.</p> : <>
      <p>Fixture plan: {result.data.plan_id}; stage {result.data.current_stage_batch} of {result.data.total_stage_batches}; state: {result.data.state}</p>
      <p role="status">{result.data.canary_halt_triggered ? 'HALTED: canary halt trigger reported in DEMO telemetry' : 'No canary halt reported in DEMO telemetry'}</p>
      <ol className="space-y-2">{result.data.execution_events.map((event, index) => <li key={index} className="p-2 border border-slate-700 rounded">{event.stage}: {event.status} -- {event.message} ({event.timestamp})</li>)}</ol>
      {!result.data.execution_events.length && <p>No rollout events supplied.</p>}
    </>}
    <p>Proposed gate: canary, then service check, then remaining batches. Halt on contract violation or failed service check. Production stop controls and live telemetry are unavailable.</p>
  </section>;
}
