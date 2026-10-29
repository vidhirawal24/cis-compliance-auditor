import { useQuery } from '@tanstack/react-query';
import { useApi, apiCacheKey } from '../../api/context';
import { ApiState } from '../../components/common/ApiState';
import { Button } from '../../components/ui/button';

export function SnapshotHistory({ orgId, assetId }: { orgId: string; assetId: string }) {
  const api = useApi();
  const query = useQuery({ queryKey: ['snapshot-references', orgId, assetId, apiCacheKey(api)], queryFn: async () => {
    const events = (await api.getDriftEvents()).data;
    if (events.some(event => event.org_id !== orgId)) throw new Error('Tenant mismatch');
    return events.filter(event => event.asset_id === assetId);
  }, retry: false });
  return <section aria-label="Snapshot references"><h2>Configuration Snapshots &amp; Baseline Archive (E06)</h2>
    <p>Snapshot enumeration and encrypted artifact retrieval are UNSUPPORTED. Only references supplied in this asset's drift history are shown. Encryption, integrity and restore readiness are UNKNOWN.</p>
    <ApiState pending={query.isPending} error={query.error} retry={() => { void query.refetch(); }}>
      {!query.data?.length && <p>No snapshot references supplied for this asset.</p>}
      <ul>{query.data?.map(event => <li key={event.event_id}>{event.previous_snapshot_id || 'Unknown previous snapshot'} to {event.current_snapshot_id || 'Unknown new snapshot'} at {event.detected_at}</li>)}</ul>
    </ApiState><Button disabled>Retrieve encrypted snapshot - unsupported</Button>
  </section>;
}
