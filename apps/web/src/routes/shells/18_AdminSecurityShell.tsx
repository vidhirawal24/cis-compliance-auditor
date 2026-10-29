import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useApi, apiCacheKey } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import { useAuth } from '../../auth/context';
import { UserRole } from '../../contracts/v1/enums';
import { ApiState } from '../../components/common/ApiState';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Card } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';

// E19,E30: context display and backend audit reads, no invented administration writes.
export function AdminSecurityShell() {
  const { orgId = '' } = useParams();
  const api = useApi();
  const { user, role } = useAuth();
  const [filter, setFilter] = useState('');
  const allowed = role === UserRole.OWNER || role === UserRole.ADMIN;
  const logs = useQuery({ queryKey: ['admin-audit', orgId, apiCacheKey(api)], enabled: allowed, queryFn: async () => {
    const records = (await api.getAuditEvents()).data;
    if (records.some(record => record.org_id !== orgId)) throw new Error('Tenant mismatch');
    return records;
  }, retry: false });
  return <div className="space-y-5"><h1 className="text-xl font-bold">Administration &amp; Security Governance (E19, E30)</h1>
    <Badge variant="warning">{api instanceof DemoApiClient ? 'DEMO - synthetic tenant context and audit records' : 'Backend access required'}</Badge>
    <Card className="p-4"><h2>RBAC and membership</h2><p>Organization: {orgId}; current role: {role}; current actor: {user?.id ?? 'Unknown'}.</p><p>Role and session display is a UI aid, not proof of server permission. Server authorization is required. Full member enumeration and role editing are UNSUPPORTED.</p><Button disabled>Edit member roles - unsupported</Button></Card>
    {!allowed && <p role="alert">403 Forbidden: this administration view requires an owner or administrator. The server remains the authority.</p>}
    <Card className="p-4"><h2>Retention and storage access</h2><p>Retention policy, private-storage ACLs and vault health: UNKNOWN. Read/write settings APIs are unavailable. No settings have been saved.</p><Button disabled>Save retention settings - unsupported</Button><p>Secrets are never requested or included in a local export.</p></Card>
    <Card className="p-4"><h2>External integration API (E30)</h2><p>API key issuance, rate-limit status and versioned API documentation location are not supplied. No keys are generated or displayed.</p><Button disabled>Create integration key - unsupported</Button></Card>
    {allowed && <Card className="p-4 space-y-3"><h2>Application audit trail (E19)</h2><label>Filter audit actions or targets<Input value={filter} onChange={event => setFilter(event.target.value)} /></label>
      <ApiState pending={logs.isPending} error={logs.error} retry={() => { void logs.refetch(); }}>
        {!!logs.data?.length && !logs.data.some(event => `${event.action_type} ${event.target_resource_id}`.toLowerCase().includes(filter.toLowerCase())) && <p>No audit records match this filter.</p>}
        {!logs.data?.length ? <p>No audit events supplied.</p> : <Table aria-label="Application audit events"><TableHeader><TableRow><TableHead>Event</TableHead><TableHead>Actor ID</TableHead><TableHead>Action</TableHead><TableHead>Target</TableHead><TableHead>Time (UTC)</TableHead><TableHead>Supplied hash (unverified)</TableHead></TableRow></TableHeader><TableBody>{logs.data.filter(event => `${event.action_type} ${event.target_resource_id}`.toLowerCase().includes(filter.toLowerCase())).map(event => <TableRow key={event.event_id}><TableCell>{event.event_id}</TableCell><TableCell>{event.actor_id}</TableCell><TableCell>{event.action_type}</TableCell><TableCell>{event.target_resource_id}</TableCell><TableCell>{event.timestamp}</TableCell><TableCell className="break-all">{event.sha256_hash || 'Unavailable'}</TableCell></TableRow>)}</TableBody></Table>}
        <p>Append-only storage, complete history and hash verification are backend responsibilities, not established by this display. IP addresses and actor emails are omitted here for data minimization.</p>
      </ApiState>
    </Card>}
  </div>;
}
