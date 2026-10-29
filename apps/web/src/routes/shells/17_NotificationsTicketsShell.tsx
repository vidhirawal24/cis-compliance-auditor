import { useState } from 'react';
import { useApi } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import { DEMO_DELIVERIES } from '../../fixtures/phase8Data';
import { Button } from '../../components/ui/button';
import { Card } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';

// E26-E27: no notification/integration methods exist in ApiClientInterface.
export function NotificationsTicketsShell() {
  const api = useApi();
  const [tab, setTab] = useState('ALERTS');
  const demo = api instanceof DemoApiClient;
  return <div className="space-y-5"><h1 className="text-xl font-bold">Alerts &amp; Integration Delivery (E26, E27)</h1>
    <p>UNSUPPORTED: notification, webhook and ticket read/write operations are not defined in the current client. No message or ticket will be sent. Missing integration support is not a delivery failure.</p>
    <div className="flex flex-wrap gap-2">{['ALERTS', 'WEBHOOKS', 'TICKETS'].map(value => <Button key={value} variant="outline" aria-pressed={tab === value} onClick={() => setTab(value)}>{value}</Button>)}</div>
    {demo ? <><Badge variant="warning">DEMO - synthetic status examples; no delivery occurred</Badge>{DEMO_DELIVERIES.filter(record => record.channel === tab).map(record => <Card key={record.id} className="p-4"><h2>{record.status} (DEMO fixture)</h2><p>{record.description}</p><p>Error: {record.error ?? 'Not supplied'}; retryable: {record.retryable === null ? 'UNKNOWN' : String(record.retryable)}</p><p>Real destination, delivery receipt, external ticket ID and delivery time: unavailable.</p></Card>)}</> : <p>No delivery or ticket data available. No synthetic fallback is enabled.</p>}
    <Button disabled>Test webhook - unsupported</Button><Button disabled>Create ticket - unsupported</Button><Button disabled>Retry delivery - unsupported</Button>
  </div>;
}
