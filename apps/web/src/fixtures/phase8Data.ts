// DEMO ONLY: presentation examples, not notification receipts or external tickets.
export interface DemoDelivery {
  id: string;
  channel: 'ALERTS' | 'WEBHOOKS' | 'TICKETS';
  status: 'PENDING' | 'DELIVERED' | 'FAILED' | 'UNKNOWN';
  description: string;
  error?: string;
  retryable: boolean | null;
}
export const DEMO_DELIVERIES: DemoDelivery[] = [
  { id: 'demo-alert-pending', channel: 'ALERTS', status: 'PENDING', description: 'Synthetic drift alert queued', retryable: null },
  { id: 'demo-webhook-delivered', channel: 'WEBHOOKS', status: 'DELIVERED', description: 'Synthetic delivery-status example; no real message was sent', retryable: false },
  { id: 'demo-webhook-failed', channel: 'WEBHOOKS', status: 'FAILED', description: 'Synthetic timeout example', error: 'DEMO endpoint timeout', retryable: true },
  { id: 'demo-ticket-unknown', channel: 'TICKETS', status: 'UNKNOWN', description: 'External ticket identity and destination unavailable', retryable: null },
];
