import type { ReactNode } from 'react';
import { Button } from '../ui/button';

export function apiErrorText(error: unknown): string {
  const data = error as { status?: number; response?: { status?: number }; code?: string } | null;
  const status = data?.status ?? data?.response?.status;
  if (data?.code === 'UNSUPPORTED') return 'UNSUPPORTED: operation or response contract is unavailable.';
  if (status === 403 || data?.code === 'FORBIDDEN') return '403 Forbidden: the server denied access.';
  if (status === 401 || data?.code === 'UNAUTHORIZED') return '401 Unauthorized: sign in again.';
  // Transport errors can contain signed URLs or credentials. Never echo them.
  return 'Request failed. Data is unavailable; no fixture fallback was used.';
}

export function ApiState({ pending, error, retry, children }: {
  pending: boolean; error: unknown; retry?: () => void; children: ReactNode;
}) {
  if (pending) return <p role="status">Loading records...</p>;
  if (error) {
    const message = apiErrorText(error);
    const denied = message.startsWith('401') || message.startsWith('403');
    const retryable = (error as { retryable?: boolean })?.retryable !== false;
    return <div role="alert"><p>{message}</p>{retry && !denied && retryable && <Button variant="outline" onClick={retry}>Retry request</Button>}</div>;
  }
  return <>{children}</>;
}
