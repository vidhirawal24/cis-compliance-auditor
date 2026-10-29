import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuth } from './context';

// Presentation cache isolation only; the backend still authorizes every request.
export function SessionCacheBoundary({ children }: { children: ReactNode }) {
  const { user, currentOrg, role, authMode } = useAuth();
  const client = useQueryClient();
  const scope = `${authMode}:${user?.id ?? ''}:${currentOrg?.org_id ?? ''}:${role}`;
  const previous = useRef(scope);
  const [ready, setReady] = useState(scope);
  useLayoutEffect(() => {
    if (previous.current !== scope) {
      client.clear();
      previous.current = scope;
      setReady(scope);
    }
  }, [scope, client]);
  return ready === scope ? <>{children}</> : <p role="status">Clearing previous session data...</p>;
}
