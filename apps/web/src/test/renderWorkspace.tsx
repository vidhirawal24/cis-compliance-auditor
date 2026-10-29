import { useEffect, type ReactNode } from 'react';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider, useAuth } from '../auth/context';
import { ApiProvider } from '../api/context';
import { DemoApiClient, type ApiClientInterface } from '../api/client';
import { UserRole } from '../contracts/v1/enums';
import { DEMO_ORG_ID } from '../fixtures/demoData';

function TestRole({ role, children }: { role: UserRole; children: ReactNode }) {
  const { setRole, role: currentRole } = useAuth();
  useEffect(() => { setRole(role); }, [role]); // Set a fixture persona, not backend authorization.
  return currentRole === role ? <>{children}</> : null;
}

export function renderWorkspace(element: ReactNode, options: { api?: ApiClientInterface; path?: string; pattern?: string; role?: UserRole } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const view = render(<QueryClientProvider client={client}><AuthProvider><TestRole role={options.role ?? UserRole.OWNER}><ApiProvider client={options.api ?? new DemoApiClient()}><MemoryRouter initialEntries={[`/orgs/${DEMO_ORG_ID}/${options.path ?? 'approvals'}`]}><Routes><Route path={options.pattern ?? '/orgs/:orgId/*'} element={element} /></Routes></MemoryRouter></ApiProvider></TestRole></AuthProvider></QueryClientProvider>);
  return { ...view, client };
}
