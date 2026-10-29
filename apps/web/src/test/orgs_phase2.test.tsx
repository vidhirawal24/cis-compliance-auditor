import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

const renderWithRoute = async (initialPath: string) => {
  const view = render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiProvider>
          <MemoryRouter initialEntries={[initialPath]}>
            <AppRouter />
          </MemoryRouter>
        </ApiProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
  await waitFor(() => expect(screen.queryByText('Loading records...')).not.toBeInTheDocument());
  return view;
};

describe('BaselineGuard - Phase 2 Organization Shell & Tenant Isolation', () => {
  it('renders organization selection view with authorized tenants', async () => {
    await renderWithRoute('/orgs');

    expect(screen.getByText('Select Tenant Workspace')).toBeInTheDocument();
    expect(screen.getByText('Acme Financial SecOps (DEMO)')).toBeInTheDocument();
    expect(screen.getByText('Healthcare DMZ Staging')).toBeInTheDocument();
  });

  it('blocks access to unauthorized tenant workspace with 403 Tenant Isolation screen (M34)', async () => {
    // Attempting to directly navigate to an unassigned/forbidden tenant
    await renderWithRoute('/orgs/org-unauthorized-adversary-corp/overview');

    expect(screen.getByText(/ERROR 403 - TENANT ISOLATION/i)).toBeInTheDocument();
    expect(screen.getByText('Cross-Tenant Access Restricted')).toBeInTheDocument();
    expect(screen.getByText(/org-unauthorized-adversary-corp/i)).toBeInTheDocument();
    expect(screen.getByText('Switch to Authorized Workspace')).toBeInTheDocument();
  });

  it('validates organization creation form with min lengths and slug constraints', async () => {
    await renderWithRoute('/orgs');

    const createTrigger = screen.getByText('Create New Tenant Workspace');
    fireEvent.click(createTrigger);

    expect(screen.getByText('New Compliance Workspace')).toBeInTheDocument();

    const submitBtn = screen.getByText('Provision Workspace');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText('Workspace name must be at least 3 characters')).toBeInTheDocument();
      expect(screen.getByText('Slug must be at least 3 characters')).toBeInTheDocument();
    });

    // Test invalid slug with uppercase and spaces
    const slugInput = screen.getByPlaceholderText('e.g. acme-corp-emea');
    fireEvent.change(slugInput, { target: { value: 'INVALID SLUG!' } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText('Slug must only contain lowercase letters, numbers, and hyphens')).toBeInTheDocument();
    });
  });
});
