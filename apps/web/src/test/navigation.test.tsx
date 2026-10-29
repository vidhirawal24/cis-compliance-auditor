import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from '../auth/context';
import { ApiProvider } from '../api/context';
import { Sidebar } from '../components/layout/Sidebar';
import { Topbar } from '../components/layout/Topbar';
import { UserRole } from '../contracts/v1/enums';

const queryClient = new QueryClient();

const RoleTesterComponent: React.FC = () => {
  const { setRole } = useAuth();
  return (
    <div>
      <Sidebar />
      <button onClick={() => setRole(UserRole.VIEWER)}>Downgrade to Viewer</button>
      <button onClick={() => setRole(UserRole.OWNER)}>Upgrade to Owner</button>
    </div>
  );
};

describe('BaselineGuard - Navigation & Role-Aware Menus', () => {
  it('renders full navigation menu for OWNER role', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ApiProvider>
            <MemoryRouter initialEntries={['/orgs/demo-org/overview']}>
              <Sidebar />
            </MemoryRouter>
          </ApiProvider>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Asset Inventory')).toBeInTheDocument();
    expect(screen.getByText('Scan Center')).toBeInTheDocument();
    expect(screen.getByText('Remediation Planner')).toBeInTheDocument();
    expect(screen.getByText('What-If Simulator')).toBeInTheDocument();
    expect(screen.getByText('Approvals & Hardening')).toBeInTheDocument();
    expect(screen.getByText('Admin & Security')).toBeInTheDocument();
  });

  it('filters privileged menus when downgraded to VIEWER role', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ApiProvider>
            <MemoryRouter initialEntries={['/orgs/demo-org/overview']}>
              <RoleTesterComponent />
            </MemoryRouter>
          </ApiProvider>
        </AuthProvider>
      </QueryClientProvider>
    );

    // Initial state: Owner sees Remediation Planner
    expect(screen.getByText('Remediation Planner')).toBeInTheDocument();

    // Downgrade to Viewer
    fireEvent.click(screen.getByText('Downgrade to Viewer'));

    // Viewer should not see Remediation Planner, What-If Simulator, or Admin
    expect(screen.queryByText('Remediation Planner')).not.toBeInTheDocument();
    expect(screen.queryByText('What-If Simulator')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin & Security')).not.toBeInTheDocument();

    // But Viewer still sees Overview and Asset Inventory
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Asset Inventory')).toBeInTheDocument();
  });

  it('renders topbar with tenant name and role switcher', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ApiProvider>
            <MemoryRouter initialEntries={['/orgs/demo-org/overview']}>
              <Topbar onOpenMobileNav={() => {}} />
            </MemoryRouter>
          </ApiProvider>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(screen.getByText('Acme Financial SecOps (DEMO)')).toBeInTheDocument();
    expect(screen.getByLabelText('Switch Active Role')).toBeInTheDocument();
  });
});

