import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { EmptyState } from '../components/common/EmptyState';
import { LoadingSkeleton } from '../components/common/LoadingSkeleton';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { AuthGuard } from '../auth/AuthGuard';
import { UserRole } from '../contracts/v1/enums';

const queryClient = new QueryClient();

// Faulty component for testing ErrorBoundary
const CrashComponent: React.FC = () => {
  throw new Error('Deterministic Component Panic Test');
};

describe('BaselineGuard - States & Edge Case Tests', () => {
  it('renders EmptyState with action button', () => {
    const onAction = vi.fn();
    render(
      <EmptyState
        title="No Devices Found"
        description="Try registering a new subnet range."
        action={{ label: 'Add Device', onClick: onAction }}
      />
    );

    expect(screen.getByText('No Devices Found')).toBeInTheDocument();
    expect(screen.getByText('Try registering a new subnet range.')).toBeInTheDocument();
    expect(screen.getByText('Add Device')).toBeInTheDocument();
  });

  it('renders LoadingSkeleton without crashing', () => {
    const { container } = render(<LoadingSkeleton type="table" rows={3} />);
    expect(container.getElementsByClassName('animate-pulse').length).toBeGreaterThan(0);
  });

  it('ErrorBoundary catches rendering failures and provides recovery CTA', () => {
    // Suppress console.error in test output for intentional crash
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <CrashComponent />
      </ErrorBoundary>
    );

    expect(screen.getByText('Component Execution Error')).toBeInTheDocument();
    expect(screen.getByText(/No sensitive diagnostic details are displayed/)).toBeInTheDocument();
    expect(screen.queryByText(/Deterministic Component Panic Test/)).not.toBeInTheDocument();
    expect(screen.getByText('Try Recovering View')).toBeInTheDocument();

    spy.mockRestore();
  });

  it('AuthGuard denies access and renders 403 screen when role is insufficient', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <MemoryRouter>
            {/* Require AUDITOR role, but default context user is OWNER */}
            <AuthGuard allowedRoles={[UserRole.AUDITOR]}>
              <div>Privileged Auditor Only Content</div>
            </AuthGuard>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(screen.getByText('ERROR 403 - FORBIDDEN')).toBeInTheDocument();
    expect(screen.getByText('Access Denied')).toBeInTheDocument();
    expect(screen.queryByText('Privileged Auditor Only Content')).not.toBeInTheDocument();
  });
});

