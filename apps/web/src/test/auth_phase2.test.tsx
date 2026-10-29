import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AuthShell } from '../routes/shells/01_AuthShell';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

const renderAuth = () => {
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiProvider>
          <MemoryRouter initialEntries={['/auth/login']}>
            <AuthShell />
          </MemoryRouter>
        </ApiProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

describe('BaselineGuard - Phase 2 Authentication Suite', () => {
  it('renders login screen with Supabase Auth form and clearly demarcated Demo section', () => {
    renderAuth();

    expect(screen.getByText('BaselineGuard')).toBeInTheDocument();
    expect(screen.getByText('Sign In to Workspace')).toBeInTheDocument();
    expect(screen.getByText('Sign In via Supabase Auth')).toBeInTheDocument();
    expect(screen.getByText(/\[DEMO MODE: Synthetic Lab Only\]/i)).toBeInTheDocument();
  });

  it('validates invalid email and short password on standard login form', async () => {
    renderAuth();

    const submitBtn = screen.getByText('Sign In via Supabase Auth');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText('Valid corporate email address required')).toBeInTheDocument();
      expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument();
    });
  });

  it('navigates to Password Recovery and validates recovery email form', async () => {
    renderAuth();

    const forgotBtn = screen.getByText('Forgot password?');
    fireEvent.click(forgotBtn);

    expect(screen.getByText('Password Recovery')).toBeInTheDocument();

    const sendBtn = screen.getByText('Send Recovery Link');
    fireEvent.click(sendBtn);

    await waitFor(() => {
      expect(screen.getByText('Valid corporate email address required')).toBeInTheDocument();
    });

    // Enter valid email
    const emailInput = screen.getByPlaceholderText('name@company.com');
    fireEvent.change(emailInput, { target: { value: 'apoorva@baselineguard.local' } });
    fireEvent.click(sendBtn);

    await waitFor(() => {
      expect(screen.getByText(/Password reset/i)).toBeInTheDocument();
    });
  });

  it('navigates to MFA enrollment screen with TOTP seed', async () => {
    renderAuth();

    const mfaEnrollBtn = screen.getByText('Enroll TOTP MFA');
    fireEvent.click(mfaEnrollBtn);

    await waitFor(() => {
      expect(screen.getByText('MFA TOTP Enrollment')).toBeInTheDocument();
      expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
    });

    const doneBtn = screen.getByText('Done & Return to Sign In');
    fireEvent.click(doneBtn);
    expect(screen.getByText('Sign In to Workspace')).toBeInTheDocument();
  });

  it('triggers MFA Challenge for privileged demo roles and validates 6-digit code', async () => {
    renderAuth();

    // The default selected role is OWNER (privileged)
    const demoQuickBtn = screen.getByText('Quick Sign-In (DEMO Mode)');
    fireEvent.click(demoQuickBtn);

    // Should transition to MFA Challenge
    await waitFor(() => {
      expect(screen.getByText('MFA Security Challenge')).toBeInTheDocument();
      expect(screen.getByText('Verify Token & Enter Workspace')).toBeInTheDocument();
    });

    const verifyBtn = screen.getByText('Verify Token & Enter Workspace');
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(screen.getByText('Must be a 6-digit verification code')).toBeInTheDocument();
    });
  });
});
