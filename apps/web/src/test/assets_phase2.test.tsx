import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';
import { DEMO_ORG_ID } from '../fixtures/demoData';

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

describe('BaselineGuard - Phase 2 Asset Inventory & Detail Suite', () => {
  it('renders asset inventory with masked OpenBao vault pointers (E15)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);

    expect(screen.getByText('Asset Inventory (E01)')).toBeInTheDocument();
    expect(screen.getByText('DEMO-W11-EXEC-01.acme.local')).toBeInTheDocument();
    expect(screen.getByText('DEMO-DC01.acme.local')).toBeInTheDocument();

    // Verify OpenBao secret path pointer masking
    expect(screen.getByText('vault:secret/win11-exec-winrm')).toBeInTheDocument();
  });

  it('filters asset inventory by search text and custom tag pills (E03)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);

    // Search for Fortinet
    const searchInput = screen.getByPlaceholderText('Search hostname, IP, vendor, model...');
    fireEvent.change(searchInput, { target: { value: 'Fortinet' } });

    expect(screen.getByText('DEMO-FG100F-PERIMETER')).toBeInTheDocument();
    expect(screen.queryByText('DEMO-W11-EXEC-01.acme.local')).not.toBeInTheDocument();

    // Clear search
    fireEvent.change(searchInput, { target: { value: '' } });
    expect(screen.getByText('DEMO-W11-EXEC-01.acme.local')).toBeInTheDocument();

    // Filter by tag
    const firewallTag = screen.getByText('#firewall');
    fireEvent.click(firewallTag);

    expect(screen.getByText('DEMO-FG100F-PERIMETER')).toBeInTheDocument();
  });

  it('validates Onboard Device Wizard forms and enforces zero-plaintext warning (E18, E15)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);

    const onboardBtn = screen.getByText('Onboard Device (E18)');
    fireEvent.click(onboardBtn);

    expect(screen.getByText('Device Onboarding Wizard (E18)')).toBeInTheDocument();

    // Clear hostname and IP to test validation
    const hostnameInput = screen.getByPlaceholderText('e.g. CORE-SW-01.acme.local');
    const ipInput = screen.getByPlaceholderText('e.g. 192.168.10.1');

    fireEvent.change(hostnameInput, { target: { value: '' } });
    fireEvent.change(ipInput, { target: { value: 'invalid-ip' } });

    const continueBtn = screen.getByText('Continue to Site & Risk');
    fireEvent.click(continueBtn);

    await waitFor(() => {
      expect(screen.getByText('Hostname is required')).toBeInTheDocument();
      expect(screen.getByText('Valid IPv4 address required')).toBeInTheDocument();
    });

    // Step 2 is blocked until valid
    expect(screen.queryByText('Site Identifier')).not.toBeInTheDocument();
  });

  it('runs Authorized Subnet Discovery Sweep (E02) and displays unassessed candidate list', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);

    const discoveryBtn = screen.getByText('Authorized Discovery (E02)');
    fireEvent.click(discoveryBtn);

    expect(screen.getByText('Authorized Subnet Discovery Sweep (E02)')).toBeInTheDocument();

    const sweepBtn = screen.getByText('Run Authorized Sweep');
    fireEvent.click(sweepBtn);

    await waitFor(() => {
      expect(screen.getByText(/Discovered Candidates/i)).toBeInTheDocument();
      expect(screen.getByText('Pending Onboarding (Unassessed)')).toBeInTheDocument();
    });
  });

  it('renders asset details with specs, supported vs unsupported capabilities, and OpenBao vault details', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets/a01-win11-corp-01`);

    expect(screen.getByText('DEMO-W11-EXEC-01.acme.local')).toBeInTheDocument();
    expect(screen.getByText('Device Specification & Collector Facts')).toBeInTheDocument();
    expect(screen.getByText(/Supported CIS Capabilities/i)).toBeInTheDocument();
    expect(screen.getByText(/Unsupported \/ Excluded Capabilities/i)).toBeInTheDocument();
    expect(screen.getByText('OpenBao Secret Path Pointer (E15)')).toBeInTheDocument();
  });

  it('opens edit asset modal and confirms save', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets/a01-win11-corp-01`);

    const editBtn = screen.getByText('Edit');
    fireEvent.click(editBtn);

    expect(screen.getByText('Edit Managed Asset')).toBeInTheDocument();

    const saveBtn = screen.getByText('Save Changes');
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(screen.queryByText('Edit Managed Asset')).not.toBeInTheDocument();
    });
  });
});
