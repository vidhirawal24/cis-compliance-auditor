import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';
import { DEMO_ORG_ID } from '../fixtures/demoData';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

const renderWithRoute = (initialPath: string) => {
  return render(
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
};

describe('BaselineGuard - 19 Route Shells Smoke Test', async () => {
  it('01: renders Authentication shell on /auth/login', async () => {
    renderWithRoute('/auth/login');
    expect(await screen.findByText('Sign In to Workspace')).toBeInTheDocument();
    expect(await screen.findByText('Corporate Email')).toBeInTheDocument();
  });

  it('02: renders Organization Selection shell on /orgs', async () => {
    renderWithRoute('/orgs');
    expect(await screen.findByText('Select Tenant Workspace')).toBeInTheDocument();
    expect(await screen.findByText('Acme Financial SecOps (DEMO)')).toBeInTheDocument();
  });

  it('03: renders Overview shell on /orgs/:orgId/overview', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/overview`);
    expect(await screen.findByText('Security Posture & Compliance Overview')).toBeInTheDocument();
    expect(await screen.findByText('ASSESSED COMPLIANCE')).toBeInTheDocument();
    expect(await screen.findByText('ASSESSMENT COVERAGE')).toBeInTheDocument();
  });

  it('04: renders Asset Inventory shell on /orgs/:orgId/assets', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);
    expect(await screen.findByText('Asset Inventory (E01)')).toBeInTheDocument();
    expect(await screen.findByText('DEMO-W11-EXEC-01.acme.local')).toBeInTheDocument();
  });

  it('05: renders Asset Details shell on /orgs/:orgId/assets/:id', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets/a01-win11-corp-01`);
    expect(await screen.findByText('System Overview')).toBeInTheDocument();
    expect(await screen.findByText('Device Specification & Collector Facts')).toBeInTheDocument();
  });

  it('06: renders Scan Center shell on /orgs/:orgId/scans', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans`);
    expect(await screen.findByText('Audit Scan Center (M13, E04, E18)')).toBeInTheDocument();
    expect(await screen.findByText('Launch Audit Wizard')).toBeInTheDocument();
  });

  it('07: renders Policy Library shell on /orgs/:orgId/policies', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);
    expect(await screen.findByText('CIS Policy & Benchmark Library (M17, M18, M19)')).toBeInTheDocument();
    expect(await screen.findByText('Active Benchmark Packs (M17)')).toBeInTheDocument();
  });

  it('08: renders Exceptions shell on /orgs/:orgId/exceptions', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/exceptions`);
    expect(await screen.findByText('Exceptions & Manual Reviews (E12, E14)')).toBeInTheDocument();
    expect(await screen.findByText('Request Policy Exception (E14)')).toBeInTheDocument();
  });

  it('09: renders Findings shell on /orgs/:orgId/findings', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);
    expect(await screen.findByText(/Findings & Compliance Evidence Explorer/i)).toBeInTheDocument();
  });

  it('10: renders Security Graph shell on /orgs/:orgId/graph', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);
    expect(await screen.findByText(/Cross-Layer Security & Topology Graph/i)).toBeInTheDocument();
  });

  it('11: renders Risk Scenarios shell on /orgs/:orgId/risk-scenarios', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/risk-scenarios`);
    expect(await screen.findByText(/Correlated Risk Scenarios/i)).toBeInTheDocument();
  });

  it('12: renders Remediation Planner shell on /orgs/:orgId/planner', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/planner`);
    expect(await screen.findByText(/Remediation Planner & Sequence DAG/i)).toBeInTheDocument();
  });

  it('13: renders What-If Simulator shell on /orgs/:orgId/simulator', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/simulator`);
    expect(await screen.findByText(/What-If Simulator & Service Safety/i)).toBeInTheDocument();
  });

  it('14: renders Approvals & Hardening shell on /orgs/:orgId/approvals', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/approvals`);
    expect(await screen.findByText(/Approvals & Controlled Hardening/i)).toBeInTheDocument();
  });

  it('15: renders Verification & Proof shell on /orgs/:orgId/verifications', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/verifications`);
    expect(await screen.findByText(/Dual Verification & Proof Dossier/i)).toBeInTheDocument();
  });

  it('16: renders Reports shell on /orgs/:orgId/reports', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/reports`);
    expect(await screen.findByText(/Compliance Reports & Drift Timeline/i)).toBeInTheDocument();
  });

  it('17: renders Notifications & Tickets shell on /orgs/:orgId/notifications', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/notifications`);
    expect(await screen.findByText(/Alerts & Integration Delivery/i)).toBeInTheDocument();
  });

  it('18: renders Admin & Security shell on /orgs/:orgId/admin/users', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/admin/users`);
    expect(await screen.findByText(/Administration & Security Governance/i)).toBeInTheDocument();
  });

  it('19: renders System States shell on /orgs/:orgId/system-states', async () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/system-states`);
    expect(await screen.findByText(/System States & Edge Case Gallery/i)).toBeInTheDocument();
  });
});

