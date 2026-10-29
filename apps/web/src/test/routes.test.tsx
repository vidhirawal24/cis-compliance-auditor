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

describe('BaselineGuard - 19 Route Shells Smoke Test', () => {
  it('01: renders Authentication shell on /auth/login', () => {
    renderWithRoute('/auth/login');
    expect(screen.getByText('Sign In to Workspace')).toBeInTheDocument();
    expect(screen.getByText('Corporate Email')).toBeInTheDocument();
  });

  it('02: renders Organization Selection shell on /orgs', () => {
    renderWithRoute('/orgs');
    expect(screen.getByText('Select Tenant Workspace')).toBeInTheDocument();
    expect(screen.getByText('Acme Financial SecOps (DEMO)')).toBeInTheDocument();
  });

  it('03: renders Overview shell on /orgs/:orgId/overview', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/overview`);
    expect(screen.getByText('Security Posture & Compliance Overview')).toBeInTheDocument();
    expect(screen.getByText('ASSESSED COMPLIANCE')).toBeInTheDocument();
    expect(screen.getByText('ASSESSMENT COVERAGE')).toBeInTheDocument();
  });

  it('04: renders Asset Inventory shell on /orgs/:orgId/assets', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets`);
    expect(screen.getByText('Asset Inventory (E01)')).toBeInTheDocument();
    expect(screen.getByText('DEMO-W11-EXEC-01.acme.local')).toBeInTheDocument();
  });

  it('05: renders Asset Details shell on /orgs/:orgId/assets/:id', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/assets/a01-win11-corp-01`);
    expect(screen.getByText('System Overview')).toBeInTheDocument();
    expect(screen.getByText('Device Specification & Collector Facts')).toBeInTheDocument();
  });

  it('06: renders Scan Center shell on /orgs/:orgId/scans', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans`);
    expect(screen.getByText('Audit Scan Center (M13, E04, E18)')).toBeInTheDocument();
    expect(screen.getByText('Launch Audit Wizard')).toBeInTheDocument();
  });

  it('07: renders Policy Library shell on /orgs/:orgId/policies', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);
    expect(screen.getByText('CIS Policy & Benchmark Library (M17, M18, M19)')).toBeInTheDocument();
    expect(screen.getByText('Active Benchmark Packs (M17)')).toBeInTheDocument();
  });

  it('08: renders Exceptions shell on /orgs/:orgId/exceptions', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/exceptions`);
    expect(screen.getByText('Exceptions & Manual Reviews (E12, E14)')).toBeInTheDocument();
    expect(screen.getByText('Request Policy Exception (E14)')).toBeInTheDocument();
  });

  it('09: renders Findings shell on /orgs/:orgId/findings', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);
    expect(screen.getByText(/Findings & Compliance Evidence Explorer/i)).toBeInTheDocument();
  });

  it('10: renders Security Graph shell on /orgs/:orgId/graph', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);
    expect(screen.getByText(/Cross-Layer Security & Topology Graph/i)).toBeInTheDocument();
  });

  it('11: renders Risk Scenarios shell on /orgs/:orgId/risk-scenarios', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/risk-scenarios`);
    expect(screen.getByText(/Correlated Risk Scenarios/i)).toBeInTheDocument();
  });

  it('12: renders Remediation Planner shell on /orgs/:orgId/planner', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/planner`);
    expect(screen.getByText(/Remediation Planner & Sequence DAG/i)).toBeInTheDocument();
  });

  it('13: renders What-If Simulator shell on /orgs/:orgId/simulator', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/simulator`);
    expect(screen.getByText(/What-If Simulator & Service Safety/i)).toBeInTheDocument();
  });

  it('14: renders Approvals & Hardening shell on /orgs/:orgId/approvals', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/approvals`);
    expect(screen.getByText(/Approvals & Controlled Hardening/i)).toBeInTheDocument();
  });

  it('15: renders Verification & Proof shell on /orgs/:orgId/verifications', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/verifications`);
    expect(screen.getByText(/Dual Verification & Proof Dossier/i)).toBeInTheDocument();
  });

  it('16: renders Reports shell on /orgs/:orgId/reports', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/reports`);
    expect(screen.getByText(/Compliance Reports & Drift Timeline/i)).toBeInTheDocument();
  });

  it('17: renders Notifications & Tickets shell on /orgs/:orgId/notifications', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/notifications`);
    expect(screen.getByText(/Alerts & Integration Delivery/i)).toBeInTheDocument();
  });

  it('18: renders Admin & Security shell on /orgs/:orgId/admin/users', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/admin/users`);
    expect(screen.getByText(/Administration & Security Governance/i)).toBeInTheDocument();
  });

  it('19: renders System States shell on /orgs/:orgId/system-states', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/system-states`);
    expect(screen.getByText(/System States & Edge Case Gallery/i)).toBeInTheDocument();
  });
});

