import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';
import { DEMO_ORG_ID } from '../fixtures/demoData';
import { fixtureStore } from '../api/store';
import { UserRole } from '../contracts/v1/enums';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

// Helper component that allows switching user roles inside test trees safely
const RoleController: React.FC<{ targetRole?: UserRole }> = ({ targetRole }) => {
  const { setRole, role } = useAuth();
  React.useEffect(() => {
    if (targetRole && role !== targetRole) {
      setRole(targetRole);
    }
  }, [targetRole, role, setRole]);
  return null;
};

const renderWithRoute = async (initialPath: string, role?: UserRole) => {
  const view = render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiProvider>
          {role && <RoleController targetRole={role} />}
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

describe('BaselineGuard - Phase 4 Suite: Policy Library, Overrides, Exceptions & Manual Audits', () => {
  beforeEach(() => {
    fixtureStore.reset();
  });

  // -------------------------------------------------------------
  // Test 1: Policy pack and baseline version display (M17)
  // -------------------------------------------------------------
  it('01: displays active CIS benchmark packs with version, publisher, rule counts and platform (M17)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Verify header and tab
    expect(screen.getByText('CIS Policy & Benchmark Library (M17, M18, M19)')).toBeInTheDocument();
    expect(screen.getByText('Active Benchmark Packs (M17)')).toBeInTheDocument();

    // Verify Cisco benchmark pack
    expect(screen.getAllByText('CIS Cisco IOS 17 Benchmark v4.0.0').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('4.0.0').length).toBeGreaterThanOrEqual(1);

    // Verify Windows benchmark pack
    expect(screen.getAllByText('CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('3.0.0').length).toBeGreaterThanOrEqual(1);

    // Verify publisher attribution
    const publishers = screen.getAllByText(/Center for Internet Security \(CIS\)/i);
    expect(publishers.length).toBeGreaterThanOrEqual(1);

    // Verify rule count indicator
    expect(screen.getByText('6 Rules Defined')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 2: Benchmark values vs organization-specific overrides (M18)
  // -------------------------------------------------------------
  it('02: contrasts official benchmark expected value with organization override in control details (M18)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Locate rule with override: CIS-CISCO-ROUTER-2.1.2
    const ruleRow = screen.getByText('CIS-CISCO-ROUTER-2.1.2');
    expect(ruleRow).toBeInTheDocument();

    // Click on the rule to open Control Detail Modal
    fireEvent.click(ruleRow);

    // Verify Modal opens with Control details
    expect(screen.getByText(/Control Specification & Audit Logic/i)).toBeInTheDocument();

    // Verify official expected benchmark value
    expect(screen.getByText(/Benchmark Expected Configuration/i)).toBeInTheDocument();

    // Verify active organization override callout
    expect(screen.getByText(/Active Organization Baseline Override/i)).toBeInTheDocument();
    expect(screen.getByText('600s (10 minutes)')).toBeInTheDocument();
    expect(screen.getByText(/Approved for remote 24\/7 SecOps NOC/i)).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 3: Level 1 / Level 2 profile selection filtering (E11)
  // -------------------------------------------------------------
  it('03: filters policy rules by CIS Profile Level 1 and Level 2 (E11)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Initially ALL is selected, so both Level 1 and Level 2 rules exist
    expect(screen.getByText('CIS-CISCO-ROUTER-2.1.1')).toBeInTheDocument(); // Level 1
    expect(screen.getByText('CIS-CISCO-ROUTER-5.1.9')).toBeInTheDocument(); // Level 2

    // Filter to Level 1 only
    const level1Btn = screen.getByRole('button', { name: /^Level 1$/i });
    fireEvent.click(level1Btn);

    expect(screen.getByText('CIS-CISCO-ROUTER-2.1.1')).toBeInTheDocument();
    expect(screen.queryByText('CIS-CISCO-ROUTER-5.1.9')).not.toBeInTheDocument();

    // Filter to Level 2 only
    const level2Btn = screen.getByRole('button', { name: /^Level 2$/i });
    fireEvent.click(level2Btn);

    expect(screen.queryByText('CIS-CISCO-ROUTER-2.1.1')).not.toBeInTheDocument();
    expect(screen.getByText('CIS-CISCO-ROUTER-5.1.9')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 4: Unsupported content notice warnings (CIS-CISCO-ROUTER-3.4.1)
  // -------------------------------------------------------------
  it('04: displays unsupported content notice badge on controls requiring human or hardware attestation', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Verify control CIS-CISCO-ROUTER-3.4.1 exists
    expect(screen.getByText('CIS-CISCO-ROUTER-3.4.1')).toBeInTheDocument();

    // Verify unsupported content warning badge
    expect(
      screen.getByText(/Unsupported on non-wireless hardware/i)
    ).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 5: Override schema validation and creation (M19)
  // -------------------------------------------------------------
  it('05: validates override form schema and creates customized baseline override (M19)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Switch to Custom Baseline Overrides tab
    const overridesTab = screen.getByRole('button', { name: /Custom Baseline Overrides/i });
    fireEvent.click(overridesTab);

    // Verify existing override is displayed
    expect(screen.getByText('CIS-CISCO-ROUTER-2.1.2')).toBeInTheDocument();
    expect(screen.getByText('600s (10 minutes)')).toBeInTheDocument();

    // Click "Add Organization Override"
    const addBtn = screen.getByRole('button', { name: /Add Organization Override/i });
    fireEvent.click(addBtn);

    // Verify modal is open
    expect(screen.getByText(/Configure Organization Baseline Override/i)).toBeInTheDocument();

    // Submit without required fields -> verify validation error
    const submitBtn = screen.getByRole('button', { name: /Save Override/i });
    fireEvent.click(submitBtn);

    expect(screen.getByText('Control ID is required.')).toBeInTheDocument();

    // Fill valid data
    const controlSelect = screen.getByLabelText(/Target CIS Control/i);
    fireEvent.change(controlSelect, { target: { value: 'CIS-CISCO-ROUTER-2.1.1' } });

    const valueInput = screen.getByPlaceholderText(/e\.g\., 600s/i);
    fireEvent.change(valueInput, { target: { value: 'ssh_v2_strict_only' } });

    const rationaleInput = screen.getByPlaceholderText(/Justification for departing/i);
    fireEvent.change(rationaleInput, {
      target: { value: 'Mandated by corporate financial compliance governance board 2026.' },
    });

    fireEvent.click(submitBtn);

    // Verify modal closes and new override is rendered in the table
    expect(screen.queryByText(/Configure Organization Baseline Override/i)).not.toBeInTheDocument();
    expect(screen.getByText('ssh_v2_strict_only')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 6: Exception required fields, expiry countdown and filtering (E14)
  // -------------------------------------------------------------
  it('06: displays time-boxed exceptions with countdown badges and status filters (E14)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/exceptions`);

    // Verify header and alert invariant banner
    expect(screen.getByText('Exceptions & Manual Reviews (E12, E14)')).toBeInTheDocument();
    expect(
      screen.getByText(/Auditing Invariant \(E14\): Exceptions Provide Operational Tolerance Only/i)
    ).toBeInTheDocument();

    // Verify active exception
    expect(screen.getByText('exc-2026-901')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE OVERLAY')).toBeInTheDocument();

    // Verify expired exception
    expect(screen.getByText('exc-2026-802')).toBeInTheDocument();
    expect(screen.getByText('EXPIRED OVERLAY')).toBeInTheDocument();

    // Test filter pills
    const activeFilterBtn = screen.getByRole('button', { name: /^Active \(/i });
    fireEvent.click(activeFilterBtn);
    expect(screen.getByText('exc-2026-901')).toBeInTheDocument();
    expect(screen.queryByText('exc-2026-802')).not.toBeInTheDocument();

    const expiredFilterBtn = screen.getByRole('button', { name: /^Expired \(/i });
    fireEvent.click(expiredFilterBtn);
    expect(screen.queryByText('exc-2026-901')).not.toBeInTheDocument();
    expect(screen.getByText('exc-2026-802')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 7: Exceptions NEVER turn a failed control into PASS
  // -------------------------------------------------------------
  it('07: enforces invariant that creating an exception does NOT turn a failed finding into PASS', async () => {
    // Check initial finding status
    const targetFinding = fixtureStore.findings.find((f) => f.finding_id === 'find-telnet-01');
    expect(targetFinding?.status).toBe('FAIL');

    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/exceptions`);

    // Open Request Policy Exception Modal
    const requestBtn = screen.getByRole('button', { name: /Request Policy Exception/i });
    fireEvent.click(requestBtn);

    expect(screen.getByText('Request Time-Boxed Policy Exception (E14)')).toBeInTheDocument();

    // Select finding from dropdown
    const select = screen.getByLabelText(/Select Target Finding/i);
    fireEvent.change(select, { target: { value: 'find-telnet-01' } });

    // Enter valid justification
    const reasonInput = screen.getByPlaceholderText(/Describe legacy system dependency/i);
    fireEvent.change(reasonInput, {
      target: { value: 'Temporary network migration exception pending maintenance window.' },
    });

    // Submit exception
    const submitBtn = screen.getByRole('button', { name: /Submit Exception/i });
    fireEvent.click(submitBtn);

    expect(screen.queryByText('Request Time-Boxed Policy Exception (E14)')).not.toBeInTheDocument();

    // Verify target finding in fixtureStore still has status FAIL
    const updatedFinding = fixtureStore.findings.find((f) => f.finding_id === 'find-telnet-01');
    expect(updatedFinding?.status).toBe('FAIL'); // INVARIANT: Status remains FAIL!
    expect(updatedFinding?.exception).toBeDefined();
    expect(updatedFinding?.exception?.reason).toContain('Temporary network migration');
  });

  // -------------------------------------------------------------
  // Test 8: Manual review evidence validation and workflow (E12)
  // -------------------------------------------------------------
  it('08: validates attestation evidence URI and processes human review sign-off (E12)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/exceptions`);

    // Switch to Manual Review Queue tab
    const manualTab = screen.getByRole('button', { name: /Manual Review Queue/i });
    fireEvent.click(manualTab);

    // Verify pending review item rev-2026-01
    expect(screen.getByText('rev-2026-01')).toBeInTheDocument();
    expect(screen.getByText('PENDING ATTESTATION')).toBeInTheDocument();
    expect(screen.getByText(/No evidence attached \(Mandatory artifact required/i)).toBeInTheDocument();

    // Click "Attest & Sign Off" on card
    const signoffBtn = screen.getByRole('button', { name: /Attest & Sign Off/i });
    fireEvent.click(signoffBtn);

    // Modal appears
    expect(screen.getByText('Human Attestation Sign-Off (E12)')).toBeInTheDocument();

    // Attempt sign-off without evidence URI -> expect validation error
    const submitBtn = screen.getByRole('button', { name: /^Confirm Attestation$/i });
    fireEvent.click(submitBtn);

    expect(
      screen.getByText('Attestation justification / inspection notes must be at least 10 characters.')
    ).toBeInTheDocument();

    // Provide justification but no evidence URI
    const notesInput = screen.getByPlaceholderText(/Detail physical inspection date/i);
    fireEvent.change(notesInput, {
      target: { value: 'Inspected rack 4 server enclosure locks with badge security officer.' },
    });
    fireEvent.click(submitBtn);

    expect(
      screen.getByText('Attestation evidence artifact URI is mandatory for human sign-off.')
    ).toBeInTheDocument();

    // Provide valid evidence URI
    const uriInput = screen.getByPlaceholderText(/e\.g\. supabase:\/\/manual-evidence/i);
    fireEvent.change(uriInput, {
      target: { value: 'supabase://manual-evidence/2026/rack4_inspection_photo.jpg' },
    });
    fireEvent.click(submitBtn);

    // Modal closes and review status becomes ATTESTED_PASS
    expect(screen.queryByText('Human Attestation Sign-Off (E12)')).not.toBeInTheDocument();
    expect(screen.getAllByText('ATTESTED PASS').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('supabase://manual-evidence/2026/rack4_inspection_photo.jpg')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 9: Read-only auditors (AUDITOR, VIEWER) cannot use editor controls
  // -------------------------------------------------------------
  it('09: blocks read-only AUDITOR role from modifying overrides or creating exceptions', async () => {
    // Render Policies view as AUDITOR
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`, UserRole.AUDITOR);

    // Switch to Overrides tab
    const overridesTab = screen.getByRole('button', { name: /Custom Baseline Overrides/i });
    fireEvent.click(overridesTab);

    // Verify Read-Only Auditor Mode badge is shown and Add button is disabled
    expect(screen.getByText('Read-Only Auditor Mode')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add Organization Override/i })).toBeDisabled();
  });

  // -------------------------------------------------------------
  // Test 10: Version diff & upgrade impact preview (E20, I19)
  // -------------------------------------------------------------
  it('10: renders version diff and upgrade impact without invented differences (E20, I19)', async () => {
    await renderWithRoute(`/orgs/${DEMO_ORG_ID}/policies`);

    // Switch to Upgrade Impact Preview tab
    const diffTab = screen.getByRole('button', { name: /Upgrade Impact Preview/i });
    fireEvent.click(diffTab);

    // Verify Cisco Benchmark Diff (v3.2.0 -> v4.0.0)
    expect(screen.getByText(/Benchmark Version Upgrade Impact Simulator/i)).toBeInTheDocument();
    expect(screen.getByText(/-3\.8% Impact/i)).toBeInTheDocument();
    expect(screen.getByText(/Affects 4 production devices/i)).toBeInTheDocument();

    // Verify added rule
    expect(screen.getByText('CIS-CISCO-ROUTER-2.4.5')).toBeInTheDocument();
    expect(screen.getByText('Restrict SSH MAC Algorithms to HMAC-SHA2-512')).toBeInTheDocument();

    // Verify removed / deprecated rule
    expect(screen.getByText('CIS-CISCO-ROUTER-1.0.4')).toBeInTheDocument();
    expect(screen.getByText(/Legacy SNMP community string complexity/i)).toBeInTheDocument();

    // Verify modified rule with old and new values
    expect(screen.getByText('CIS-CISCO-ROUTER-2.1.2')).toBeInTheDocument();
    expect(screen.getByText('900s (15 mins)')).toBeInTheDocument();
    expect(screen.getByText(/300s \(5 mins\)/i)).toBeInTheDocument();

    // Switch pack to Windows 11 (which has no upgrade diff history)
    const packSelect = screen.getByLabelText(/Benchmark Pack Diff Selector/i);
    fireEvent.change(packSelect, { target: { value: 'cis-windows-11-v3' } });

    // Verify honest missing data state without fabricated diffs
    expect(screen.getByText('No Benchmark Version Diff Available')).toBeInTheDocument();
    expect(
      screen.getByText(/There is no recorded previous benchmark release diff for this policy pack/i)
    ).toBeInTheDocument();
  });
});
