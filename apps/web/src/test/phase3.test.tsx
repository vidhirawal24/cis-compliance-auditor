import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';
import { DEMO_ORG_ID } from '../fixtures/demoData';
import { fixtureStore } from '../api/store';
import { EvaluationStatus } from '../contracts/v1/enums';

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

describe('BaselineGuard - Phase 3 Suite: Dashboard, Scans & Findings', () => {
  beforeEach(() => {
    fixtureStore.reset();
  });

  // -------------------------------------------------------------
  // Test 1: Overview Dashboard Metrics & Invariant Separation
  // -------------------------------------------------------------
  describe('Overview Dashboard (M34, M35, E07)', () => {
    it('displays ASSESSED COMPLIANCE and ASSESSMENT COVERAGE as distinct metrics', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/overview`);

      // Verify separate metrics exist
      expect(screen.getByText('ASSESSED COMPLIANCE')).toBeInTheDocument();
      expect(screen.getByText('ASSESSMENT COVERAGE')).toBeInTheDocument();

      // Verify mathematical formula is displayed
      expect(screen.getByText('Formula: PASS / (PASS + FAIL)')).toBeInTheDocument();

      // Verify backend values are rendered directly without manufacturing
      const currentScan = fixtureStore.scans[0];
      expect(screen.getByText(`${currentScan.assessed_compliance_pct}%`)).toBeInTheDocument();
      expect(screen.getByText(`${currentScan.assessment_coverage_pct}%`)).toBeInTheDocument();
    });

    it('renders all 6 invariant evaluation statuses and NEVER counts NOT_ASSESSED as PASS', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/overview`);

      // Verify all 6 status headers are rendered in the manifest
      expect(screen.getByText('PASS')).toBeInTheDocument();
      expect(screen.getByText('FAIL')).toBeInTheDocument();
      expect(screen.getByText('NOT APPLICABLE')).toBeInTheDocument();
      expect(screen.getByText('MANUAL REVIEW')).toBeInTheDocument();
      expect(screen.getByText('ERROR')).toBeInTheDocument();
      expect(screen.getByText('NOT ASSESSED')).toBeInTheDocument();

      // Verify explicit rule notice is rendered
      expect(
        screen.getByText('Integrity Rule: NOT_ASSESSED is NEVER counted as PASS')
      ).toBeInTheDocument();

      // Verify exact counts from fixture store
      const passFindings = fixtureStore.findings.filter((f) => f.status === EvaluationStatus.PASS);
      const notAssessedFindings = fixtureStore.findings.filter((f) => f.status === EvaluationStatus.NOT_ASSESSED);

      expect(passFindings.length).toBe(2);
      expect(notAssessedFindings.length).toBe(1);

      // Verify PASS count card renders '2'
      const passText = screen.getByText('PASS');
      const passCard = passText.closest('.rounded-lg');
      expect(passCard).toHaveTextContent('2');

      // Verify NOT ASSESSED card renders '1'
      const naText = screen.getByText('NOT ASSESSED');
      const naCard = naText.closest('.rounded-lg');
      expect(naCard).toHaveTextContent('1');
    });

    it('renders Recharts visual intelligence sections for trends and severity breakdown', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/overview`);

      expect(screen.getByText('30-Day Posture Historical Trend (E07)')).toBeInTheDocument();
      expect(screen.getByText('Severity Breakdown (M35)')).toBeInTheDocument();
      expect(screen.getByText('Platform Family Compliance Posture')).toBeInTheDocument();
      expect(screen.getByText('CIS Benchmark Category Risk Distribution')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------
  // Test 2: Scan Center, Wizard & Mandatory Read-Only Confirmation
  // -------------------------------------------------------------
  describe('Audit Scan Center (M13, E04, E18)', () => {
    it('renders scan queue with read-only badge, progress and completion stats', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans`);

      expect(screen.getByText('Audit Scan Center (M13, E04, E18)')).toBeInTheDocument();
      expect(screen.getByText('scan-2026-1029-01')).toBeInTheDocument();

      // Verify all scans display READ-ONLY badge
      const readOnlyBadges = screen.getAllByText('READ-ONLY');
      expect(readOnlyBadges.length).toBeGreaterThan(0);
    });

    it('enforces mandatory Read-Only Audit confirmation checkbox (E18) in the launch wizard', async () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans?tab=NEW_SCAN`);

      expect(screen.getByText('Multi-Target Audit Scan Dispatcher (M13, E08, E18)')).toBeInTheDocument();

      const dispatchButton = screen.getByRole('button', { name: /Dispatch Audit Job/i });

      // Initially, the read-only checkbox is unchecked, so dispatch button is disabled
      expect(dispatchButton).toBeDisabled();

      // Find the mandatory confirmation checkbox
      const checkbox = screen.getByRole('checkbox', { name: /Confirm Read-Only Audit Execution/i });
      expect(checkbox).not.toBeChecked();

      // Check the checkbox
      fireEvent.click(checkbox);
      expect(checkbox).toBeChecked();

      // Dispatch button is now enabled
      expect(dispatchButton).toBeEnabled();

      // Click dispatch
      fireEvent.click(dispatchButton);

      // Verify wizard dispatches scan and transitions back to history tab
      await waitFor(() => {
        expect(screen.getByText('Audit History & Active Runs (5)')).toBeInTheDocument();
      });
    });

    it('displays per-target errors drawer for failed scans and allows retry', async () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans`);

      // Find failed scan 'scan-2026-1027-04'
      expect(screen.getByText('scan-2026-1027-04')).toBeInTheDocument();

      // Click "View Errors"
      const viewErrorsButton = screen.getByRole('button', { name: /View Errors/i });
      fireEvent.click(viewErrorsButton);

      // Verify error modal opens with target failure details
      expect(screen.getByText('Target Execution Faults: scan-2026-1027-04')).toBeInTheDocument();
      expect(screen.getByText(/DEMO-CP6600-CLUSTER-A/)).toBeInTheDocument();
      expect(screen.getByText(/Management API socket timeout after 15000ms/)).toBeInTheDocument();

      // Click "Retry Failed Scan" inside modal
      const retryModalButton = screen.getByRole('button', { name: /Retry Failed Scan/i });
      fireEvent.click(retryModalButton);

      // Verify modal closes and retried scan is added
      await waitFor(() => {
        expect(screen.queryByText('Target Execution Faults: scan-2026-1027-04')).not.toBeInTheDocument();
      });
    });

    it('manages recurring cron audit schedules with 5-field cron validation (E04)', async () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/scans?tab=SCHEDULES`);

      expect(screen.getByText('Active Cron Audit Schedules (E04)')).toBeInTheDocument();
      expect(screen.getByText('Daily Midnight Core Fleet Audit')).toBeInTheDocument();
      expect(screen.getByText('Cron: 0 0 * * *')).toBeInTheDocument();

      // Open Add Schedule modal
      const addScheduleButton = screen.getByRole('button', { name: /Add Schedule/i });
      fireEvent.click(addScheduleButton);

      expect(screen.getByText('Create Recurring Audit Schedule (E04)')).toBeInTheDocument();

      // Enter invalid cron expression
      const cronInput = screen.getByPlaceholderText('0 0 * * * (Midnight daily)');
      fireEvent.change(cronInput, { target: { value: 'invalid-cron' } });

      const nameInput = screen.getByPlaceholderText('e.g., Nightly Core Network Audit');
      fireEvent.change(nameInput, { target: { value: 'Test Invalidation Schedule' } });

      const saveButton = screen.getByRole('button', { name: /Save Schedule/i });
      fireEvent.click(saveButton);

      // Verify error message is rendered
      expect(
        screen.getByText('Cron expression must follow standard 5-field syntax (e.g., "0 0 * * *").')
      ).toBeInTheDocument();

      // Correct cron expression to 5 fields
      fireEvent.change(cronInput, { target: { value: '0 12 * * *' } });
      fireEvent.click(saveButton);

      // Verify schedule was saved and modal closed
      await waitFor(() => {
        expect(screen.getByText('Test Invalidation Schedule')).toBeInTheDocument();
        expect(screen.getByText('Cron: 0 12 * * *')).toBeInTheDocument();
      });
    });
  });

  // -------------------------------------------------------------
  // Test 3: Findings Explorer, Evidence, Exceptions & Non-Executable CLI
  // -------------------------------------------------------------
  describe('Findings Explorer (M36, M37, E29)', () => {
    it('renders side-by-side Expected vs Observed state and SHA-256 evidence hash (M36)', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);

      expect(screen.getByText(/Findings & Compliance Evidence Explorer/i)).toBeInTheDocument();

      // Verify first finding is selected by default: CIS-CISCO-ROUTER-2.1.1 (Telnet Enabled)
      expect(screen.getByText('Expected State (CIS Benchmark)')).toBeInTheDocument();
      expect(screen.getByText('Observed State (Live Evidence)')).toBeInTheDocument();

      // Check SHA-256 evidence reference
      expect(
        screen.getByText('Collector Evidence & Cryptographic Provenance (M12)')
      ).toBeInTheDocument();
      expect(
        screen.getByText('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
      ).toBeInTheDocument();
    });

    it('renders remediation guidance strictly as non-executable text with risk warnings (M37)', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);

      expect(
        screen.getByText('Actionable Remediation Guidance (Read-Only Preview) (M37)')
      ).toBeInTheDocument();

      // Verify copy button exists
      expect(screen.getByRole('button', { name: /Copy CLI/i })).toBeInTheDocument();

      // Verify Risk Warning banner is displayed
      expect(screen.getByText(/Risk Warning:/i)).toBeInTheDocument();

      // Verify CLI is rendered inside <pre> tag (non-executable)
      const cliBlock = screen.getByText(/transport input ssh/i);
      expect(cliBlock.tagName.toLowerCase()).toBe('pre');

      // Verify disclaimer is present
      expect(
        screen.getByText(/Browser client executes zero mutations directly/i)
      ).toBeInTheDocument();
    });

    it('filters findings by evaluation status including NOT_ASSESSED and ERROR', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);

      // Filter by NOT_ASSESSED status
      const statusSelect = screen.getByDisplayValue('All Statuses (6 Invariant)');
      fireEvent.change(statusSelect, { target: { value: EvaluationStatus.NOT_ASSESSED } });

      // Verify unassessed finding is displayed
      expect(screen.getAllByText('CIS-CISCO-ROUTER-5.1.9').length).toBeGreaterThanOrEqual(1);
      expect(
        screen.getAllByText('BGP Route Flap Dampening Parameters (Capability Restricted)').length
      ).toBeGreaterThanOrEqual(1);

      // Verify notice reiterates unassessed is NEVER scored as PASS
      expect(
        screen.getByText(/Unassessed controls are NEVER scored as PASS/i)
      ).toBeInTheDocument();

      // Filter by ERROR status
      fireEvent.change(statusSelect, { target: { value: EvaluationStatus.ERROR } });
      expect(screen.getAllByText('CIS-CHECKPOINT-4.1.2').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Collector Probe Error/i)).toBeInTheDocument();

      // Filter by PASS status
      fireEvent.change(statusSelect, { target: { value: EvaluationStatus.PASS } });
      expect(screen.getAllByText('CIS-CISCO-ROUTER-1.1.2').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('CIS-UBUNTU-5.2.1').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Verified CIS Benchmark Compliance/i)).toBeInTheDocument();
    });

    it('displays policy exception banner while strictly preserving violation status (E14)', () => {
      renderWithRoute(`/orgs/${DEMO_ORG_ID}/findings`);

      // Find finding with approved exception: CIS-WIN11-2.3.17 (UAC elevation)
      const uacFinding = screen.getByText('CIS-WIN11-2.3.17');
      fireEvent.click(uacFinding);

      // Verify Exception Manifest banner is shown
      expect(
        screen.getByText('Approved Policy Exception Manifest (E14)')
      ).toBeInTheDocument();
      expect(screen.getByText(/ciso@acmefinancial.com/)).toBeInTheDocument();
      expect(screen.getByText(/Legacy automated deployment software compatibility/)).toBeInTheDocument();

      // Verify invariant scoring rule is displayed
      expect(
        screen.getByText(/Strict Invariant Scoring: Policy exceptions grant operational tolerance, but this control is strictly retained as a violation/i)
      ).toBeInTheDocument();
    });
  });
});
