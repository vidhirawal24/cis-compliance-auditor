import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiProvider } from '../api/context';
import { DemoApiClient } from '../api/client';
import { RemediationPlannerShell } from '../routes/shells/12_RemediationPlannerShell';
import { WhatIfSimulatorShell } from '../routes/shells/13_WhatIfSimulatorShell';
import { ApprovalsHardeningShell } from '../routes/shells/14_ApprovalsHardeningShell';
import { DEMO_ORG_ID, DEMO_REMEDIATION_PLAN } from '../fixtures/demoData';
import { updateSession } from '../features/phase6/model';
import { contractDraftSchema, SafetyVerdict } from '../features/phase6/SimulationPanels';
import { SimulationVerdict as V } from '../contracts/v1/enums';

function mount(path = 'planner', api = new DemoApiClient()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><ApiProvider client={api}><MemoryRouter initialEntries={[`/orgs/${DEMO_ORG_ID}/${path}`]}><Routes>
    <Route path="/orgs/:orgId/planner" element={<RemediationPlannerShell />} />
    <Route path="/orgs/:orgId/simulator" element={<WhatIfSimulatorShell />} />
    <Route path="/orgs/:orgId/approvals" element={<ApprovalsHardeningShell />} />
  </Routes></MemoryRouter></ApiProvider></QueryClientProvider>);
}
const preview = async () => { fireEvent.click(await screen.findByRole('button', { name: 'Load DEMO comparison' })); };
beforeEach(() => { updateSession(DEMO_ORG_ID, { selected: 'balanced', preview: null, dirty: false }); vi.restoreAllMocks(); });

describe('Phase 6 -- I06-I15 presentation and I14 approval invariant', () => {
  it('renders typed plan, objective meanings, actual React Flow nodes and dependency fallback (I06,I08,I10)', async () => {
    const view = mount();
    expect(screen.getByRole('status')).toHaveTextContent('Loading remediation');
    expect(await screen.findByRole('button', { name: 'Selected plan: Balanced sequence' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText(/Disruption: 0.6/)).toBeInTheDocument();
    expect(screen.getByText(/act-01-telnet to act-02-acl/)).toBeInTheDocument();
    expect(view.container.querySelector('.react-flow')).toBeInTheDocument();
    expect(view.container.querySelectorAll('.react-flow__node')).toHaveLength(DEMO_REMEDIATION_PLAN.actions.length);
    expect(view.container.querySelectorAll('.react-flow__edge')).toHaveLength(1);
    expect(view.container.querySelector('.react-flow__edge')).toHaveAttribute('data-id', 'act-01-telnet-act-02-acl');
    fireEvent.click(view.container.querySelector('.react-flow__node')!);
    expect(screen.getByRole('article', { name: 'Selected step details' })).toHaveTextContent('Crypto RSA 2048');
    fireEvent.click(screen.getByRole('button', { name: /1. Cisco:/ }));
    expect(screen.getByRole('article', { name: 'Selected step details' })).toHaveTextContent('Crypto RSA 2048');
  });
  it('changes explicit selected candidate and preserves it into simulation (I07)', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Select plan: Restrictive ACL hypothesis' }));
    expect(screen.getByRole('button', { name: 'Selected plan: Restrictive ACL hypothesis' })).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByRole('button', { name: /Proceed to What-If/ }));
    await preview();
    expect(screen.getByText('VIOLATES_CONTRACT', { exact: true })).toBeInTheDocument();
  });
  it('shows UNSAT and blocks simulation progression (I09)', async () => {
    mount(); fireEvent.click(await screen.findByRole('button', { name: 'Select plan: Zero-change constraint hypothesis' }));
    expect(screen.getByRole('alert')).toHaveTextContent('UNSAT');
    expect(screen.getByRole('button', { name: /Proceed to What-If/ })).toBeDisabled();
  });
  it('shows baseline/candidate diagrams, affected services and topology uncertainty (I11,I13)', async () => {
    mount('simulator'); await preview();
    expect(screen.getByRole('region', { name: 'Baseline service diagram' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Candidate service diagram' })).toBeInTheDocument();
    expect(screen.getByText(/91.5%/)).toBeInTheDocument();
    expect(screen.getByText(/23\/tcp.*hypothetical model impact/)).toBeInTheDocument();
    expect(screen.getByText(/Unknown dependencies remain/)).toBeInTheDocument();
  });
  it.each(Object.values(V))('renders distinct %s verdict and limitations (I14)', verdict => {
    render(<SafetyVerdict verdict={verdict} />);
    expect(screen.getByRole('status')).toHaveTextContent(verdict);
    expect(screen.getByRole('status').querySelector('p')?.textContent?.length).toBeGreaterThan(20);
  });
  it('blocks violating hypothesis through simulator and direct approval route (I14)', async () => {
    updateSession(DEMO_ORG_ID, { selected: 'restrictive' });
    const view = mount('simulator'); await preview();
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
    expect(screen.getByText(/SSH unreachable -- contract violation/)).toBeInTheDocument();
    view.unmount(); mount('approvals');
    expect(screen.getByRole('alert')).toHaveTextContent('Approval blocked');
    expect(screen.queryByRole('button', { name: /Trigger Stage/ })).not.toBeInTheDocument();
  });
  it('requires a preview even on direct approval navigation (I14)', () => {
    mount('approvals'); expect(screen.getByRole('alert')).toHaveTextContent('Approval blocked');
  });
  it('allows eligible DEMO review after preview, without approving or executing a plan', async () => {
    const api = new DemoApiClient();
    const execute = vi.spyOn(api, 'executeChange'); const approve = vi.spyOn(api, 'approvePlan');
    const load = vi.spyOn(api, 'getSimulation');
    mount('simulator', api); await preview();
    fireEvent.click(screen.getByRole('button', { name: /Proceed to Approval/ }));
    expect(await screen.findByText(/Approval ID:/)).toBeInTheDocument();
    expect(load).toHaveBeenCalledWith('sim-2026-4401');
    expect(execute).not.toHaveBeenCalled(); expect(approve).not.toHaveBeenCalled();
  });
  it('validates contracts with RHF and invalidates preview on edit (I12,I14)', async () => {
    mount('simulator'); await preview();
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeEnabled();
    fireEvent.change(screen.getByLabelText('source cidr'), { target: { value: '999.1.1.1/24' } });
    fireEvent.click(screen.getByRole('button', { name: 'Validate local draft' }));
    expect((await screen.findAllByText('Valid IPv4 CIDR required', { exact: true })).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Load DEMO comparison' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText('Mandatory in draft'));
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
  });
  it('rejects out-of-range/reversed ports and invalid CIDRs (I12)', () => {
    const valid = { name: 'SSH', description: 'Preserve access', source_cidr: '10.0.0.0/24', destination_cidr: '10.1.0.0/16', port_range: '22', protocol: 'TCP', mandatory: true };
    expect(contractDraftSchema.safeParse(valid).success).toBe(true);
    for (const port_range of ['0', '65536', '443-80', '22;whoami']) expect(contractDraftSchema.safeParse({ ...valid, port_range }).success).toBe(false);
    expect(contractDraftSchema.safeParse({ ...valid, source_cidr: '10.0.0.0/33' }).success).toBe(false);
  });
  it.each(['unsupported', 'incomplete'])('blocks %s and avoids invented impact (I13,I14)', async selected => {
    updateSession(DEMO_ORG_ID, { selected }); mount('simulator'); await preview();
    expect(screen.getByText(/Affected services and blast radius unknown/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Baseline service diagram' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
  });
  it('renders empty action and dependency states (I10)', async () => {
    const api = new DemoApiClient();
    vi.spyOn(api, 'getRemediationPlan').mockResolvedValue({ schema_version: '1.0.0', data: { ...DEMO_REMEDIATION_PLAN, actions: [] }, meta: { request_id: 'test' } });
    mount('planner', api);
    expect(await screen.findByText('No remediation steps supplied.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Proceed to What-If/ })).toBeDisabled();
  });
  it('renders request errors and retry (I06)', async () => {
    const api = new DemoApiClient(); vi.spyOn(api, 'getRemediationPlan').mockRejectedValue(new Error('Plan unavailable'));
    mount('planner', api); expect(await screen.findByRole('alert')).toHaveTextContent('Plan unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
  it('keeps zero topology coverage explicit (I13)', async () => {
    const api = new DemoApiClient();
    const original = await api.getSecurityGraph();
    vi.spyOn(api, 'getSecurityGraph').mockResolvedValue({ ...original, data: { nodes: [], edges: [], meta: { total_nodes: 0, total_edges: 0, coverage_completeness_pct: 0 } } });
    mount('simulator', api); await preview(); expect(screen.getByText(/Topology coverage: 0%/)).toBeInTheDocument();
  });
  it('blocks known violations even with a SAFE_IN_MODEL aggregate (I14)', async () => {
    const api = new DemoApiClient(); const original = await api.getSimulation('sim-2026-4401');
    vi.spyOn(api, 'getSimulation').mockResolvedValue({ ...original, data: { ...original.data, safety_contracts_violated: 1 } });
    mount('simulator', api); await preview(); expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
  });
  it('rejects mismatched simulation identity and cross-tenant data', async () => {
    const api = new DemoApiClient(); const original = await api.getSimulation('sim-2026-4401');
    vi.spyOn(api, 'getSimulation').mockResolvedValue({ ...original, data: { ...original.data, plan_id: 'other-plan' } });
    mount('simulator', api); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Simulation does not match'));
  });
});

describe('Phase 6 boundary and uncertainty regressions', () => {
  it('shows unsupported candidate data for a non-DEMO client without manufacturing alternatives', async () => {
    const demo = new DemoApiClient();
    const api = {
      getRemediationPlan: demo.getRemediationPlan.bind(demo),
      getSimulation: demo.getSimulation.bind(demo),
      getSafetyContracts: demo.getSafetyContracts.bind(demo),
      getSecurityGraph: demo.getSecurityGraph.bind(demo),
    } as DemoApiClient;
    mount('planner', api);
    expect(await screen.findByText(/No candidate data available/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Select plan:/ })).not.toBeInTheDocument();
  });
  it('shows supplied conflicts and prevents progression', async () => {
    const api = new DemoApiClient();
    vi.spyOn(api, 'getRemediationPlan').mockResolvedValue({ schema_version: '1.0.0', data: { ...DEMO_REMEDIATION_PLAN, conflict_detected: true, conflicts: ['Management reachability prerequisite missing'] }, meta: { request_id: 'test' } });
    mount('planner', api);
    expect(await screen.findByText(/Constraint violation: Management reachability/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Proceed to What-If/ })).toBeDisabled();
  });
  it('validates a complete local contract without persisting or evaluating it', async () => {
    mount('simulator'); await preview();
    for (const [label, value] of Object.entries({ name: 'Admin SSH', description: 'Preserve admin access', 'source cidr': '10.0.0.0/24', 'destination cidr': '10.1.0.0/16', 'port range': '22' })) fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: 'Validate local draft' }));
    expect(await screen.findByText(/Draft valid. Not persisted or simulated/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
  });
  it('simulation preview never executes shell commands or calls execution APIs', async () => {
    const api = new DemoApiClient();
    const execute = vi.spyOn(api, 'executeChange');
    const approve = vi.spyOn(api, 'approvePlan');
    const read = vi.spyOn(api, 'getSimulation');
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    mount('simulator', api); await preview();
    expect(read).toHaveBeenCalledOnce();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /execute|run command|shell/i })).not.toBeInTheDocument();
  });
  it('blocks stale previews when the supplied plan hash changes', async () => {
    const view = mount('simulator'); await preview();
    expect(screen.getByRole('button', { name: /Proceed to Approval/ })).toBeEnabled();
    view.unmount();
    const api = new DemoApiClient();
    vi.spyOn(api, 'getRemediationPlan').mockResolvedValue({ schema_version: '1.0.0', data: { ...DEMO_REMEDIATION_PLAN, plan_hash: 'changed-plan-hash' }, meta: { request_id: 'test' } });
    mount('approvals', api);
    expect(await screen.findByRole('alert')).toHaveTextContent('Approval blocked');
  });
  it('rejects cross-tenant plans', async () => {
    const api = new DemoApiClient();
    vi.spyOn(api, 'getRemediationPlan').mockResolvedValue({ schema_version: '1.0.0', data: { ...DEMO_REMEDIATION_PLAN, org_id: 'another-org' }, meta: { request_id: 'test' } });
    mount('planner', api);
    expect(await screen.findByRole('alert')).toHaveTextContent('another organization');
  });
});

describe('Phase 6 staged rollout presentation (I15)', () => {
  it('renders historical batches and canary events without starting a rollout', async () => {
    mount('simulator');
    expect(await screen.findByText(/Fixture plan: plan-2026-8801; stage 2 of 2/)).toBeInTheDocument();
    expect(screen.getByText(/STAGE_1_CANARY: SUCCESS/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /execute|halt|start rollout/i })).not.toBeInTheDocument();
  });
  it('shows a reported canary halt distinctly', async () => {
    const api = new DemoApiClient(); const original = await api.getChange('chg-2026-7701');
    vi.spyOn(api, 'getChange').mockResolvedValue({ ...original, data: { ...original.data, canary_halt_triggered: true } });
    mount('simulator', api);
    expect(await screen.findByText(/HALTED: canary halt trigger/)).toBeInTheDocument();
  });
});
