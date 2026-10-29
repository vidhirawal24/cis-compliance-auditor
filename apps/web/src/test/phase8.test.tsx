import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, act } from '@testing-library/react';
import { DemoApiClient, type ApiClientInterface } from '../api/client';
import { apiCacheKey } from '../api/context';
import { fixtureStore } from '../api/store';
import { DEMO_ORG_ID, DEMO_REPORTS } from '../fixtures/demoData';
import { ReportFormat, UserRole } from '../contracts/v1/enums';
import { ReportAccess, reportAccess } from '../features/phase8/ReportAccess';
import { ExecutiveSummary } from '../features/phase8/ExecutiveSummary';
import { ReportsHistoryShell } from '../routes/shells/16_ReportsHistoryShell';
import { NotificationsTicketsShell } from '../routes/shells/17_NotificationsTicketsShell';
import { AdminSecurityShell } from '../routes/shells/18_AdminSecurityShell';
import { ScreenDataBoundary, LEGACY_FAMILIES, screenFamily } from '../components/common/ScreenDataBoundary';
import { renderWorkspace } from './renderWorkspace';
import { SnapshotHistory } from '../features/phase8/SnapshotHistory';
import { MobileNav } from '../components/layout/MobileNav';

// A mock transport with the existing API shape, not a production adapter or fallback.
function transport(): ApiClientInterface {
  const demo = new DemoApiClient();
  return Object.fromEntries(Object.getOwnPropertyNames(DemoApiClient.prototype).filter(name => name !== 'constructor').map(name => [name, (demo[name as keyof DemoApiClient] as (...args: unknown[]) => unknown).bind(demo)])) as unknown as ApiClientInterface;
}
const report = (format = ReportFormat.PDF) => ({ ...DEMO_REPORTS[0], format, download_url: 'https://storage.example.test/private/report?signature=opaque', signed_url_expires_at: '2099-01-01T00:00:00Z' });
beforeEach(() => { fixtureStore.reset(); vi.restoreAllMocks(); });

describe('Phase 8 - M38 signed artifacts and privacy', () => {
  it.each(Object.values(ReportFormat))('retrieves the backend-supplied %s URL with no credentials and no fabricated success', async format => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('sanitized report', { status: 200 }));
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn(() => 'blob:test-artifact') });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    const save = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    renderWorkspace(<ReportAccess report={report(format)} />, { api: transport() });
    fireEvent.click(screen.getByRole('button', { name: `Retrieve ${format}` }));
    expect(await screen.findByText(/Save completion is not confirmed/)).toBeInTheDocument();
    expect(fetchSpy).toHaveBeenCalledWith(report(format).download_url, expect.objectContaining({ credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', redirect: 'error' }));
    expect(save).toHaveBeenCalledOnce();
    expect(document.body.textContent).not.toContain('signature=opaque');
    expect(document.querySelector('a[href*="signature"]')).not.toBeInTheDocument();
  });
  it('blocks expired, malformed, credential-bearing and unknown-expiry links', () => {
    expect(reportAccess({ ...report(), signed_url_expires_at: '2000-01-01T00:00:00Z' })).toBe('EXPIRED');
    expect(reportAccess({ ...report(), signed_url_expires_at: '' })).toBe('UNKNOWN_EXPIRY');
    expect(reportAccess({ ...report(), download_url: 'javascript:alert(1)' })).toBe('UNSUPPORTED_URL');
    expect(reportAccess({ ...report(), download_url: 'https://user:secret@storage.example.test/a' })).toBe('UNSUPPORTED_URL');
    expect(reportAccess({ ...report(), download_url: '' })).toBe('UNAVAILABLE');
  });
  it('rechecks expiry at click time even if the display timer has not fired', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch'); const time = vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2098-12-31T23:59:59Z'));
    renderWorkspace(<ReportAccess report={report()} />, { api: transport() });
    time.mockReturnValue(Date.parse('2099-01-01T00:00:01Z'));
    fireEvent.click(screen.getByRole('button', { name: 'Retrieve PDF' }));
    expect(fetchSpy).not.toHaveBeenCalled();
  });
  it('updates expired access while the page remains open', () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2098-12-31T23:59:59Z'));
    const view = renderWorkspace(<ReportAccess report={report()} />, { api: transport() });
    act(() => { vi.advanceTimersByTime(2000); });
    expect(screen.getByRole('button', { name: 'Retrieve PDF' })).toBeDisabled();
    view.unmount(); vi.useRealTimers();
  });
  it.each([403, 500])('reports failed retrieval HTTP %s without exposing the signed URL', async status => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status }));
    renderWorkspace(<ReportAccess report={report()} />, { api: transport() });
    fireEvent.click(screen.getByRole('button', { name: 'Retrieve PDF' }));
    expect(await screen.findByText(status === 403 ? /403 Forbidden: artifact access denied/ : /Retrieval failed or access expired/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('opaque');
  });
  it('never fetches a DEMO artifact URL', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch'); renderWorkspace(<ReportAccess report={report()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Retrieve PDF' })); expect(fetchSpy).not.toHaveBeenCalled();
  });
  it('shows all four format slots and missing generation/renewal support', async () => {
    renderWorkspace(<ReportsHistoryShell />);
    for (const format of Object.values(ReportFormat)) expect(await screen.findByRole('heading', { name: `${format} exports` })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Generate new report/ })).toBeDisabled();
    expect(screen.getByText(/No HTML artifact supplied/)).toBeInTheDocument();
  });
  it('does not display cross-tenant export metadata', async () => {
    const api = transport(); vi.spyOn(api, 'getReports').mockResolvedValue({ schema_version: '1.0.0', data: [{ ...report(), org_id: 'other-tenant', title: 'Private other-tenant report' }], meta: { request_id: 'test' } });
    renderWorkspace(<ReportsHistoryShell />, { api });
    expect(await screen.findByText(/Request failed/)).toBeInTheDocument();
    expect(screen.queryByText('Private other-tenant report')).not.toBeInTheDocument();
  });
});

describe('Phase 8 - executive summary, drift, integrations, administration', () => {
  it('uses supplied compliance and coverage separately with an accessible exact-value trend table', async () => {
    const api = new DemoApiClient(); const scans = await api.getScans(DEMO_ORG_ID);
    vi.spyOn(api, 'getScans').mockResolvedValue({ ...scans, data: scans.data.filter(s => s.status === 'COMPLETED').map(s => ({ ...s, assessed_compliance_pct: 71.25, assessment_coverage_pct: 42.5 })) });
    renderWorkspace(<ExecutiveSummary />, { api });
    expect(await screen.findByText(/Assessed compliance: 71.25%; assessment coverage: 42.5%/)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Compliance and coverage trends/ })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Exact compliance and coverage history' })).toBeInTheDocument();
  });
  it('shows missing summary and trend data without zero compliance claims', async () => {
    const api = new DemoApiClient(); const scans = await api.getScans(DEMO_ORG_ID); const trends = await api.getComplianceTrends();
    vi.spyOn(api, 'getScans').mockResolvedValue({ ...scans, data: [] }); vi.spyOn(api, 'getComplianceTrends').mockResolvedValue({ ...trends, data: [] });
    renderWorkspace(<ExecutiveSummary />, { api });
    expect(await screen.findByText(/Assessed compliance: Not available; assessment coverage: Not available/)).toBeInTheDocument();
    expect(screen.getByText('No compliance trend history supplied.')).toBeInTheDocument();
  });
  it('shows only supplied drift events and handles filters without implying continuous monitoring', async () => {
    renderWorkspace(<ReportsHistoryShell />, { path: 'reports/drift' });
    expect(await screen.findByText('Observed snapshot history')).toBeInTheDocument();
    expect(screen.getByText(/Previous snapshot: snap-2026-1020-01/)).toBeInTheDocument();
    expect(screen.getByText(/does not imply continuous monitoring/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search reports or drift assets'), { target: { value: 'nonexistent' } });
    expect(screen.getByText('No drift records match this filter.')).toBeInTheDocument();
  });
  it('shows DEMO delivery failures separately from missing integration support', () => {
    renderWorkspace(<NotificationsTicketsShell />); fireEvent.click(screen.getByRole('button', { name: 'WEBHOOKS' }));
    expect(screen.getByText('FAILED (DEMO fixture)')).toBeInTheDocument();
    expect(screen.getByText(/DEMO endpoint timeout/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry delivery - unsupported' })).toBeDisabled();
  });
  it('does not invent delivery status or ticket identity for a production transport', () => {
    renderWorkspace(<NotificationsTicketsShell />, { api: transport() });
    expect(screen.getByText(/No delivery or ticket data available/)).toBeInTheDocument();
    expect(screen.queryByText(/DELIVERED/)).not.toBeInTheDocument();
  });
  it('shows context RBAC, unsupported settings and a responsive minimized audit table', async () => {
    const view = renderWorkspace(<AdminSecurityShell />);
    expect(screen.getByText(/current role: OWNER/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save retention/ })).toBeDisabled();
    expect(await screen.findByRole('table', { name: 'Application audit events' })).toBeInTheDocument();
    expect(view.container.querySelector('.overflow-auto')).toBeInTheDocument();
    expect(screen.queryByText('Actor Email')).not.toBeInTheDocument();
    expect(screen.getByText(/No settings have been saved/)).toBeInTheDocument();
  });
  it('handles server 403 without retrying or displaying cached audit events', async () => {
    const api = new DemoApiClient(); vi.spyOn(api, 'getAuditEvents').mockRejectedValue({ response: { status: 403 } });
    renderWorkspace(<AdminSecurityShell />, { api });
    expect(await screen.findByRole('alert')).toHaveTextContent('403 Forbidden');
    expect(screen.queryByRole('button', { name: 'Retry request' })).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
  it('does not query privileged audit data as a viewer', async () => {
    const api = new DemoApiClient(); const read = vi.spyOn(api, 'getAuditEvents'); renderWorkspace(<AdminSecurityShell />, { api, role: UserRole.VIEWER });
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('403 Forbidden'));
    expect(read).not.toHaveBeenCalled();
  });
  it('isolates caches between adapters', () => {
    const demo = new DemoApiClient(); const mock = transport();
    expect(apiCacheKey(demo)).not.toBe(apiCacheKey(mock)); expect(apiCacheKey(demo)).toBe(apiCacheKey(demo));
  });
});

describe('Phase 8 - legacy route-family data boundaries', () => {
  const methods = ['getOrganizations', 'getScans', 'getAssets', 'getAsset', 'getPolicyPacks', 'getPolicyExceptions', 'getManualReviews', 'getFindings', 'getSecurityGraph', 'getRiskScenarios'] as const;
  it.each(LEGACY_FAMILIES)('family %s shows loading and then actual DEMO content', async family => {
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><h1>Supplied DEMO screen</h1></ScreenDataBoundary>, { path: 'assets/a01-win11-corp-01', pattern: '/orgs/:orgId/assets/:assetId' });
    expect(screen.getByRole('status')).toHaveTextContent('Loading records');
    expect(await screen.findByText('Supplied DEMO screen')).toBeInTheDocument();
  });
  it.each(LEGACY_FAMILIES)('family %s displays network failures without fixture fallback', async family => {
    const api = new DemoApiClient(); for (const method of methods) vi.spyOn(api, method).mockRejectedValue(new Error('Network error containing secret-url'));
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><p>Forbidden stale content</p></ScreenDataBoundary>, { api });
    expect(await screen.findByRole('alert')).toHaveTextContent('Request failed');
    expect(screen.queryByText('Forbidden stale content')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('secret-url');
  });
  it.each(LEGACY_FAMILIES)('family %s displays 403 without stale content', async family => {
    const api = new DemoApiClient(); for (const method of methods) vi.spyOn(api, method).mockRejectedValue({ status: 403 });
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><p>Forbidden stale content</p></ScreenDataBoundary>, { api });
    expect(await screen.findByRole('alert')).toHaveTextContent('403 Forbidden');
    expect(screen.queryByText('Forbidden stale content')).not.toBeInTheDocument();
  });
  it.each(LEGACY_FAMILIES)('family %s blocks production rendering of fixture-only screens', family => {
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><p>Forbidden fixture fallback</p></ScreenDataBoundary>, { api: transport() });
    expect(screen.getByRole('status')).toHaveTextContent('UNSUPPORTED');
    expect(screen.queryByText('Forbidden fixture fallback')).not.toBeInTheDocument();
  });
  it.each(LEGACY_FAMILIES.filter(family => family !== '05'))('family %s handles empty supplied collections', async family => {
    const api = new DemoApiClient();
    for (const method of methods) vi.spyOn(api, method).mockResolvedValue({ schema_version: '1.0.0', data: method === 'getSecurityGraph' ? { nodes: [], edges: [], meta: { total_nodes: 0, total_edges: 0, coverage_completeness_pct: 0 } } : [], meta: { request_id: 'test' } } as never);
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><p>Unsafe empty-data renderer</p></ScreenDataBoundary>, { api });
    expect(await screen.findByText(`No records for screen family ${family}`)).toBeInTheDocument();
    expect(screen.queryByText('Unsafe empty-data renderer')).not.toBeInTheDocument();
  });
  it('maps all 19 guide families to their actual route inventory', () => {
    const paths = ['/auth/login', '/orgs', ...['overview', 'assets', 'assets/id', 'scans', 'policies', 'exceptions', 'findings', 'graph', 'risk-scenarios', 'planner', 'simulator', 'approvals', 'verifications', 'reports', 'notifications', 'admin/users', 'system-states'].map(path => `/orgs/${DEMO_ORG_ID}/${path}`)];
    expect(paths.map(screenFamily)).toEqual(Array.from({ length: 19 }, (_, index) => String(index + 1).padStart(2, '0')));
  });
});

describe('Phase 8 - snapshot and keyboard regressions', () => {
  it('shows only this asset snapshot references without asserting encryption or verified hashes', async () => {
    const api = new DemoApiClient(); const events = await api.getDriftEvents();
    const event = events.data[0];
    renderWorkspace(<SnapshotHistory orgId={DEMO_ORG_ID} assetId={event.asset_id} />, { api });
    expect(await screen.findByText(new RegExp(`${event.previous_snapshot_id} to ${event.current_snapshot_id}`))).toBeInTheDocument();
    expect(screen.getByText(/restore readiness are UNKNOWN/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Retrieve encrypted snapshot/ })).toBeDisabled();
  });
  it('does not invent snapshot records for an asset absent from the supplied history', async () => {
    renderWorkspace(<SnapshotHistory orgId={DEMO_ORG_ID} assetId="unobserved-asset" />);
    expect(await screen.findByText('No snapshot references supplied for this asset.')).toBeInTheDocument();
  });
  it('supports Escape and keyboard focus containment in mobile navigation', () => {
    const close = vi.fn(); renderWorkspace(<MobileNav isOpen onClose={close} />);
    const dialog = screen.getByRole('dialog', { name: 'Mobile Navigation' });
    const controls = dialog.querySelectorAll<HTMLElement>('button, a[href], select, [tabindex="0"]');
    expect(document.activeElement).toBe(controls[0]);
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(controls[controls.length - 1]);
    fireEvent.keyDown(document, { key: 'Escape' }); expect(close).toHaveBeenCalledOnce();
  });
  it.each(['12', '13', '14', '15'])('never requests synthetic default IDs from production for family %s', family => {
    const api = transport(); const read = vi.spyOn(api, 'getRemediationPlan');
    renderWorkspace(<ScreenDataBoundary familyOverride={family}><p>Unbound production workflow</p></ScreenDataBoundary>, { api });
    expect(screen.getByRole('status')).toHaveTextContent('DEMO identifiers will not be requested');
    expect(read).not.toHaveBeenCalled(); expect(screen.queryByText('Unbound production workflow')).not.toBeInTheDocument();
  });
});
