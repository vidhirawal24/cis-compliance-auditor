import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, renderHook, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { AuthProvider, useAuth } from '../auth/context';
import { SessionCacheBoundary } from '../auth/SessionCacheBoundary';
import { approvalState, verificationOutcome } from '../features/phase7/review';
import { ExecutionState } from '../contracts/v1/enums';
import { legacyRecordCount } from '../components/common/ScreenDataBoundary';
import { DemoApiClient } from '../api/client';
import { createConfiguredClient } from '../api/configuredClient';
import { DEMO_APPROVAL_RECORD, DEMO_REMEDIATION_PLAN, DEMO_HARDENING_CHANGE, DEMO_DUAL_VERIFICATION, DEMO_REPORTS, DEMO_ORG_ID } from '../fixtures/demoData';
import { ReportsHistoryShell } from '../routes/shells/16_ReportsHistoryShell';
import { renderWorkspace } from './renderWorkspace';

const sdk = vi.hoisted(() => ({ signInWithPassword: vi.fn(), signOut: vi.fn(), resetPasswordForEmail: vi.fn(), onAuthStateChange: vi.fn() }));
vi.mock('../auth/supabase', () => ({ supabase: { auth: sdk } }));
beforeEach(() => {
  window.__BASELINEGUARD_CONFIG__ = { mode: 'disabled' };
  sdk.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe() {} } } });
  sdk.signInWithPassword.mockResolvedValue({ data: { user: { id: 'real-user-test', email: 'test@example.test' } }, error: null });
  sdk.signOut.mockResolvedValue({ error: null });
});
afterEach(() => { delete window.__BASELINEGUARD_CONFIG__; vi.restoreAllMocks(); vi.clearAllMocks(); });

describe('Phase 10 - final frontend safety regression', () => {
  it('renders approved report reads independently of unsupported drift and summary operations', async () => {
    window.__BASELINEGUARD_CONFIG__ = { mode: 'demo' };
    const transport = vi.fn().mockResolvedValue(new Response(JSON.stringify({ schema_version: '1.0.0', data: DEMO_REPORTS, meta: { request_id: 'test' } })));
    const api = createConfiguredClient({ mode: 'http', apiBaseUrl: '/api/v1', approvedReads: ['getReports'] }, async () => 'synthetic-token', transport);
    renderWorkspace(<ReportsHistoryShell />, { api });
    expect(await screen.findByRole('heading', { name: DEMO_REPORTS[0].title })).toBeInTheDocument();
    expect(await screen.findByText(/UNSUPPORTED: operation or response contract/)).toBeInTheDocument();
    expect(transport).toHaveBeenCalledOnce();
  });
  it('clears local authenticated data even when remote sign-out fails, without claiming remote success', async () => {
    const hook = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => { await hook.result.current.loginSupabase('test@example.test', 'password-for-test'); });
    expect(hook.result.current.isAuthenticated).toBe(true);
    sdk.signOut.mockRejectedValue(new Error('raw-secret-diagnostic'));
    await act(async () => { await expect(hook.result.current.logout()).rejects.toThrow('remote sign-out was not confirmed'); });
    expect(hook.result.current.user).toBeNull(); expect(hook.result.current.currentOrg).toBeNull();
  });
  it('redacts authentication transport diagnostics', async () => {
    sdk.signInWithPassword.mockRejectedValue(new Error('token=must-not-render'));
    const hook = renderHook(() => useAuth(), { wrapper: AuthProvider });
    let message = '';
    await act(async () => { message = (await hook.result.current.loginSupabase('test@example.test', 'test')).error ?? ''; });
    expect(message).toContain('No fallback session'); expect(message).not.toContain('token=');
    expect(hook.result.current.user).toBeNull();
  });
  it('does not fabricate password-reset delivery on a network error', async () => {
    sdk.resetPasswordForEmail.mockRejectedValue(new Error('Network unavailable'));
    const hook = renderHook(() => useAuth(), { wrapper: AuthProvider });
    expect(await hook.result.current.resetPassword('test@example.test')).toEqual({ success: false, message: 'Password reset request failed. No delivery is claimed.' });
  });
  it('never assigns real memberships or accepts real MFA locally after login', async () => {
    const hook = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => { await hook.result.current.loginSupabase('test@example.test', 'test'); });
    expect(hook.result.current.userOrgs).toEqual([]); expect(hook.result.current.role).toBe('VIEWER');
    expect(hook.result.current.user?.mfaVerified).toBe(false);
    expect((await hook.result.current.verifyMfa('123456')).success).toBe(false);
  });
  it('does not treat matching empty hashes as a bound approval', () => {
    expect(approvalState({ ...DEMO_APPROVAL_RECORD, plan_hash: '' }, { ...DEMO_REMEDIATION_PLAN, plan_hash: '' })).toBe('INSUFFICIENT_EVIDENCE');
  });
  it.each([ExecutionState.EXECUTING, ExecutionState.VERIFYING, ExecutionState.ROLLED_BACK, ExecutionState.NEEDS_MANUAL_RECOVERY])('never reports verification SUCCESS in backend state %s', state => {
    expect(verificationOutcome({ ...DEMO_HARDENING_CHANGE, state }, DEMO_DUAL_VERIFICATION)).not.toBe('SUCCESS');
  });
  it('rejects an asset response that does not match the requested identity', async () => {
    const api = new DemoApiClient(); const asset = await api.getAsset('a01-win11-corp-01');
    vi.spyOn(api, 'getAsset').mockResolvedValue(asset);
    await expect(legacyRecordCount('05', api, DEMO_ORG_ID, 'different-asset')).rejects.toThrow('Asset identity mismatch');
  });
  it('rechecks session availability on each HTTP read and never returns previous data after expiry', async () => {
    const token = vi.fn().mockResolvedValueOnce('synthetic-test-token').mockResolvedValue(null);
    const transport = vi.fn().mockResolvedValue(new Response(JSON.stringify({ schema_version: '1.0.0', data: DEMO_REPORTS, meta: { request_id: 'test' } })));
    const api = createConfiguredClient({ mode: 'http', apiBaseUrl: '/api/v1', approvedReads: ['getReports'] }, token, transport);
    expect((await api.getReports()).data).toHaveLength(DEMO_REPORTS.length);
    await expect(api.getReports()).rejects.toMatchObject({ status: 401 });
    expect(transport).toHaveBeenCalledOnce();
  });
  it('clears query cache before rendering a changed actor or role scope', () => {
    window.__BASELINEGUARD_CONFIG__ = { mode: 'demo' };
    const client = new QueryClient(); client.setQueryData(['previous-private-result'], 'private-record');
    function ChangeActor() { const { loginDemo } = useAuth(); return <button onClick={() => loginDemo('other@example.test', 'VIEWER' as never)}>Change test actor</button>; }
    render(<QueryClientProvider client={client}><AuthProvider><ChangeActor /><SessionCacheBoundary><p>Scoped view</p></SessionCacheBoundary></AuthProvider></QueryClientProvider>);
    fireEvent.click(screen.getByRole('button', { name: 'Change test actor' }));
    expect(client.getQueryData(['previous-private-result'])).toBeUndefined();
  });
  it('ships only public Supabase placeholders in the environment example', () => {
    const example = readFileSync(path.resolve('.env.example'), 'utf8');
    expect([...example.matchAll(/^(VITE_\w+)=/gm)].map(match => match[1]).sort()).toEqual(['VITE_SUPABASE_ANON_KEY', 'VITE_SUPABASE_URL']);
    expect(example).not.toMatch(/eyJ[a-zA-Z0-9_-]{15,}/);
  });
});
