import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { createConfiguredClient } from '../api/configuredClient';
import { runtimeConfig } from '../api/config';
import { DemoApiClient } from '../api/client';
import { AuthProvider, useAuth } from '../auth/context';
import { DEMO_REPORTS } from '../fixtures/demoData';
import { readFileSync } from 'node:fs';
import path from 'node:path';

afterEach(() => { delete window.__BASELINEGUARD_CONFIG__; vi.restoreAllMocks(); });
const config = { mode: 'http' as const, apiBaseUrl: '/api/v1', approvedReads: ['getReports'] };
describe('Phase 9 - configurable integration and no production fallback', () => {
  it('preserves all 88 immutable IDs with an explicit evidence status', () => {
    const matrix = readFileSync(path.resolve('../../docs/frontend/feature-coverage.md'), 'utf8');
    const rows = [...matrix.matchAll(/^\| ([MEI]\d{2}) \|.*?\| (DONE|PARTIAL|BLOCKED|UNTESTED) \|/gm)];
    const expected = [['M', 38], ['E', 30], ['I', 20]].flatMap(([prefix, count]) => Array.from({ length: Number(count) }, (_, i) => `${prefix}${String(i + 1).padStart(2, '0')}`));
    expect(rows.map(row => row[1]).sort()).toEqual(expected.sort());
    expect(rows.filter(row => row[2] === 'DONE')).toHaveLength(0);
  });
  it('fails closed for malformed configuration', () => {
    window.__BASELINEGUARD_CONFIG__ = { mode: 'typo' };
    expect(runtimeConfig().mode).toBe('disabled');
  });
  it('enables fixtures only through explicit DEMO selection', async () => {
    expect(createConfiguredClient({ ...config, mode: 'demo' })).toBeInstanceOf(DemoApiClient);
    const disabled = createConfiguredClient({ ...config, mode: 'disabled' });
    await expect(disabled.getReports()).rejects.toMatchObject({ code: 'UNSUPPORTED', retryable: false });
  });
  it('rejects undeclared operations and never issues device mutations', async () => {
    const fetcher = vi.fn(); const client = createConfiguredClient(config, async () => 'test-token', fetcher);
    await expect(client.executeChange('any-cli')).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    await expect(client.approvePlan('plan', { plan_hash: 'hash', justification: 'untrusted' })).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('requires an approved read binding and a current session', async () => {
    await expect(createConfiguredClient({ ...config, approvedReads: [] }).getReports()).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    await expect(createConfiguredClient(config, async () => null).getReports()).rejects.toMatchObject({ status: 401 });
  });
  it.each([401, 403, 500])('preserves HTTP %s and returns no DEMO reports', async status => {
    const fetcher = vi.fn().mockResolvedValue(new Response('', { status }));
    const client = createConfiguredClient(config, async () => 'test-token', fetcher);
    await expect(client.getReports()).rejects.toMatchObject({ status });
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('checks the versioned response before exposing reports', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: DEMO_REPORTS })));
    await expect(createConfiguredClient(config, async () => 'test-token', fetcher).getReports()).rejects.toMatchObject({ code: 'UNSUPPORTED' });
  });
  it('uses only the agreed GET reports binding and validates canonical data', async () => {
    const payload = { schema_version: '1.0.0', data: DEMO_REPORTS, meta: { request_id: 'synthetic-test' } };
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    const value = await createConfiguredClient(config, async () => 'test-token', fetcher).getReports();
    expect(value).toEqual(payload);
    expect(fetcher).toHaveBeenCalledWith(`${window.location.origin}/api/v1/reports`, expect.objectContaining({ method: 'GET', credentials: 'omit', redirect: 'error' }));
  });
  it('never sends a bearer token to an unapproved origin', async () => {
    const fetcher = vi.fn();
    await expect(createConfiguredClient({ ...config, apiBaseUrl: 'https://untrusted.example.test/api/v1' }, async () => 'test-token', fetcher).getReports()).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('has no default real-session persona, memberships or role escalation', async () => {
    window.__BASELINEGUARD_CONFIG__ = { mode: 'disabled' };
    const hook = renderHook(() => useAuth(), { wrapper: AuthProvider });
    expect(hook.result.current.user).toBeNull(); expect(hook.result.current.userOrgs).toEqual([]);
    act(() => { hook.result.current.loginDemo('fake@example.test', 'OWNER' as never); });
    expect(hook.result.current.user).toBeNull();
    expect((await hook.result.current.verifyMfa('123456')).success).toBe(false);
    expect((await hook.result.current.resetPassword('nobody@example.test')).success).toBe(false);
  });
});
