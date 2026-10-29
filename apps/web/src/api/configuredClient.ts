import { z } from 'zod';
import { DemoApiClient, type ApiClientInterface } from './client';
import { ReportFormat } from '../contracts/v1/enums';
import { runtimeConfig, type RuntimeConfig } from './config';
import { supabase } from '../auth/supabase';

const reportSchema = z.object({
  report_id: z.string().min(1), org_id: z.string().min(1), title: z.string(),
  format: z.nativeEnum(ReportFormat), file_size_bytes: z.number().finite().nonnegative(),
  download_url: z.string(), signed_url_expires_at: z.string(), created_at: z.string(),
});
const reportsEnvelope = z.object({ schema_version: z.literal('1.0.0'), data: z.array(reportSchema), meta: z.object({ request_id: z.string() }) });
export class UnavailableOperation extends Error {
  readonly code = 'UNSUPPORTED'; readonly retryable = false;
  constructor(operation: string) { super(`${operation} is unavailable: no agreed integration binding is enabled.`); }
}

// Only GET /reports has both an agreed path and a fully checked response here.
// All other bindings need cross-team agreement; no guessed endpoints or device writes.
export function createConfiguredClient(config: RuntimeConfig, token: () => Promise<string | null> = async () => {
  if (!supabase) return null;
  return (await supabase.auth.getSession()).data.session?.access_token ?? null;
}, transport: typeof fetch = fetch): ApiClientInterface {
  if (config.mode === 'demo') return new DemoApiClient();
  const getReports: ApiClientInterface['getReports'] = async () => {
    if (config.mode !== 'http' || !config.approvedReads.includes('getReports')) throw new UnavailableOperation('getReports');
    const base = new URL(config.apiBaseUrl.replace(/\/$/, '') + '/', window.location.origin);
    if (base.origin !== window.location.origin || base.username || base.password || base.search || base.hash || !base.pathname.startsWith('/api/')) throw new UnavailableOperation('Invalid API base (same-origin /api/ required)');
    const accessToken = await token();
    if (!accessToken) throw Object.assign(new Error('Authentication required'), { status: 401, retryable: false });
    const response = await transport(new URL('reports', base).href, { method: 'GET', headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' }, credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw Object.assign(new Error('API request failed'), { status: response.status, retryable: response.status >= 500 });
    const parsed = reportsEnvelope.safeParse(await response.json());
    if (!parsed.success) throw Object.assign(new Error('Unsupported response schema'), { code: 'UNSUPPORTED', retryable: false });
    return parsed.data;
  };
  return new Proxy({ getReports }, { get(target, name) {
    if (name === 'getReports') return target.getReports;
    return async () => { throw new UnavailableOperation(String(name)); };
  } }) as ApiClientInterface;
}
let configured: ApiClientInterface | undefined;
export function configuredClient(): ApiClientInterface {
  return configured ??= createConfiguredClient(runtimeConfig());
}
