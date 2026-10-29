import type { ReactNode } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { DemoApiClient, type ApiClientInterface } from '../../api/client';
import { useApi, apiCacheKey } from '../../api/context';
import { useAuth } from '../../auth/context';
import { ApiState } from './ApiState';
import { EmptyState } from './EmptyState';
import { Database } from 'lucide-react';

// Guide pages 3-4: these legacy screens still read the local fixture store.
// They must never appear to consume production records from another adapter.
export const LEGACY_FAMILIES = ['02', '03', '04', '05', '06', '07', '08', '09', '10', '11'] as const;
export function screenFamily(pathname: string): string {
  const parts = pathname.split('/').filter(Boolean);
  if (parts[0] === 'auth') return '01';
  if (parts.length === 1 && parts[0] === 'orgs') return '02';
  const route = parts[2];
  if (route === 'assets') return parts[3] && !['discover', 'import'].includes(parts[3]) ? '05' : '04';
  return ({ overview: '03', scans: '06', policies: '07', exceptions: '08', 'manual-reviews': '08', findings: '09', graph: '10', scenarios: '11', 'risk-scenarios': '11', planner: '12', simulator: '13', approvals: '14', changes: '14', verifications: '15', 'proof-packages': '15', reports: '16', notifications: '17', integrations: '17', admin: '18', 'system-states': '19' } as Record<string, string>)[route] ?? '19';
}

export async function legacyRecordCount(family: string, api: ApiClientInterface, org: string, assetId?: string): Promise<number> {
  const scopedCount = (records: { org_id?: string }[]) => {
    if (records.some(record => record.org_id && record.org_id !== org)) throw new Error('Tenant mismatch');
    return records.length;
  };
  switch (family) {
    case '02': return (await api.getOrganizations()).data.length;
    case '03': case '06': return scopedCount((await api.getScans(org)).data);
    case '04': return scopedCount((await api.getAssets(org)).data);
    case '05': {
      const asset = (await api.getAsset(assetId ?? '')).data;
      if (asset.asset_id !== assetId) throw new Error('Asset identity mismatch');
      return scopedCount([asset]);
    }
    case '07': return (await api.getPolicyPacks()).data.length;
    case '08': {
      const [exceptions, reviews] = await Promise.all([api.getPolicyExceptions(org), api.getManualReviews(org)]);
      return scopedCount(exceptions.data) + reviews.data.length;
    }
    case '09': return scopedCount((await api.getFindings()).data);
    case '10': return (await api.getSecurityGraph()).data.nodes.length;
    case '11': return scopedCount((await api.getRiskScenarios()).data);
    default: return 0;
  }
}

export function ScreenDataBoundary({ children, familyOverride }: { children: ReactNode; familyOverride?: string }) {
  const { pathname } = useLocation();
  const { orgId = '', assetId } = useParams();
  const { isDemoSession } = useAuth();
  const api = useApi();
  const family = familyOverride ?? screenFamily(pathname);
  const legacy = (LEGACY_FAMILIES as readonly string[]).includes(family);
  const demo = api instanceof DemoApiClient && isDemoSession;
  const query = useQuery({ queryKey: ['screen-preflight', orgId, family, pathname, apiCacheKey(api)], enabled: legacy && demo,
    queryFn: () => legacyRecordCount(family, api, orgId, assetId), retry: false, staleTime: 0 });
  if (!isDemoSession && api instanceof DemoApiClient) return <p role="alert">UNSUPPORTED: production data adapter is unavailable. Synthetic fixture fallback is disabled.</p>;
  if (!demo && ['12', '13', '14', '15'].includes(family)) return <p role="status">UNSUPPORTED: production plan, simulation, submission revision and verification bindings are incomplete. DEMO identifiers will not be requested from a production adapter.</p>;
  if (!legacy) return <>{children}</>;
  if (!demo) return <p role="status">UNSUPPORTED: screen family {family} is fixture-only and has no production data binding. No DEMO fallback was used.</p>;
  return <ApiState pending={query.isPending} error={query.error} retry={() => { void query.refetch(); }}>
    {query.data === 0 ? <EmptyState icon={Database} title={`No records for screen family ${family}`} description="No data was supplied. Missing or unassessed data is not a successful result." /> : children}
  </ApiState>;
}
