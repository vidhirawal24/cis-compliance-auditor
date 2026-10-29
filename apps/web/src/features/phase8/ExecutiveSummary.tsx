import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { useApi, apiCacheKey } from '../../api/context';
import { ApiState } from '../../components/common/ApiState';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table';

export function ExecutiveSummary() {
  const { orgId = '' } = useParams();
  const api = useApi();
  const query = useQuery({ queryKey: ['executive', orgId, apiCacheKey(api)], queryFn: async () => {
    const [scans, assets, findings, trends, risks] = await Promise.all([api.getScans(orgId), api.getAssets(orgId), api.getFindings(), api.getComplianceTrends(), api.getRiskScenarios()]);
    if ([...scans.data, ...assets.data, ...findings.data, ...risks.data].some(item => item.org_id !== orgId)) throw new Error('Tenant mismatch');
    return { scans: scans.data, assets: assets.data, findings: findings.data, trends: trends.data, risks: risks.data };
  }, retry: false });
  const data = query.data;
  const scan = data?.scans.filter(s => s.status === 'COMPLETED').sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))[0];
  return <section aria-label="Executive summary"><h2>Executive summary (E28)</h2>
    <ApiState pending={query.isPending} error={query.error} retry={() => { void query.refetch(); }}>
      {data && <div className="space-y-3">
        <p>Assessed compliance: {scan ? `${scan.assessed_compliance_pct}%` : 'Not available'}; assessment coverage: {scan ? `${scan.assessment_coverage_pct}%` : 'Not available'}. Values supplied by the API, never recomputed.</p>
        <p>Assets: {data.assets.length}; findings: {data.findings.length}; risk scenarios: {data.risks.length} (returned records only; complete fleet totals are not established).</p>
        <p>Audit: {scan?.scan_id ?? 'No completed audit supplied'}; policy: {scan?.policy_pack_id ?? 'Unknown'}; profile: {scan?.profile_level ?? 'Unknown'}; freshness: {scan?.completed_at ?? 'Completion time not supplied'}.</p>
        <p>Reporting range: {data.trends[0]?.date ?? 'Unknown'} through {data.trends[data.trends.length - 1]?.date ?? 'Unknown'}. Benchmark consistency and trend tenant metadata are not supplied; compare cautiously.</p>
        {!data.trends.length ? <p>No compliance trend history supplied.</p> : <>
          <div role="img" aria-label="Compliance and coverage trends; exact values in the following table" style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%"><LineChart data={data.trends} accessibilityLayer><XAxis dataKey="date" /><YAxis domain={[0, 100]} /><Tooltip /><Legend /><Line name="Assessed compliance" dataKey="assessed_compliance_pct" stroke="#38bdf8" /><Line name="Assessment coverage" dataKey="assessment_coverage_pct" stroke="#f59e0b" /></LineChart></ResponsiveContainer>
          </div>
          <Table aria-label="Exact compliance and coverage history"><TableHeader><TableRow><TableHead>Date</TableHead><TableHead>Compliance %</TableHead><TableHead>Coverage %</TableHead></TableRow></TableHeader><TableBody>{data.trends.map(point => <TableRow key={point.date}><TableCell>{point.date}</TableCell><TableCell>{point.assessed_compliance_pct}</TableCell><TableCell>{point.assessment_coverage_pct}</TableCell></TableRow>)}</TableBody></Table>
        </>}
      </div>}
    </ApiState>
  </section>;
}
