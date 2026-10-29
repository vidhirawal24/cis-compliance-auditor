import { useEffect, useState } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useApi, apiCacheKey } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import { ReportFormat } from '../../contracts/v1/enums';
import { ApiState } from '../../components/common/ApiState';
import { Card } from '../../components/ui/card';
import { Input } from '../../components/ui/input';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { ConfigDiff } from '../../components/common/ConfigDiff';
import { ReportAccess } from '../../features/phase8/ReportAccess';
import { ExecutiveSummary } from '../../features/phase8/ExecutiveSummary';

// M38,E05-E07,E28-E29: backend artifacts and history only; no generated links.
export function ReportsHistoryShell() {
  const api = useApi();
  const { orgId = '' } = useParams();
  const { pathname } = useLocation();
  const [filter, setFilter] = useState('');
  const [format, setFormat] = useState('ALL');
  const [tab, setTab] = useState(pathname.endsWith('/drift') ? 'DRIFT' : 'REPORTS');
  useEffect(() => { setTab(pathname.endsWith('/drift') ? 'DRIFT' : 'REPORTS'); }, [pathname]);
  const query = useQuery({ queryKey: ['reports-history', orgId, apiCacheKey(api)], queryFn: async () => {
    const [reports, drift] = await Promise.all([api.getReports(), api.getDriftEvents()]);
    if ([...reports.data, ...drift.data].some(record => record.org_id !== orgId)) throw new Error('Tenant mismatch');
    return { reports: reports.data, drift: drift.data };
  }, retry: false });
  return <div className="space-y-5"><h1 className="text-xl font-bold">Compliance Reports &amp; Drift Timeline (M38, E05-E07, E28-E29)</h1>
    <Badge variant="warning">{api instanceof DemoApiClient ? 'DEMO - synthetic reports and history' : 'Backend-supplied records'}</Badge>
    <p>Report generation is UNSUPPORTED: no typed generation operation. Report asset scope, benchmark release and profile metadata are not supplied; do not infer them from a title. Exports require server authorization and redaction.</p>
    <Button disabled>Generate new report - unsupported</Button>
    <div className="flex flex-wrap gap-2">{['REPORTS', 'DRIFT'].map(value => <Button key={value} variant="outline" aria-pressed={tab === value} onClick={() => setTab(value)}>{value === 'REPORTS' ? 'Export center' : 'Configuration drift'}</Button>)}</div>
    <label>Search reports or drift assets<Input value={filter} onChange={event => setFilter(event.target.value)} /></label>
    <ApiState pending={query.isPending} error={query.error} retry={() => { void query.refetch(); }}>
      {tab === 'REPORTS' ? <section aria-label="Report formats" className="space-y-3">
        <label>Format <select className="bg-slate-900 border p-2" value={format} onChange={event => setFormat(event.target.value)}>{['ALL', ...Object.values(ReportFormat)].map(value => <option key={value}>{value}</option>)}</select></label>
        {Object.values(ReportFormat).filter(value => format === 'ALL' || format === value).map(value => {
          const reports = query.data?.reports.filter(report => report.format === value && report.title.toLowerCase().includes(filter.toLowerCase())) ?? [];
          return <Card key={value} className="p-4 space-y-3"><h2>{value} exports</h2>{reports.length ? reports.map(report => <article key={report.report_id} className="p-3 border border-slate-700 rounded"><h3>{report.title}</h3><p>Report: {report.report_id}; generated: {report.created_at}; size: {report.file_size_bytes} bytes.</p><ReportAccess report={report} /></article>) : <p>No {value} artifact supplied or matching this filter. Generation and signed-URL renewal are unavailable.</p>}</Card>;
        })}
      </section> : <section aria-label="Configuration drift timeline" className="space-y-3"><h2>Observed snapshot history</h2><p>Only supplied snapshot events are shown. This does not imply continuous monitoring or prove an unauthorized change.</p>
        {!query.data?.drift.length && <p>No drift history supplied.</p>}
        {!!query.data?.drift.length && !query.data.drift.some(event => `${event.hostname} ${event.asset_id}`.toLowerCase().includes(filter.toLowerCase())) && <p>No drift records match this filter.</p>}
        {query.data?.drift.filter(event => `${event.hostname} ${event.asset_id}`.toLowerCase().includes(filter.toLowerCase())).map(event => <Card key={event.event_id} className="p-4"><h3>{event.hostname}</h3><p>Asset: {event.asset_id}; observed: {event.detected_at}; severity: {event.severity}</p><p>Previous snapshot: {event.previous_snapshot_id || 'Unknown'}; new snapshot: {event.current_snapshot_id || 'Unknown'}</p><ConfigDiff diffText={event.diff_preview} title="Supplied previous/new snapshot delta" /><p>Control identity, full previous/new values, evidence artifact URI, encryption and hash verification are not supplied. Snapshot retrieval is unsupported.</p></Card>)}
      </section>}
    </ApiState>
    <Card className="p-4"><ExecutiveSummary /></Card>
  </div>;
}
