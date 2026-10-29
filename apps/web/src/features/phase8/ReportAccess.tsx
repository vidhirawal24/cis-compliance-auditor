import { useEffect, useRef, useState } from 'react';
import type { GeneratedReport } from '../../contracts/v1/types';
import { DemoApiClient } from '../../api/client';
import { useApi } from '../../api/context';
import { Button } from '../../components/ui/button';

export function reportAccess(report: GeneratedReport, now = Date.now()): string {
  if (!report.download_url) return 'UNAVAILABLE';
  try {
    const url = new URL(report.download_url);
    if (url.protocol !== 'https:' || url.username || url.password) return 'UNSUPPORTED_URL';
  } catch { return 'UNSUPPORTED_URL'; }
  const expires = Date.parse(report.signed_url_expires_at);
  if (!Number.isFinite(expires)) return 'UNKNOWN_EXPIRY';
  return expires <= now ? 'EXPIRED' : 'AVAILABLE';
}

// Use only the supplied URL; never construct a storage URL or store its token.
export function ReportAccess({ report }: { report: GeneratedReport }) {
  const api = useApi();
  const [now, setNow] = useState(Date.now());
  const [state, setState] = useState('');
  const [pending, setPending] = useState(false);
  const activeRequest = useRef<AbortController | null>(null);
  useEffect(() => () => { activeRequest.current?.abort(); }, []);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const access = reportAccess(report, now);
  const demo = api instanceof DemoApiClient;
  const retrieve = async () => {
    if (demo || pending || reportAccess(report) !== 'AVAILABLE') return;
    setPending(true); setState('Retrieving artifact...');
    const controller = new AbortController();
    activeRequest.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(report.download_url, { credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', redirect: 'error', signal: controller.signal });
      if (response.status === 401 || response.status === 403) {
        setState(`${response.status} ${response.status === 403 ? 'Forbidden' : 'Unauthorized'}: artifact access denied. Request fresh authorized access.`);
        return;
      }
      if (!response.ok) throw new Error('Retrieval denied or failed');
      const blob = await response.blob();
      if (controller.signal.aborted) return;
      if (!blob.size || reportAccess(report) !== 'AVAILABLE') throw new Error('Artifact unavailable or access expired');
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = `baselineguard-report.${report.format.toLowerCase()}`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setState('Artifact retrieved; browser save requested. Save completion is not confirmed.');
    } catch {
      setState('Retrieval failed or access expired. Request a fresh authorized report; no download success is claimed.');
    } finally { window.clearTimeout(timeout); setPending(false); }
  };
  return <div><p>Access: {access}; expires: {report.signed_url_expires_at || 'Not supplied'}</p>
    {demo && <p>DEMO artifact only; external fixture URL retrieval is disabled.</p>}
    <Button variant="outline" disabled={demo || pending || access !== 'AVAILABLE'} onClick={() => { void retrieve(); }}>Retrieve {report.format}</Button>
    {state && <p role="status">{state}</p>}
  </div>;
}
