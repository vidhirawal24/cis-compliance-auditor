import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useApi } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import { ApiState } from '../../components/common/ApiState';
import { Badge } from '../../components/ui/badge';
import { Card } from '../../components/ui/card';
import { verificationOutcome, validHash } from '../../features/phase7/review';

// E25, I16-I18. Missing evidence remains explicit.
export function VerificationProofShell() {
  const { orgId = '', packageId } = useParams();
  const api = useApi();
  const query = useQuery({ queryKey: ['phase7-proof', orgId, packageId], queryFn: async () => {
    const proof = (await api.getProofPackage(packageId ?? 'proof-2026-001')).data;
    if (proof.org_id !== orgId || (packageId && proof.package_id !== packageId)) throw new Error('Proof identity mismatch');
    const [change, verification] = await Promise.all([api.getChange(proof.change_id), api.getVerification('verif-2026-9901')]);
    if (change.data.change_id !== proof.change_id || verification.data.change_id !== proof.change_id) throw new Error('Verification linkage mismatch');
    return { proof, change: change.data, verification: verification.data };
  }, retry: false });
  const data = query.data;
  return <div className="space-y-5"><h1 className="text-xl font-bold">Dual Verification &amp; Proof Dossier (I16-I18)</h1>
    <Badge variant="warning">{api instanceof DemoApiClient ? 'DEMO - synthetic evidence, not live verification' : 'Supplied backend evidence'}</Badge>
    <ApiState pending={query.isPending} error={query.error} retry={() => { void query.refetch(); }}>
      {data && <>
        <Card className="p-4 space-y-2"><h2>Dual verification</h2><p>Overall result: {verificationOutcome(data.change, data.verification)}</p>
          <p>CIS control verification: {data.verification.cis_control_status ?? 'UNKNOWN'}</p>
          <p>Actual service-health verification: {data.verification.service_probe_status ?? 'UNKNOWN'}</p>
          <p>Backend change state: {data.change.state}; overall_verified: {String(data.verification.overall_verified)}</p>
          <p>Verification ID: {data.verification.verification_id}; time: {data.verification.verified_at || 'Not supplied'}</p>
          <p>Control IDs, service IDs, expected/observed details and probe evidence references are not supplied by this contract. Do not infer live SSH or HTTPS verification.</p>
          <p>Post-fix re-audit trigger: UNSUPPORTED. This page reads the supplied verification record only.</p>
        </Card>
        <Card className="p-4"><h2>Residual risk (I17)</h2><p>Baseline risk: {data.verification.pre_change_risk_score ?? 'UNKNOWN'}; residual risk: {data.verification.residual_risk_score ?? 'UNKNOWN'}. Backend values; scale and calculation provenance not supplied. No zero-risk claim.</p></Card>
        <Card className="p-4 space-y-2"><h2>Proof manifest (I18)</h2>
          <p>Package: {data.proof.package_id}; change: {data.proof.change_id}; plan: {data.change.plan_id}</p>
          <p>Created: {data.proof.created_at || 'Not supplied'}; signer identity: {data.proof.signer_identity || 'Not supplied'}</p>
          <p>Manifest state: {data.proof.manifest_verified === true ? 'VERIFIED as reported by backend record' : data.proof.manifest_verified === false ? 'NOT VERIFIED / check not confirmed' : 'UNKNOWN'}. No independent local signature verification was performed.</p>
          <dl className="break-all">{Object.entries({ 'Before hash': data.proof.pre_hardening_config_hash, 'After hash': data.proof.post_hardening_config_hash, 'Execution log hash': data.proof.execution_log_hash }).map(([label, hash]) => <div key={label}><dt>{label}</dt><dd>{validHash(hash) ? hash : 'Unavailable or invalid SHA-256'}</dd></div>)}</dl>
          <p>Hash shape validation does not verify artifact integrity. Before/after artifact URIs and individual hash-check results are not supplied.</p>
          <p>PDF/JSON dossier retrieval: BLOCKED - proof URL expiry and authorized retrieval behavior are not defined. No artifact was downloaded or verified here.</p>
        </Card>
      </>}
    </ApiState>
  </div>;
}
