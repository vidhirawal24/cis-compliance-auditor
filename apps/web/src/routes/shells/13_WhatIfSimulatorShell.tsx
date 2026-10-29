import { useNavigate, useParams } from 'react-router-dom';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { SimulationVerdict as V } from '../../contracts/v1/enums';
import { ContractEditor, SafetyVerdict, ServiceComparison } from '../../features/phase6/SimulationPanels';
import { RolloutPreview } from '../../features/phase6/RolloutPreview';
import { BlastRadiusDiagram } from '../../features/phase6/PlanDiagram';
import { usePhase6, updateSession } from '../../features/phase6/model';

// I11-I14: existing API reads only; there is no simulation submission endpoint.
export function WhatIfSimulatorShell() {
  const { orgId = '', simId } = useParams();
  const navigate = useNavigate();
  const result = usePhase6(orgId, undefined, simId);
  const candidate = result.candidate;
  const data = result.data;
  const previewed = !!result.previewKey && result.session.preview === result.previewKey;
  return <div className="space-y-6"><h1 className="text-xl font-bold">What-If Simulator & Service Safety (I11-I14)</h1><Badge variant="warning">DEMO -- synthetic results; no simulation engine ran</Badge>
    <p>SAFE_IN_MODEL is not verified device safety. Server enforcement and real service verification remain required. No commands are executed by this workflow.</p>
    {result.isPending ? <p role="status">Loading simulation data...</p> : result.isError ? <div role="alert">Unable to load simulation: {result.error.message} <Button onClick={() => result.refetch()}>Retry</Button></div> : !candidate || !data ? <p>No simulation candidate supplied. Production simulation submission is UNSUPPORTED.</p> : <>
      <Card className="p-4 space-y-3"><h2>Selected plan: {candidate.name}</h2><Button variant="outline" onClick={() => navigate(`/orgs/${orgId}/planner`)}>Choose candidate</Button>
        <p>Load a stored DEMO preview. This does not run an optimizer or simulation. Contract drafts cannot be evaluated.</p>
        <Button disabled={result.session.dirty || !!candidate.unsat.length || candidate.plan.conflict_detected || !!candidate.plan.conflicts.length} onClick={() => updateSession(orgId, { preview: result.previewKey })}>Load DEMO comparison</Button>
        {result.session.dirty && <p role="alert">Contract draft changed: INSUFFICIENT_EVIDENCE. Backend re-evaluation is unavailable; approval blocked.</p>}
        {candidate.unsat.map(message => <p role="alert" key={message}>{message}</p>)}
        {previewed && <>
          <SafetyVerdict verdict={candidate.verdict} />
          <p>Model coverage: {candidate.verdict === V.UNSUPPORTED ? 'Not available' : candidate.verdict === V.INSUFFICIENT_EVIDENCE ? 'Incomplete; percentage unknown' : `${data.simulation.model_coverage_pct}% (synthetic)`}</p>
          <p>Model engine in stored fixture: {data.simulation.model_engine}. No real-device verification.</p>
          {(candidate.verdict === V.SAFE_IN_MODEL || candidate.verdict === V.VIOLATES_CONTRACT) ? <ServiceComparison violated={candidate.verdict === V.VIOLATES_CONTRACT} /> : <p>Before/after reachability unavailable for this model; do not infer preserved connectivity.</p>}
          <h3>Safety contracts supplied</h3><ul>{data.contracts.map(c => <li key={c.contract_id}>{c.name}: {c.source_cidr} to {c.destination_cidr}; {c.port_range}/{c.protocol}; {c.mandatory ? 'MANDATORY' : 'OPTIONAL'}; {c.active ? 'ACTIVE' : 'INACTIVE'} -- {candidate.verdict === V.VIOLATES_CONTRACT && c.contract_id === 'sc-01-mgmt-access' ? 'VIOLATES_CONTRACT (hypothetical)' : 'Per-contract result not supplied'}</li>)}</ul>
          <p>Stored result: {data.simulation.safety_contracts_evaluated} evaluated / {data.simulation.safety_contracts_violated} violated. The restrictive hypothesis additionally violates management SSH in the synthetic example.</p>
          <h3>Affected services / blast radius (I13)</h3>
          {(candidate.verdict === V.SAFE_IN_MODEL || candidate.verdict === V.VIOLATES_CONTRACT) ? <><p>Estimated endpoints: {data.simulation.blast_radius_asset_count} (DEMO estimate; complete endpoint identities not supplied)</p><ul>{data.simulation.affected_services.map(s => <li key={s}>{s} -- hypothetical model impact</li>)}</ul></> : <p>Affected services and blast radius unknown: unsupported or insufficiently evidenced impact.</p>}
          <BlastRadiusDiagram graph={data.graph} affectedServices={data.simulation.affected_services} showImpact={candidate.verdict === V.SAFE_IN_MODEL || candidate.verdict === V.VIOLATES_CONTRACT} />
          <h3>Supplied dependency data (confirmed within DEMO fixture only)</h3><ul>{data.graph.edges.filter(e => e.data.confidence === 'CONFIRMED' && ['hosted_on', 'attached_to', 'routes_to', 'allows'].includes(e.data.relation)).map(e => <li key={e.data.id}>{e.data.source} to {e.data.target}: {e.data.relation}</li>)}</ul>
          <p>Topology coverage: {data.graph.meta.coverage_completeness_pct}%. Unknown dependencies remain outside the supplied graph. Transitive consequences are hypothetical; graph links alone do not confirm service disruption. Missing topology prevents a complete blast-radius claim.</p>
        </>}
        <Button disabled={!result.canReview} onClick={() => { if (result.canReview) navigate(`/orgs/${orgId}/approvals`); }}>Proceed to Approval Review (I14)</Button>
        {!result.canReview && <p>Approval blocked: load an eligible preview with no violations, conflicts, or changed contracts.</p>}
        <p>The server remains the final enforcement authority. DEMO review cannot authorize production execution.</p>
      </Card>
      <Card className="p-4"><ContractEditor onDirty={() => updateSession(orgId, { dirty: true, preview: null })} /></Card>
      <Card className="p-4"><RolloutPreview /></Card>
    </>}
  </div>;
}
