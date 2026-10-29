import { useNavigate, useParams } from 'react-router-dom';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { PlanDiagram } from '../../features/phase6/PlanDiagram';
import { usePhase6, updateSession } from '../../features/phase6/model';

// I06-I10 presentation; optimizer execution is unavailable.
export function RemediationPlannerShell() {
  const { orgId = '', planId } = useParams();
  const navigate = useNavigate();
  const result = usePhase6(orgId, planId);
  return <div className="space-y-6"><h1 className="text-xl font-bold">Remediation Planner & Sequence DAG (I06-I10)</h1>
    <Badge variant="warning">DEMO -- synthetic alternatives; no optimizer ran</Badge>
    <p>Candidate scores and weights are fixture values, not production recommendations. Vetted action templates come from the supplied DEMO plan.</p>
    <Card className="p-4 space-y-2"><h2>Objective weights (DEMO, read-only)</h2><p>Disruption: 0.6 -- prefer lower operational interruption. Cost: 0.3 -- prefer lower change effort. Change count: 0.1 -- prefer fewer steps.</p><p>Weights explain the synthetic example only; changing objectives and re-optimization are unsupported by the current API.</p></Card>
    {result.isPending ? <p role="status">Loading remediation plans...</p> : result.isError ? <div role="alert">Unable to load plans: {result.error.message} <Button onClick={() => result.refetch()}>Retry</Button></div> : !result.candidates.length ? <p>No candidate data available. Production alternative generation is UNSUPPORTED.</p> : <>
      <div className="grid md:grid-cols-2 gap-4">{result.candidates.map(c => <Card key={c.id} className={`p-4 space-y-2 ${result.session.selected === c.id ? 'border-sky-400' : ''}`}><h2>{c.name}</h2><p>DEMO disruption: {c.disruption}; effort cost: {c.cost}; steps: {c.plan.actions.length}</p><Button variant="outline" aria-pressed={result.session.selected === c.id} onClick={() => updateSession(orgId, { selected: c.id, preview: null })}>{result.session.selected === c.id ? 'Selected plan: ' : 'Select plan: '}{c.name}</Button></Card>)}</div>
      {result.candidate && <Card className="p-4 space-y-4"><h2>Selected plan: {result.candidate.name}</h2><p>DEMO scenario: {result.candidate.verdict}</p>
        {result.candidate.unsat.map(message => <p role="alert" key={message}>{message}</p>)}
        {result.candidate.plan.conflicts.map(message => <p role="alert" key={message}>Constraint violation: {message}</p>)}
        {result.candidate.plan.conflict_detected && <p role="alert">Conflicts detected; simulation cannot proceed.</p>}
        {!result.candidate.plan.conflict_detected && !result.candidate.plan.conflicts.length && !result.candidate.unsat.length && <p>No conflicts reported in supplied DEMO data; this is not a safety guarantee.</p>}
        <PlanDiagram key={result.candidate.id} candidate={result.candidate} />
        <Button disabled={!!result.candidate.unsat.length || result.candidate.plan.conflict_detected || !!result.candidate.plan.conflicts.length || !result.candidate.plan.actions.length} onClick={() => navigate(`/orgs/${orgId}/simulator`)}>Proceed to What-If Simulation (I11)</Button>
      </Card>}
    </>}
  </div>;
}
