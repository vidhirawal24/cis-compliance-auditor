import { useSyncExternalStore } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useApi } from '../../api/context';
import { DemoApiClient } from '../../api/client';
import type { RemediationPlan, WhatIfSimulation } from '../../contracts/v1/types';
import { SimulationVerdict as V } from '../../contracts/v1/enums';

// Frontend DEMO presentation metadata, never a production wire contract.
export interface Candidate {
  id: string;
  name: string;
  plan: RemediationPlan;
  verdict: V;
  cost: number;
  disruption: number;
  unsat: string[];
  dependencies: { source: string; target: string; reason: string }[];
}
export function demoCandidates(plan: RemediationPlan, simulation: WhatIfSimulation): Candidate[] {
  const dependencies = plan.actions.length > 1 ? [{ source: plan.actions[0].action_id, target: plan.actions[1].action_id, reason: 'Verify SSH management before restricting the ACL (DEMO dependency)' }] : [];
  const base = { plan, dependencies, cost: 3, disruption: plan.minimal_change_score, unsat: [] };
  return [
    { ...base, id: 'balanced', name: 'Balanced sequence', verdict: simulation.verdict },
    { ...base, plan: { ...plan, plan_id: 'demo-restrictive', plan_hash: '', actions: plan.actions.map((a, i) => i === 1 ? { ...a, title: 'Hypothetical ACL removes admin SSH', command_template: 'No executable template supplied for this hypothesis' } : a) }, id: 'restrictive', name: 'Restrictive ACL hypothesis', cost: 2, disruption: 27, verdict: V.VIOLATES_CONTRACT },
    { ...base, id: 'unsupported', name: 'Unsupported vendor hypothesis', verdict: V.UNSUPPORTED },
    { ...base, id: 'incomplete', name: 'Incomplete topology hypothesis', verdict: V.INSUFFICIENT_EVIDENCE },
    { ...base, id: 'unsat', name: 'Zero-change constraint hypothesis', verdict: V.INSUFFICIENT_EVIDENCE, unsat: ['UNSAT: zero changes and removal of Telnet cannot both be satisfied.'] },
  ];
}
type Session = { selected: string; preview: string | null; dirty: boolean };
const sessions = new Map<string, Session>();
const initial: Session = { selected: 'balanced', preview: null, dirty: false };
const listeners = new Set<() => void>();
export function updateSession(org: string, patch: Partial<Session>) {
  sessions.set(org, { ...(sessions.get(org) ?? initial), ...patch });
  listeners.forEach(fn => fn());
}
export function usePlanSession(org: string) {
  return useSyncExternalStore(fn => { listeners.add(fn); return () => { listeners.delete(fn); }; }, () => sessions.get(org) ?? initial);
}
export function usePhase6(org: string, planId = 'plan-2026-8801', simId = 'sim-2026-4401') {
  const api = useApi();
  const query = useQuery({ queryKey: ['phase6', org, planId, simId, api], queryFn: async () => {
    const [plan, simulation, contracts, graph] = await Promise.all([
      api.getRemediationPlan(planId), api.getSimulation(simId), api.getSafetyContracts(), api.getSecurityGraph(),
    ]);
    if (plan.data.org_id !== org || contracts.data.some(c => c.org_id !== org)) throw new Error('Plan or contracts belong to another organization.');
    if (simulation.data.plan_id !== plan.data.plan_id || simulation.data.simulation_id !== simId) throw new Error('Simulation does not match the requested plan or simulation ID.');
    return { plan: plan.data, simulation: simulation.data, contracts: contracts.data, graph: graph.data };
  }, retry: false });
  const session = usePlanSession(org);
  const candidates = query.data && api instanceof DemoApiClient ? demoCandidates(query.data.plan, query.data.simulation) : [];
  const candidate = candidates.find(c => c.id === session.selected);
  const previewKey = candidate && query.data ? JSON.stringify([candidate.id, query.data.plan, query.data.simulation, query.data.contracts, query.data.graph]) : null;
  const canReview = !query.isError && !query.isFetching && !!candidate && !!candidate.plan.actions.length && session.preview === previewKey && !session.dirty && candidate.verdict === V.SAFE_IN_MODEL && !candidate.unsat.length && !candidate.plan.conflict_detected && !candidate.plan.conflicts.length && !!query.data && query.data.simulation.model_coverage_pct > 0 && query.data.graph.meta.coverage_completeness_pct > 0 && query.data.simulation.safety_contracts_violated === 0 && query.data.simulation.safety_contracts_evaluated >= query.data.contracts.filter(c => c.active && c.mandatory).length;
  return { ...query, candidates, candidate, session, previewKey, canReview };
}
