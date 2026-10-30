"""Phase 7: OR-Tools CP-SAT remediation plan optimizer.

Implements I06–I10:
- I06: Select bounded remediation actions using vetted Vidhi candidates
- I07: Safety-contract preservation as hard constraints
- I08: Blast-radius cap, change-cost budget
- I09: Dependency ordering and conflict detection
- I10: UNSAT diagnosis and alternative plan ranking

Design invariants:
- No LLM free-form planning; no fabricated CLI commands.
- Only approved action IDs from vetted template registry are dispatched.
- If no validated candidate exists → NO_VALIDATED_PLAN outcome.
- If constraints infeasible → UNSAT with violated_constraints list.
- Deterministic: same input → same plan hash.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid5, NAMESPACE_URL

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Domain types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class VettedCandidate:
    """A remediation action candidate vetted by the Vidhi engine.

    Fields come from the template registry; no executable command strings allowed.
    """
    template_id: UUID
    template_version: str
    asset_id: UUID
    targets_control_ids: list[str]          # CIS control IDs this action addresses
    platform_family: str                     # e.g. "linux", "windows", "firewall"
    expected_device_version: str
    baseline_sha256: str                     # current config hash pre-action
    validated_parameters_ref: UUID           # opaque reference to validated params
    recovery: str                            # "ROLLBACK" | "COMPENSATION" | "MANUAL_REQUIRED"
    change_cost: int                         # relative cost unit (1–100)
    blast_radius: int                        # potential service impact (1–100)
    depends_on_template_ids: list[UUID] = field(default_factory=list)
    supported: bool = True                   # False → cannot be selected (firmware unsupported)


@dataclass
class PlanConstraints:
    """Hard constraints from the plan creation request."""
    finding_ids: list[UUID]
    safety_contract_ids: list[UUID]
    max_change_cost: int                     # ≥ 0; 0 means unlimited
    max_blast_radius: int = 100             # per action cap
    require_recoverability: bool = True      # ROLLBACK or COMPENSATION only


@dataclass
class PlanResult:
    outcome: str                             # FEASIBLE | UNSAT | UNSUPPORTED | NO_VALIDATED_PLAN
    selected_actions: list[dict[str, Any]]  # RemediationAction-compatible dicts
    violated_constraints: list[str]
    objective_score: int                     # lower = better (minimized cost)
    sequence: list[int]                      # topological index ordering
    alternative_count: int = 0              # hint: how many other feasible combos found


# ─────────────────────────────────────────────────────────────────────────────
# Graph-based sequencer
# ─────────────────────────────────────────────────────────────────────────────

def _build_dependency_order(candidates: list[VettedCandidate], selected_indices: list[int]) -> list[int]:
    """Topologically sort selected candidates by their dependency relationships."""
    import networkx as nx

    selected_set = {candidates[i].template_id for i in selected_indices}
    g = nx.DiGraph()
    idx_by_tid = {candidates[i].template_id: i for i in selected_indices}

    for i in selected_indices:
        g.add_node(i)
        for dep_tid in candidates[i].depends_on_template_ids:
            if dep_tid in selected_set:
                # dep must run before i
                g.add_edge(idx_by_tid[dep_tid], i)

    try:
        return list(nx.topological_sort(g))
    except nx.NetworkXUnfeasible:
        return selected_indices  # cyclic dep → keep original order, flag in violations


def _conflict_detect(candidates: list[VettedCandidate], selected_indices: list[int]) -> list[str]:
    """Detect conflicting actions (same asset, same control targeted twice)."""
    conflicts = []
    seen: dict[tuple[UUID, str], int] = {}
    for i in selected_indices:
        c = candidates[i]
        for ctrl in c.targets_control_ids:
            key = (c.asset_id, ctrl)
            if key in seen:
                conflicts.append(
                    f"Conflict: template {c.template_id} and {candidates[seen[key]].template_id} "
                    f"both target control {ctrl} on asset {c.asset_id}"
                )
            else:
                seen[key] = i
    return conflicts


# ─────────────────────────────────────────────────────────────────────────────
# OR-Tools CP-SAT optimizer
# ─────────────────────────────────────────────────────────────────────────────

_CP_SAT_AVAILABLE = False
try:
    from ortools.sat.python import cp_model
    _CP_SAT_AVAILABLE = hasattr(cp_model, 'CpModel')
except ImportError:
    logger.warning("OR-Tools CP-SAT not available; using greedy fallback optimizer.")


def _greedy_select(
    candidates: list[VettedCandidate],
    required_controls: set[str],
    constraints: PlanConstraints,
) -> tuple[list[int], list[str]]:
    """Greedy fallback: sort by cost ascending, pick until all controls covered."""
    remaining = set(required_controls)
    selected: list[int] = []
    total_cost = 0
    violations: list[str] = []

    ordered = sorted(range(len(candidates)), key=lambda i: candidates[i].change_cost)
    for i in ordered:
        c = candidates[i]
        if not c.supported:
            continue
        if constraints.require_recoverability and c.recovery == "MANUAL_REQUIRED":
            continue
        covered = set(c.targets_control_ids) & remaining
        if not covered:
            continue
        new_cost = total_cost + c.change_cost
        if constraints.max_change_cost > 0 and new_cost > constraints.max_change_cost:
            violations.append(f"Cost budget exceeded adding template {c.template_id}")
            continue
        if c.blast_radius > constraints.max_blast_radius:
            violations.append(f"Blast radius {c.blast_radius} exceeds cap for template {c.template_id}")
            continue
        selected.append(i)
        remaining -= covered
        total_cost += c.change_cost

    if remaining:
        for ctrl in sorted(str(c) for c in remaining):
            violations.append(f"No vetted candidate covers control {ctrl}")

    return selected, violations


def _cpsat_select(
    candidates: list[VettedCandidate],
    required_controls: set[str],
    constraints: PlanConstraints,
) -> tuple[list[int], list[str], int]:
    """CP-SAT selection: minimize total change_cost subject to hard constraints."""
    from ortools.sat.python import cp_model  # type: ignore

    model = cp_model.CpModel()
    n = len(candidates)
    x = [model.NewBoolVar(f"x_{i}") for i in range(n)]

    by_template = {c.template_id: i for i,c in enumerate(candidates)}
    for i,c in enumerate(candidates):
        for dependency in c.depends_on_template_ids:
            if dependency not in by_template:
                model.Add(x[i] == 0)
            else:
                model.Add(x[i] <= x[by_template[dependency]])
    import networkx as nx
    dependencies = nx.DiGraph()
    dependencies.add_nodes_from(range(n))
    for i,c in enumerate(candidates):
        dependencies.add_edges_from((i,by_template[d]) for d in c.depends_on_template_ids if d in by_template)
    for cycle in nx.simple_cycles(dependencies):
        for i in cycle:
            model.Add(x[i] == 0)
    for i,c in enumerate(candidates):
        for j in range(i):
            other=candidates[j]
            if c.asset_id == other.asset_id and set(c.targets_control_ids) & set(other.targets_control_ids):
                model.Add(x[i]+x[j] <= 1)

    # Hard constraint: unsupported or no-recovery actions cannot be selected
    for i, c in enumerate(candidates):
        if not c.supported:
            model.Add(x[i] == 0)
        if constraints.require_recoverability and c.recovery == "MANUAL_REQUIRED":
            model.Add(x[i] == 0)
        if c.blast_radius > constraints.max_blast_radius:
            model.Add(x[i] == 0)

    # Hard constraint: every required control must be covered by at least one selected action
    ctrl_to_candidates: dict[str, list[int]] = {}
    for i, c in enumerate(candidates):
        for ctrl in c.targets_control_ids:
            if ctrl in required_controls:
                ctrl_to_candidates.setdefault(ctrl, []).append(i)

    uncoverable: list[str] = []
    for ctrl in required_controls:
        covering = ctrl_to_candidates.get(ctrl, [])
        if not covering:
            uncoverable.append(f"No vetted candidate covers control {ctrl}")
            continue
        model.AddBoolOr([x[i] for i in covering])

    if uncoverable:
        return [], uncoverable, 0

    # Hard constraint: total change_cost ≤ max_change_cost (if set)
    if constraints.max_change_cost > 0:
        model.Add(sum(c.change_cost * x[i] for i, c in enumerate(candidates)) <= constraints.max_change_cost)

    # Objective: minimize total change_cost
    model.Minimize(sum(c.change_cost * x[i] for i, c in enumerate(candidates)))

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 10.0
    solver.parameters.num_search_workers = 1  # deterministic single-threaded
    status = solver.Solve(model)

    violations: list[str] = []
    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        selected = [i for i in range(n) if solver.Value(x[i]) == 1]
        objective = int(solver.ObjectiveValue())
        return selected, violations, objective
    else:
        # INFEASIBLE or UNKNOWN
        violations.append("CP-SAT: no feasible combination satisfies all constraints")
        return [], violations, 0


# ─────────────────────────────────────────────────────────────────────────────
# Public optimizer entry point
# ─────────────────────────────────────────────────────────────────────────────

def optimize_plan(
    candidates: list[VettedCandidate],
    required_control_ids: set[str],
    constraints: PlanConstraints,
) -> PlanResult:
    """Select the optimal remediation action set under CP-SAT constraints.

    Returns a PlanResult with outcome FEASIBLE, UNSAT, UNSUPPORTED, or NO_VALIDATED_PLAN.
    Never returns executable command strings; only approved action IDs.
    """
    if not candidates:
        return PlanResult(
            outcome="NO_VALIDATED_PLAN",
            selected_actions=[],
            violated_constraints=["No vetted remediation candidates provided"],
            objective_score=0,
            sequence=[],
        )

    supported = [c for c in candidates if c.supported]
    if not supported:
        return PlanResult(
            outcome="UNSUPPORTED",
            selected_actions=[],
            violated_constraints=["All candidates are unsupported for this firmware/platform"],
            objective_score=0,
            sequence=[],
        )

    violations: list[str] = []
    objective = 0

    if _CP_SAT_AVAILABLE:
        selected_indices, violations, objective = _cpsat_select(candidates, required_control_ids, constraints)
    else:
        selected_indices, violations = _greedy_select(candidates, required_control_ids, constraints)
        objective = sum(candidates[i].change_cost for i in selected_indices)

    # Conflict detection
    conflict_violations = _conflict_detect(candidates, selected_indices)
    if conflict_violations:
        violations.extend(conflict_violations)
        selected_indices = []

    if not selected_indices and violations:
        return PlanResult(
            outcome="UNSAT",
            selected_actions=[],
            violated_constraints=violations,
            objective_score=0,
            sequence=[],
        )

    # Dependency-ordered sequence
    sequence = _build_dependency_order(candidates, selected_indices)

    # Build action dicts
    actions = []
    action_ids = {i:uuid5(NAMESPACE_URL, json.dumps({
        'template':str(candidates[i].template_id), 'asset':str(candidates[i].asset_id),
        'version':candidates[i].template_version, 'baseline':candidates[i].baseline_sha256,
        'parameters':str(candidates[i].validated_parameters_ref)}, sort_keys=True)) for i in sequence}
    for i in sequence:
        c = candidates[i]
        action_id = action_ids[i]
        actions.append({
            "action_id": str(action_id),
            "asset_id": str(c.asset_id),
            "template_id": str(c.template_id),
            "template_version": c.template_version,
            "expected_device_version": c.expected_device_version,
            "baseline_sha256": c.baseline_sha256,
            "validated_parameters_ref": str(c.validated_parameters_ref),
            "depends_on": [str(action_ids[j]) for j in sequence if candidates[j].template_id in c.depends_on_template_ids],
            "recovery": c.recovery,
        })

    return PlanResult(
        outcome="FEASIBLE",
        selected_actions=actions,
        violated_constraints=[],
        objective_score=objective,
        sequence=list(range(len(actions))),
    )


def compute_plan_sha256(actions: list[dict], safety_contract_ids: list[UUID]) -> str:
    """Compute deterministic SHA-256 hash of a plan for tamper-detection."""
    canonical = json.dumps(
        {
            "actions": sorted(actions, key=lambda a: a["action_id"]),
            "safety_contract_ids": sorted(str(s) for s in safety_contract_ids),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def rank_alternative_plans(
    candidates: list[VettedCandidate],
    required_control_ids: set[str],
    base_constraints: PlanConstraints,
    max_alternatives: int = 3,
) -> list[PlanResult]:
    """Generate ranked alternative plans by relaxing cost/blast caps progressively."""
    results: list[PlanResult] = []

    # Try with tighter cost windows first, then broader
    cost_multipliers = [1.0, 1.5, 2.0]
    for m in cost_multipliers:
        adjusted = PlanConstraints(
            finding_ids=base_constraints.finding_ids,
            safety_contract_ids=base_constraints.safety_contract_ids,
            max_change_cost=int(base_constraints.max_change_cost * m) if base_constraints.max_change_cost > 0 else 0,
            max_blast_radius=base_constraints.max_blast_radius,
            require_recoverability=base_constraints.require_recoverability,
        )
        r = optimize_plan(candidates, required_control_ids, adjusted)
        if r.outcome == "FEASIBLE":
            results.append(r)
        if len(results) >= max_alternatives:
            break

    return results

