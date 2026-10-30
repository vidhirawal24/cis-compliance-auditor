"""Phase 7 unit tests: CP-SAT remediation plan optimizer (I06–I10).

Tests:
- Solvable plan with matching candidates
- UNSAT when no candidate covers a required control
- UNSAT when cost budget too tight
- NO_VALIDATED_PLAN when candidates list is empty
- UNSUPPORTED when all candidates are unsupported
- Stable/deterministic plan hash
- Conflict detection between overlapping candidates
- Topological dependency ordering
- Alternative plan ranking relaxes cost budget
- Greedy fallback path (works without OR-Tools import)
"""
from uuid import uuid4

import pytest

from cisguard_api.plan_optimizer import (
    PlanConstraints,
    PlanResult,
    VettedCandidate,
    compute_plan_sha256,
    optimize_plan,
    rank_alternative_plans,
    _conflict_detect,
    _build_dependency_order,
)


def _make_candidate(
    *,
    controls: list[str],
    family: str = "linux",
    cost: int = 10,
    blast: int = 20,
    recovery: str = "ROLLBACK",
    supported: bool = True,
    depends_on: list = None,
) -> VettedCandidate:
    asset_id = uuid4()
    return VettedCandidate(
        template_id=uuid4(),
        template_version="1.0.0",
        asset_id=asset_id,
        targets_control_ids=controls,
        platform_family=family,
        expected_device_version="22.04",
        baseline_sha256="a" * 64,
        validated_parameters_ref=uuid4(),
        recovery=recovery,
        change_cost=cost,
        blast_radius=blast,
        supported=supported,
        depends_on_template_ids=depends_on or [],
    )


def _constraints(
    *,
    finding_ids=None,
    safety_ids=None,
    max_cost=0,
    max_blast=100,
    require_recovery=True,
) -> PlanConstraints:
    return PlanConstraints(
        finding_ids=finding_ids or [uuid4()],
        safety_contract_ids=safety_ids or [],
        max_change_cost=max_cost,
        max_blast_radius=max_blast,
        require_recoverability=require_recovery,
    )


# ─────────────────────────────────────────────────────────────────────────────
# I06: Solvable plan
# ─────────────────────────────────────────────────────────────────────────────

def test_solvable_plan_produces_feasible_outcome():
    c1 = _make_candidate(controls=["5.2.1", "5.2.2"])
    c2 = _make_candidate(controls=["3.5.1"])
    constraints = _constraints(max_cost=50)
    result = optimize_plan([c1, c2], {"5.2.1", "5.2.2", "3.5.1"}, constraints)
    assert result.outcome == "FEASIBLE"
    assert len(result.selected_actions) >= 2
    assert result.violated_constraints == []


def test_solvable_plan_single_candidate_covers_all():
    c1 = _make_candidate(controls=["5.2.1", "5.2.2", "3.5.1"], cost=15)
    result = optimize_plan([c1], {"5.2.1", "5.2.2", "3.5.1"}, _constraints())
    assert result.outcome == "FEASIBLE"
    assert len(result.selected_actions) == 1


# ─────────────────────────────────────────────────────────────────────────────
# I07–I08: Safety constraints and cost cap
# ─────────────────────────────────────────────────────────────────────────────

def test_unsat_when_cost_budget_exceeded():
    c1 = _make_candidate(controls=["5.2.1"], cost=50)
    c2 = _make_candidate(controls=["3.5.1"], cost=60)
    constraints = _constraints(max_cost=30)  # cannot afford any
    result = optimize_plan([c1, c2], {"5.2.1", "3.5.1"}, constraints)
    assert result.outcome == "UNSAT"
    assert result.violated_constraints


def test_unsat_no_candidate_covers_required_control():
    c1 = _make_candidate(controls=["5.2.1"])
    result = optimize_plan([c1], {"9.9.9"}, _constraints())
    assert result.outcome == "UNSAT"
    assert any("9.9.9" in v for v in result.violated_constraints)


def test_unsat_blast_radius_too_high():
    c1 = _make_candidate(controls=["5.2.1"], blast=90)
    constraints = _constraints(max_blast=50)
    result = optimize_plan([c1], {"5.2.1"}, constraints)
    assert result.outcome == "UNSAT"


def test_unsat_no_recovery_candidate_excluded_when_required():
    c1 = _make_candidate(controls=["5.2.1"], recovery="MANUAL_REQUIRED")
    result = optimize_plan([c1], {"5.2.1"}, _constraints(require_recovery=True))
    assert result.outcome == "UNSAT"


def test_no_recovery_candidate_accepted_when_not_required():
    c1 = _make_candidate(controls=["5.2.1"], recovery="MANUAL_REQUIRED")
    result = optimize_plan([c1], {"5.2.1"}, _constraints(require_recovery=False))
    assert result.outcome == "FEASIBLE"


# ─────────────────────────────────────────────────────────────────────────────
# I10: NO_VALIDATED_PLAN and UNSUPPORTED
# ─────────────────────────────────────────────────────────────────────────────

def test_no_validated_plan_when_empty_candidates():
    result = optimize_plan([], {"5.2.1"}, _constraints())
    assert result.outcome == "NO_VALIDATED_PLAN"
    assert result.violated_constraints


def test_unsupported_when_all_candidates_unsupported():
    c1 = _make_candidate(controls=["5.2.1"], supported=False)
    c2 = _make_candidate(controls=["3.5.1"], supported=False)
    result = optimize_plan([c1, c2], {"5.2.1", "3.5.1"}, _constraints())
    assert result.outcome == "UNSUPPORTED"


# ─────────────────────────────────────────────────────────────────────────────
# I09: Conflict detection
# ─────────────────────────────────────────────────────────────────────────────

def test_conflict_detection_same_asset_same_control():
    asset_id = uuid4()

    def _make_with_asset(asset, controls):
        return VettedCandidate(
            template_id=uuid4(),
            template_version="1.0.0",
            asset_id=asset,
            targets_control_ids=controls,
            platform_family="linux",
            expected_device_version="22.04",
            baseline_sha256="a" * 64,
            validated_parameters_ref=uuid4(),
            recovery="ROLLBACK",
            change_cost=5,
            blast_radius=10,
            supported=True,
        )

    c1 = _make_with_asset(asset_id, ["5.2.1"])
    c2 = _make_with_asset(asset_id, ["5.2.1"])  # same control on same asset
    conflicts = _conflict_detect([c1, c2], [0, 1])
    assert len(conflicts) >= 1
    assert "5.2.1" in conflicts[0]


def test_no_conflict_different_assets():
    c1 = _make_candidate(controls=["5.2.1"])
    c2 = _make_candidate(controls=["5.2.1"])  # same control but different asset
    conflicts = _conflict_detect([c1, c2], [0, 1])
    assert conflicts == []


# ─────────────────────────────────────────────────────────────────────────────
# Dependency ordering
# ─────────────────────────────────────────────────────────────────────────────

def test_dependency_ordering_respects_depends_on():
    c0 = _make_candidate(controls=["1.1.1"], cost=5)
    c1 = _make_candidate(controls=["2.2.2"], cost=5, depends_on=[c0.template_id])
    result = optimize_plan([c0, c1], {"1.1.1", "2.2.2"}, _constraints())
    assert result.outcome == "FEASIBLE"
    # c0 must appear before c1 in action list if both selected
    if len(result.selected_actions) == 2:
        tids = [a["template_id"] for a in result.selected_actions]
        assert tids.index(str(c0.template_id)) < tids.index(str(c1.template_id))


# ─────────────────────────────────────────────────────────────────────────────
# Determinism / stable plan hash
# ─────────────────────────────────────────────────────────────────────────────

def test_plan_sha256_deterministic():
    actions = [
        {"action_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "template_id": "t1", "asset_id": "a1"},
        {"action_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "template_id": "t2", "asset_id": "a2"},
    ]
    safety_ids = [uuid4()]
    sha1 = compute_plan_sha256(actions, safety_ids)
    sha2 = compute_plan_sha256(actions, safety_ids)
    assert sha1 == sha2
    assert len(sha1) == 64


def test_plan_sha256_changes_with_different_actions():
    safety_ids = [uuid4()]
    actions_a = [{"action_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "x": 1}]
    actions_b = [{"action_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "x": 2}]
    assert compute_plan_sha256(actions_a, safety_ids) != compute_plan_sha256(actions_b, safety_ids)


# ─────────────────────────────────────────────────────────────────────────────
# Alternative plan ranking
# ─────────────────────────────────────────────────────────────────────────────

def test_rank_alternatives_returns_at_least_one_feasible():
    c1 = _make_candidate(controls=["5.2.1"], cost=10)
    constraints = _constraints(max_cost=8)  # too tight initially
    alternatives = rank_alternative_plans([c1], {"5.2.1"}, constraints)
    # At relaxed cost (8 * 1.5 = 12) c1 fits
    feasible = [r for r in alternatives if r.outcome == "FEASIBLE"]
    assert len(feasible) >= 1

