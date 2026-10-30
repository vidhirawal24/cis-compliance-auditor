# Later-phase engineering checklists

These are local development instructions, not installed skills or runtime AI components. Every ticket and acceptance test must cite Mxx/Exx/Ixx and status DONE/PARTIAL/BLOCKED/UNTESTED with evidence. Do not mark a feature DONE for a contract or UI mock.

| Checklist | Required review |
|---|---|
| 88-feature registry | Exact stable IDs, source requirement, owner, supported versions, positive/negative tests, real evidence, known limitations |
| Supabase tenant security | JWT claims, MFA, least privilege, backend authorization, USING/WITH CHECK, composite tenant FK, storage/Realtime/RPC negative tests |
| CIS rule authoring | Rights/source/version/profile; safe operators; applicability; unknown/error distinction; deterministic fixtures; immutable override history |
| Graph correlation | Evidence-backed nodes/edges, explicit topology gaps, deterministic explanation and source findings; no inferred validated paths without semantics |
| Optimizer constraints | Vetted firmware-specific candidates, hard safety/availability constraints, dependency graph, feasible/UNSAT cases, reproducible objective |
| Safe approvals | Exact plan/baseline hash, non-self approver, active scope/MFA, expiry, backup/recovery, mandatory contracts, staged stop gates |
| Proof dossier | Before/after hashes, benchmark/evaluator versions, approvals, events, fresh compliance and service evidence, residual risk, signature verification |
| Audit/report consistency | PASS/(PASS+FAIL), explicit coverage and null denominator, exceptions remain overlays, identical PDF/HTML/CSV/JSON totals |

CI must run contract regeneration check, schema/OpenAPI validation and negative semantic tests before consumer builds. Later CI adds Ruff/mypy, secret scanning, SAST, dependency/container audits, authorized integration testing and performance measurements. The Phase 0 environment is not the runtime dependency lock for those services.
