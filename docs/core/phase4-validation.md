# Phase 4 Validation

29 October 2026, Python 3.12 on Windows.

- **Supabase Connectivity & Live PostgreSQL Orchestration**: Verified against live Supabase PostgreSQL database.
- **Alembic Head**: Migration revision `0005_policy_engine` applied; database at head.
- **Total Test Results**: **286 passed** (282 unit/contract/HTTP/interpreter tests + 4 live database integration tests). One upstream Starlette/httpx deprecation warning. Zero failures.
- **M16 Deterministic CIS Interpreter**: Evaluated with 8 allowlisted predicate operators (`equals`, `contains`, `regex`, `range`, `set_membership`, `cidr_contains`, `ordered_acl`, `xccdf_oval`). Verified that missing or uncollected evidence strictly results in `ERROR` and **NEVER defaults to PASS**. Verified in `test_phase4_policy_engine.py` and `test_live_phase4.py`.
- **M17 & M35 Accurate Scoring and Independent Coverage**: Tested server calculation of `assessed_compliance = PASS / (PASS + FAIL)`. Preserves full visibility of `NOT_APPLICABLE`, `MANUAL_REVIEW`, and `ERROR` without inflating compliance scores.
- **M18 Custom Baseline Overrides**: Tenants can customize parameters (e.g., maximum password age or failed attempt lockouts) for specific controls without modifying official CIS benchmark definitions. Verified in `test_policy_override_evaluation` and live scan execution.
- **M19 Supplementary OpenSCAP Bridge**: Ingests XCCDF XML benchmarks with XXE protections (external entity resolution prohibited). Explicitly marks imported definitions as `validated_scap_mapping` with non-equivalence disclaimers.
- **E11 & E12 Status Preservation & Manual Reviews**: Full preservation of audit outcome states. Manual reviews accept verifiable audit evidence references (`private://evidence/...`) and transition findings to `PASS` or `FAIL`.
- **E14 Time-Boxed Exceptions & Separation of Duties**: Exception requests are time-boxed with mandatory justification and review dates. Self-approval is strictly prevented by both business logic and database constraints.
- **E20 Determinism & ReDoS Protection**: Verified reproducible evaluation results and regex safety validator (`is_safe_regex`) preventing exponential backtracking.
- **I19 & I20 Benchmark Diff & Upgrade Preview**: Computes structured delta (`added_control_ids`, `removed_control_ids`, `modified_control_ids`) between benchmark versions (e.g., Ubuntu CIS v1 vs v2) and previews impact on target assets before upgrading baselines.

---

## Test Execution Summary

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache --junitxml=docs/core/phase4-tests.xml apps/api/tests
```

```
........................................................................ [ 25%]
........................................................................ [ 50%]
........................................................................ [ 75%]
......................................................................   [100%]
============================== warnings summary ===============================
infra\.venv-phase0\Lib\site-packages\fastapi\testclient.py:1
  StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
======================= 286 passed, 1 warning in 83.69s =======================
```

**Exit Gate Status**: Phase 4 deliverables fully verified. Deterministic CIS rule interpreter, SCAP bridge, custom baselines, manual assessment evidence, accurate scoring math, and upgrade diffs are operational and live-tested.

