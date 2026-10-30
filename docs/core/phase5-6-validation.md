# Phase 5 & 6 Validation

30 October 2026, Python 3.12 on Windows.

- **Supabase Connectivity & Live PostgreSQL Orchestration**: Verified against live Supabase PostgreSQL database.
- **Alembic Head**: Migration revision `0006_reports_and_graph` applied; database at head.
- **Total Test Results**: **299 passed** (294 unit/contract/HTTP/graph tests + 5 live database integration tests). One upstream Starlette/httpx deprecation warning. Zero failures.
- **M36 & E29 Canonical Findings Persistence**: Verified scan results transition into persistent `cisguard.findings` rows with severity classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and remediation pointers.
- **M38 & E28 Multi-Format Report Consistency**:
  - Tested that all four report formats (JSON, RFC 4180 CSV, HTML, and PDF) produce identical outcome totals (`pass_count`, `fail_count`, `assessed_compliance_pct`, `total_findings`) derived from the exact same underlying canonical data.
  - Tested ReportLab fallback when WeasyPrint system GTK libraries are absent, ensuring valid `%PDF-` document output across platforms.
- **M38 Authorized Signed Downloads**: HMAC-SHA256 signature validation implemented with time-limited expirations for secure report artifact retrieval.
- **E06, E07, M35, M37 Trends & Executive Dashboards**: Verified dashboard aggregations and historical compliance trend calculations.
- **E05, E26, E27, E30 Webhooks & Ticketing Adapters**:
  - Verified HMAC webhook payload signing (`X-CISGuard-Signature`), delivery IDs, exponential backoff retries, and deduplication records in `cisguard.notifications`.
  - Verified Jira, ServiceNow, and Generic ticket transformation interfaces.
- **I01, I03 NetworkX Security Graph Builder**: Verified generation of multi-layer security topology containing asset, interface, subnet, route, rule, service, and finding nodes with typed edges (`hosted_on`, `attached_to`, `routes_to`, `allows`, `denies`, `depends_on`, `violates`).
- **I02, I05 Graph Reachability & Incomplete Evidence**: Verified bidirectional graph path traversal evaluating intermediate firewall allow/deny rules and flagging topology missingness.
- **E13, I02, I04 Risk Scenario Correlation & Negative Testing**:
  - Verified multi-host risk scenario correlation (lateral movement, perimeter exposure, blast radius) with full explainability chains (`source_finding_ids`, `evidence_refs`).
  - **Negative Test Pass**: Rejection of false correlations when firewall rules block traffic between affected assets.
- **Determinism**: Verified stable, deterministic sorting of all graph nodes, edges, and risk scenarios across successive runs.

---

## Test Execution Summary

```powershell
$env:CISGUARD_LIVE_TESTS='1'
& infra/.venv-phase0/Scripts/python.exe -m pytest -q -o cache_dir=apps/api/.pytest_cache --junitxml=docs/core/phase5-6-tests.xml apps/api/tests
```

```
........................................................................ [ 24%]
........................................................................ [ 48%]
........................................................................ [ 72%]
........................................................................ [ 96%]
...........                                                              [100%]
============================== warnings summary ===============================
infra\.venv-phase0\Lib\site-packages\fastapi\testclient.py:1
  StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
======================= 299 passed, 1 warning in 106.85s =======================
```

**Exit Gate Status**: Phase 5 and Phase 6 deliverables fully verified. Canonical findings API, multi-format reports with identical totals, HMAC signed artifact downloads, ticketing adapters, webhooks, NetworkX security graph builder, reachability traversal, risk scenario correlation, and false correlation rejection are operational and live-tested.

