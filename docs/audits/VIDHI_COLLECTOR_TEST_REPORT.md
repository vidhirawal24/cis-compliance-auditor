# Vidhi Collector Test Report

Audit date: 2026-10-30  
Environment: Windows, Python 3.14.6 virtual environment, Pydantic 2.14.1, pytest 9.2.0.

## Commands and results

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest --basetemp=.pytest-audit-final -p no:cacheprovider` | 266 passed before repair in 14.37s |
| `.venv\Scripts\python.exe -m pytest --basetemp=.pytest-audit-postfix -p no:cacheprovider` | 267 passed after repair in 15.16s |
| `.venv\Scripts\python.exe -m ruff check .` | passed, no findings |
| `git diff --check` | passed |
| `.venv\Scripts\python.exe -m cisguard_device capabilities` | valid JSON; exposed the fixture metadata defect subsequently repaired |
| `.venv\Scripts\python.exe -m cisguard_device self-test` | exit 0; valid synthetic `FactsEnvelope` |

After the metadata repair, the complete suite and Ruff were rerun successfully. No live collection or write command was executed.

## Coverage verified from tests and fixtures

- Canonical models, UTC validation, hashes, structured errors, and serialization.
- Fixture path traversal, size, encoding, platform mismatch, malformed input, and expected-output checks.
- Windows offline classification, partial/denied evidence, local subprocess failures, WinRM TLS/secrets/error redaction.
- Linux distro/version classification, local/SSH failures, strict host keys, source uncertainty, and 12 OS fixtures.
- Safe XCCDF parsing, state retention, unsafe XML, profile/platform mismatch, and `oscap` runner exit behavior.
- Firewall capture parsing, pagination/object resolution, HTTPS validation, ASA command allowlist, and transport failures.
- Sophos, PAN-OS, Cisco router/switch fixture parsing and secret redaction.
- M20-M33 predicate PASS/FAIL/NOT_ASSESSED/NOT_APPLICABLE behavior and incomplete-capture downgrades.
- Offline import provenance and sanitization.
- Candidate/preview binding, backup cipher boundary, custom simulation contracts, fake execution gates, verification, and drift.
- Mandar consumer and sample-payload smoke tests against the provisional local schema.

## Tests not possible or not configured

- No live vendor/VM/hardware tests, GNS3/EVE-NG tests, or production credential flow.
- No OpenSCAP executable or pinned ComplianceAsCode corpus.
- No Batfish service or `pybatfish` tests.
- No `packages/contracts/v1` contract suite or real Mandar worker test.
- No configured mypy/pyright, Bandit, dependency vulnerability scan, or Hypothesis suite.
- No real backup restore, rollback, post-fix re-audit, or active service reachability test.

## Interpretation

The suite provides good confidence in deterministic offline behavior and fail-closed boundaries. It cannot establish vendor interoperability, benchmark correctness, operational reachability, or production remediation safety.
