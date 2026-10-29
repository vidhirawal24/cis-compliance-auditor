# Phase 2 results

## Implementation status

| Capability | Status | Evidence |
|---|---|---|
| Windows offline JSON ingestion | IMPLEMENTED / FIXTURE_TESTED | Windows 11 Enterprise secure, standalone weak, Server 2019 partial fixtures |
| Windows classification | IMPLEMENTED / FIXTURE_TESTED | ProductType plus caption/version/edition/context tests |
| Fixed local PowerShell collection | IMPLEMENTED / SMOKE ATTEMPTED | One non-elevated run; several sources denied/error |
| Optional WinRM | IMPLEMENTED / MOCK-TESTED / LIVE-UNTESTED | HTTPS/certificate guard and redacted failure tests; no authorized lab |
| Central CIS evaluation/scoring | NOT_IMPLEMENTED | Mandar-owned boundary |
| Windows remediation | NOT_IMPLEMENTED | Writes remain blocked |

M01, M02 and M14 are `PARTIAL`, not DONE. Fixture evidence and one privilege-limited
local attempt do not establish full platform or benchmark coverage.

## Local smoke result

The development host exposed registry metadata as `Windows 10 Home Single Language`,
DisplayVersion `26H2`, build `26300`, EditionID `CoreSingleLanguage`; PowerShell was
5.1.26100.9711. This metadata is internally inconsistent with the target-family labels,
and the fixed collector's authoritative CIM OS query was denied. The collector therefore
returned nonzero `WINDOWS_IDENTITY_UNAVAILABLE: OS identity unavailable` rather than
guessing a platform.

Source outcomes from that single run:

- Success: account policy, permissions, selected registry settings, selected services.
- Denied: OS identity, domain membership, firewall profiles.
- Error: audit policy and local security-policy export.

No raw real-host capture was tracked or included in documentation.

## Fact groups produced

`os`, `deployment`, `account_policy`, `local_security_policy`, `audit_policy`,
`firewall_profiles`, `services`, `registry_settings`, and `permissions`. Every group has
collection state, value or explicit null, source identity/timestamp/exit status, error
code and limitation where applicable.

## Validation

Automated tests cover fixture normalization, hashes, supported/unsupported
classification, workstation/server distinction, standalone context, access denial,
missing registry values, malformed/contradictory captures, locale uncertainty,
subprocess timeout/nonzero/malformed JSON, WinRM safety/error redaction and CLI exits.
Existing Phase-0 and Cisco fixture behavior remains covered.
