# OpenSCAP and ComplianceAsCode integration

## XCCDF ingestion

Offline result ingestion enforces an 8 MiB default limit and rejects DTD/entity
declarations and malformed XML. It extracts benchmark/version, profile, TestResult
times, rule IDs and original result strings, and hashes the exact XML bytes.

Raw states remain distinct. Provisional shared mappings are:

| XCCDF result | Provisional shared status |
|---|---|
| `pass` | PASS |
| `fail` | FAIL |
| `notapplicable` | NOT_APPLICABLE |
| `error` | ERROR |
| `informational` | MANUAL_REVIEW |
| `unknown`, `notchecked`, `notselected`, `fixed`, unrecognized | NOT_ASSESSED |

`fixed` is not treated as PASS because Phase 3 does not perform or validate remediation.
The original XCCDF result is always retained.

## Explicit local assessment

The runner verifies that the requested profile exists and requires a matching platform
reference before executing:

```text
oscap xccdf eval --profile PROFILE --results OUTPUT CONTENT
```

No `--remediate` option is accepted or generated. Exit 0 means completed; exit 2 means
completed with noncompliant/failed/unknown/error results and is reported as
`COMPLETED_NONCOMPLIANT`; other exits are execution failure. Output must be in an
explicit existing directory. Tool version, content hash, profile and result hash are
retained.

This follows official OpenSCAP documentation for profile selection, XCCDF results and
the exit-2 noncompliance convention. Content is never downloaded or built automatically.
ComplianceAsCode/SCAP Security Guide content is not automatically equivalent to a CIS
Benchmark. Exact mappings require authorized content and validation.

References:

- https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html
- https://www.open-scap.org/getting-started/
- https://www.open-scap.org/security-policies/scap-security-guide/

Ubuntu 20.04 compatibility is explicit: no compatible content was available in this
environment, and 22.04 content is not substituted. Native collection remains available.
