# Phase 1 results

## Delivered

- Provisional synchronous adapter SDK with typed fixture input, collected artifact, and
  parsed configuration boundaries.
- Offline synthetic fixture runner with a bounded Cisco IOS parser.
- Secure, weak, and unknown/partial fixtures, each with manifest and golden envelope.
- Exact source-byte SHA-256 before parsing; stable fixture URI and collection timestamp.
- Context-preserving multiple VTY blocks, configured SSH version, session timeout,
  remote syslog, and NTP server facts with line provenance.
- Structured CLI success/failure behavior for all Phase-1 command names.
- Optional dependency groups declared without importing or installing them for core use.

## Truthful status by related feature

| IDs | Status | Evidence / limit |
|---|---|---|
| M10, M11 | PARTIAL | Synthetic Cisco IOS fixture parsing only; no live/lab support |
| M12, M15 | PARTIAL | Offline fixture collection boundary only; no live transport |
| M20, M21, M31, M32 | PARTIAL | Configuration facts only; no central evaluation or operational proof |
| M22-M30, M33 | NOT_STARTED | No predicates or supported facts claimed |
| E10 | PARTIAL | Synthetic fixture replay, not general offline vendor assessment |
| E18 | PARTIAL | Read-only interface enforced; full audit workflow owned by Mandar |
| M37, E21-E25, I11-I16 | NOT_STARTED | Typed negative boundaries only |

All 88 IDs and their ownership remain recorded in `phase0-coverage.md`. Interfaces do
not make a feature DONE.

## Limits

- No network, credentials, device commands, writes, or raw configuration logging.
- Parser accepts only UTF-8 and rejects source files over 1 MiB by default.
- It recognizes only intentionally bounded syntax. Unsupported VTY declarations produce
  warnings; missing/ambiguous facts stay null.
- An NTP server line means configured only; `synchronized` remains null.
- SSH version does not imply key authentication.
- Syslog destination does not imply reachability.
- VTY configuration does not prove effective exposure or actual reachability.
- Fixture versions are illustrative and are not firmware compatibility evidence.
- No official CIS control IDs, mappings, findings, scores, or audit verdicts exist here.

## Validation

The final validation commands are recorded in the package README. Phase-1 completion
requires both pytest and Ruff to pass plus successful CLI fixture collection; actual
results are reported in the handoff response rather than asserted permanently here.
