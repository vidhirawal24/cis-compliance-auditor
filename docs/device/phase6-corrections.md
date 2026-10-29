# Phase 6 correctness corrections

This document supersedes conflicting Phase 6 examples and status claims in earlier
notes. Stable `DEV-Mxx-NNN` check IDs are internal. Their `feature_id` is the matching
project control M20-M33; E05/E06/E07/E08 were historical documentation mistakes, not
the predicate result mapping. `DEV-M21-001` remains stable and maps to M20 because it
checks HTTP management plane security.

- M20: `DEV-M20-001` needs declared or platform-verified VTY inventory; no universal
  0-15 range is assumed. `DEV-M21-001` maps to M20.
- M21: SSHv2, key-only authentication, and VTY timeout map to M21. Key-only PASS needs
  positive key, permitted-method, password-exclusion, and scope evidence. `login local`,
  generic AAA, or a pubkey chain alone is NOT_ASSESSED, not FAIL or PASS.
- M22-M25: broad source scope and sensitive ports are organizational policy parameters.
  The default monitored example includes 22, 23, 80, 443, 445, and 3389. A final deny
  does not erase earlier broad permits; unsupported ACL syntax is retained as unassessed.
- M26-M30: switch checks require collected switching capability and applicable role or
  inventory evidence; they are not inferred solely from the platform label.
- M31-M33: telemetry checks map to their corresponding M controls. A PASS for absence
  of legacy SNMP communities requires complete relevant SNMP configuration evidence.

## Import timestamp provenance

The former 2000-01-01 sentinel was removed. With unknown source capture time,
`facts.import.source_capture_timestamp` is null and `facts.import.imported_at` records
the import timestamp. The compatibility envelope still requires `collected_at`, so it
holds that labelled import time and `CAPTURE_TIMESTAMP_UNKNOWN` explicitly warns it is
not source-capture evidence. The shared canonical contract should add nullable source
capture time to remove this provisional compromise.

Evidence reference hashes are SHA-256 of the original bytes read before parsing. The
normalizer never claims its sanitized fact output has that hash. If a future storage
stage writes a sanitized artifact, it must record a separate sanitized-artifact hash.

## Vendor coverage

The evaluator is Cisco IOS/IOS-XE fact-subset only: `cisco_router` and devices with
explicit `capabilities.switching`. FortiOS, ASA/FTD/FMC, Check Point, Sophos, PAN-OS,
Linux, and Windows remain NOT_ASSESSED for these Cisco predicates. This is not a
complete multi-vendor firewall evaluator.

| Family | Phase 6 predicate coverage |
|---|---|
| Cisco IOS/IOS-XE router | M20-M25, M31-M33 where required facts are complete; switch controls need collected switching capability |
| Cisco IOS/IOS-XE switch | M20-M33 where capability, role, inventory, and complete evidence requirements are met |
| FortiOS / ASA / FTD-FMC / Check Point | NOT_ASSESSED by this Cisco-focused evaluator |
| Sophos / PAN-OS | NOT_ASSESSED by this Cisco-focused evaluator |
| Windows / Linux | NOT_ASSESSED by this network predicate evaluator |

## Validation

On 29 October 2026, the full device-engine suite was run with a fresh owned pytest
base temp directory: **244 passed, 0 failed, 0 skipped**. Ruff and `git diff --check`
also passed.
