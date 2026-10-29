# Phase 3 results

## Status

| Capability | Status |
|---|---|
| 12 Linux fixtures (secure/weak/unknown x four targets) | IMPLEMENTED / TESTED |
| Exact Ubuntu/RHEL detection | IMPLEMENTED / TESTED |
| Fixed local native collector | IMPLEMENTED / NOT RUN (Windows host) |
| Paramiko SSH collector | IMPLEMENTED / MOCK-TESTED / LIVE-UNTESTED |
| Safe XCCDF ingestion | IMPLEMENTED / TESTED |
| Local OpenSCAP runner | IMPLEMENTED / MOCK-TESTED / TOOL-CONTENT UNAVAILABLE |
| CIS rule mapping/evaluation/scoring | NOT IMPLEMENTED / Mandar-owned |
| Remediation | NOT IMPLEMENTED / BLOCKED |

M03, M04 and M14 are PARTIAL. Applicable M20/M21/M31 evidence is PARTIAL. M32/M33 need
additional native facts and remain not started for Linux-specific coverage.

## Validation and smoke decision

The full suite covers distro/version/derivative identity, missing identity, all fixtures,
exact hashes, source denial/missing commands, configured/runtime differences, SSH Match
uncertainty, firewall missing versus disabled, SELinux divergence, local subprocess
failures, SSH host-key/transport rejection, every XCCDF state, unsafe XML, profile and
platform mismatch, missing oscap, and exit 0/2/failure handling.

No live Linux collection ran. The execution host is Windows and WSL distribution
enumeration returned `Wsl/EnumerateDistros/Service/E_ACCESSDENIED`; therefore no actual
supported Linux identity could be established. `oscap` was not installed and no suitable
local content/profile was supplied. No install, WSL enablement or download was attempted.
