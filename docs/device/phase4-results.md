# Phase 4 results

Phase 4 adds deterministic, read-only firewall capture replay for FortiOS, Cisco ASA,
Cisco FTD through FMC, and Check Point Management. It stops before evaluation,
simulation, exposure inference, scoring, or remediation.

## Verification

- Full suite: `97 passed`
- Ruff: `All checks passed!`
- Corpus: 12 synthetic captures (secure, weak, unknown per family)
- Live lab: none; no model or firmware compatibility claim

M05, M06, M07, M15, and initial M20-M25 remain **PARTIAL**. Complete acceptance
depends on authenticated vendor labs, encrypted artifact storage, central evaluation,
and deployment-state integration. All 88 feature IDs remain in product scope.

ASA SSH uses a fixed show-command allowlist and strict host-key checking; behavior is
mock-tested only. FortiOS, FMC, and Check Point live API collectors are blocked because
public material did not establish every versioned endpoint/field needed for the fact set.
No plausible endpoint set was invented.
