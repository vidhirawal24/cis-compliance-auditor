# Vidhi Remediation Safety Audit

## Verdict

Production remediation is safely unavailable. The public CLI `execute` always returns `LIVE_WRITE_BLOCKED`. Existing execution success paths require deliberately injected test-only dependencies and executable templates; the shipped catalog remains preview-only.

## Gate review

| Safety property | Verified behavior | Readiness |
|---|---|---|
| Allowlisted actions | Typed templates/candidates bind action content and evidence | FIXTURE VERIFIED |
| Dry-run preview | Deterministic no-write preview and expected change | FIXTURE VERIFIED |
| Approval | Coordinator requires injected approval validation | FAKE-DEPENDENCY VERIFIED ONLY |
| Target/state freshness | Identity and fresh collection gates exist | FAKE-DEPENDENCY VERIFIED ONLY |
| Secrets | Provider boundary; no raw credential arguments/logging | DESIGN + TEST VERIFIED |
| Backup | Encrypted artifact interface and metadata binding | UNIT VERIFIED; provider/storage external |
| Simulation | Mandatory verdict gate supported | CUSTOM MODEL ONLY |
| Durable lock/journal | Required injected dependency | TEST DOUBLE ONLY |
| Timeout/partial failure | Coordinator states and reconciliation paths exist | UNIT VERIFIED |
| Rollback | Recovery specifications/compensation states exist | NOT LAB VERIFIED |
| Post-change verification | Separate configuration and service outcomes required | INJECTED PROVIDERS ONLY |
| Staged rollout | Later batches stop on failed gate | FAKE-DEPENDENCY VERIFIED ONLY |

## Security findings

- Safe default: no production write transport is reachable from the supported CLI.
- Candidate hashes are integrity bindings, not approvals or signatures.
- The engine does not validate Mandar-issued signed `ActionEnvelope` contracts because the shared contract package is absent.
- Backup encryption is a boundary requiring production key/vault integration; it is not evidence of deployed secure storage.
- Custom simulation understands only three Cisco preview effects. An unsupported or insufficient model must never be converted to safe.
- No Ansible Runner, vendor write API, PowerShell remediation, OpenBao, live rollback, or dual live verification is configured.

## Required production gates before enabling writes

1. Publish and contract-test the signed/expiring approval envelope.
2. Supply audited secrets, lock, durable journal, backup, executor, rollback, and independent verification providers.
3. Lab-validate every template against exact vendor/model/firmware combinations.
4. Require fresh identity/config hashes, simulation coverage, protected-management-path checks, and explicit deployment mode.
5. Exercise timeout, disconnect, partial commit, rollback failure, and manual-recovery procedures.
6. Keep raw browser-supplied commands and unapproved templates unreachable.

No destructive or configuration-changing operation was run during this audit.
