# Phase 3 handoff

## Mandar can integrate now

- Replay 12 deterministic Linux captures and receive canonical `FactsEnvelope` objects.
- Use strict Ubuntu 20.04/22.04 and RHEL 8/9 identity classification.
- Invoke explicit local or SSH native collection with source-state/error preservation.
- Inject a vault-backed `SSHSecretProvider`; unknown host keys are rejected.
- Ingest supplied XCCDF result XML safely and retain exact raw states/hashes.
- Optionally run local `oscap` assessment with prevalidated profile/platform content and
  distinguish exit 2 noncompliance from execution failure.

## Evidence limits

All Linux versions are fixture-tested only. Local collection was skipped on the Windows
host; WSL enumeration was access-denied. SSH has mock tests but no authorized lab.
OpenSCAP execution has mock tests but no installed tool or suitable real content.
Ubuntu 20.04 SCAP coverage is unavailable and is not substituted.

Mandar still owns authorized benchmark mapping, applicability, central verdicts,
exceptions, findings and scoring. No fixture or XCCDF importer makes M03/M04/M14 DONE.

## Integration questions

- Confirm shared source-state/provenance models and supplemental artifact envelopes.
- Confirm async worker wrapping and production SSH/OpenBao secret-provider signature.
- Confirm private artifact storage/encryption and result output ownership.
- Supply authorized Ubuntu 20.04/22.04 and RHEL 8/9 labs plus known_hosts.
- Supply installed OpenSCAP versions and platform-compatible authorized content/profile.
- Supply authorized CIS benchmark versions before exact rule mappings.

Phase 4 now provides firewall fixture adapters, but simulation, remediation, and Linux
writes remain unstarted. Mandar must dispatch by exact platform and must not score
unknown deployment, unresolved objects, permission denial, or missing Gaia as secure.
Phase 3 Linux NTP and SNMP collection gaps remain open.

Phase 5 adds `collect_remaining_fixture` and raw Sophos, PAN-OS, and Cisco parsers.
Mandar must preserve candidate/running state, interface operational/configured state,
designated-unused nullability, and VLAN-specific snooping/DAI scope. Phase 5 implements
no live transport, evaluator, simulation, or remediation. NX-OS and Panorama remain unsupported.

## Phase 6 handoff: Network Predicates & Offline Import

### Mandar can integrate now
- Ingest offline device configurations and snapshots using `import_offline_file()`.
- Evaluate 21 device predicates across M20–M33 via `evaluate_network_controls()`.
- Pass typed `NetworkControlPolicy` parameters with required organizational thresholds.
- Consume structured `PredicateResult` instances with actual vs. expected evidence, error codes, and limitations.

### Clear boundaries preserved
- Mandar owns mapping internal check IDs (`DEV-Mxx-NNN`) to official CIS benchmark rules.
- Mandar owns central policy packs, tenant exceptions, findings persistence, and overall compliance scoring.
- Device-engine does NOT calculate compliance percentages or act as a second central policy engine.

### Remaining gaps and limitations
- Linux and Windows host collection gaps for NTP and SNMP remain open.
- Live network device collection is unstarted; all tests are offline or fixture-based.
- Remediation operations (`execute`) remain blocked with `LIVE_WRITE_BLOCKED`.
- NX-OS, Panorama, and Check Point Gaia remain unsupported.
- Complex ACL constructs (IPv6, object-groups, dynamic rules, NAT) are explicitly unassessed.

## Phase 7 handoff

Mandar consumes candidates but owns approval, authorization, persistence, planning, and
OpenBao-backed cipher implementation. Candidate hashes are content bindings, not signatures.
Live execution and recovery execution remain blocked; no backup is considered restorable
merely because a local artifact exists.

See `phase6-corrections.md` before Phase 7. It records corrected M20-M33 feature
mapping, VTY/key-only uncertainty, import timestamp provenance, and Cisco-only predicate scope.

## Phase 8 handoff

Mandar may call `simulate()` / `simulate_what_if()` with exact offline facts, a generated
candidate, contracts, hashes, and (for path claims) explicit modeled topology availability.
Consume `SAFE_IN_MODEL` only within its reported scope. Aggregate precedence is
`VIOLATES_CONTRACT` > `UNSUPPORTED` > `INSUFFICIENT_EVIDENCE` > `SAFE_IN_MODEL`.

Open gaps: no Batfish snapshot/service integration, no NAT/authentication/stateful-flow model,
no real reachability proof, no live connection, no execution, and no vendor-wide firewall claim.
