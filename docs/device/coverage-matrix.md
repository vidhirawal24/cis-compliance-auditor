# Device-engine coverage matrix

| Family | Accepted input / identity | Predicate & remediation scope | Validation / known gap |
|---|---|---|---|
| Windows 11 Enterprise, Standalone, Server 2019 | Synthetic PowerShell-shaped capture; strict product identity | Facts only; no network predicates/remediation | Fixture tests; local PowerShell smoke privilege-denied; WinRM mock only |
| Ubuntu 20.04/22.04, RHEL 8/9 | Native synthetic capture; exact OS/version | Facts/XCCDF ingestion only | Fixture/mock; no live SSH/OpenSCAP lab or CIS mapping |
| FortiOS, ASA, FTD/FMC, Check Point | Vendor-shaped offline captures | Facts only | Fixture/mock parsers; no live API/SSH proof |
| Sophos, PAN-OS | XML vendor-shaped sources | Facts only | Fixture parsers; no Panorama/live support |
| Cisco router, managed switch | IOS/IOS-XE bounded config/show text | Cisco-only M20–M33 predicates; three preview-only templates; custom simulation | Fixture-tested; no live network collection, execution, Batfish, or verified rollback |

## Handoff labels and blockers

| Family | Adapter / capability labels | Dependencies and blockers |
|---|---|---|
| Windows 11 Enterprise/Standalone, Server 2019 | FIXTURE_TESTED; local PowerShell implemented; WinRM UNTESTED | `pywinrm` optional; Enterprise applicability UNTESTED. Windows 11 Home is collection-only diagnostic and benchmark UNSUPPORTED. |
| Ubuntu/RHEL | FIXTURE_TESTED; local/SSH collector implemented but UNTESTED live | `paramiko` optional; no authorized lab, OpenSCAP content or CIS mapping. |
| FortiOS/ASA/FTD/Check Point | FIXTURE_TESTED; ASA SSH mock-tested; other live APIs BLOCKED | Missing authorized endpoint/version evidence and labs. |
| Sophos/PAN-OS | FIXTURE_TESTED vendor-shaped XML; live UNSUPPORTED | No live transport, Panorama/inheritance evidence. |
| Cisco router/switch | FIXTURE_TESTED; Cisco M20-M33 predicate evidence; PREVIEW_ONLY remediation | No live transport/lab, Batfish, production approval/vault/restore or trusted live verification. |

All families retain unsupported/unknown semantics. Simulation is bounded to local HTTP, VTY timeout,
and explicitly modeled interface paths. Backups require an injected authenticated cipher; execution
uses fake-device tests only. Verification is offline/synthetic and requires injected recollection
and trusted outcome providers.
