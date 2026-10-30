# Vidhi Platform Support Matrix

Audit date: 2026-10-30. `FIXTURE VERIFIED ONLY` means deterministic synthetic replay passed; it is not vendor/model/firmware certification.

| Platform | Overall classification | Collection/authentication | Parsing and normalized evidence | CIS/remediation/simulation limits |
|---|---|---|---|---|
| Windows 11 Enterprise | FIXTURE VERIFIED ONLY | Offline fixture; local PowerShell implemented; HTTPS WinRM with injected secrets and certificate checks is mock-tested | Secure fixture and explicit partial-source states | No official CIS mapping; no writes; custom simulation not Windows-aware |
| Windows 11 Standalone | FIXTURE VERIFIED ONLY | Same transport boundary; weak standalone fixture | Deployment context and Windows fact groups normalized | Same limits; no authorized live target |
| Windows Server 2019 | FIXTURE VERIFIED ONLY | Same transport boundary; only unknown/partial fixture | Server classification and missing evidence represented | Fixture corpus lacks secure/weak server pair |
| Ubuntu 20.04 LTS | FIXTURE VERIFIED ONLY | Offline fixture; local and strict-host-key SSH implemented but not lab-run | Secure/weak/unknown fixtures and source states | `oscap`/compatible CaC content unavailable; no CIS mapping |
| Ubuntu 22.04 LTS | FIXTURE VERIFIED ONLY | Same | Secure/weak/unknown fixtures | Same limits |
| RHEL 8 | FIXTURE VERIFIED ONLY | Same | Secure/weak/unknown fixtures including SELinux facts | Same limits |
| RHEL 9 | FIXTURE VERIFIED ONLY | Same | Secure/weak/unknown fixtures including SELinux facts | Same limits |
| Fortinet FortiOS | FIXTURE VERIFIED ONLY | Offline capture only; live REST/SSH contract blocked | Ordered rules/objects and evidence normalized from synthetic JSON | No live API, lab, remediation, or Batfish proof |
| Cisco ASA | FIXTURE VERIFIED ONLY | Offline capture; fixed allowlist SSH collector mock-tested with host-key checks | Synthetic secure/weak/unknown parsing | No authorized lab; no FTD equivalence claim |
| Cisco FTD/FMC | FIXTURE VERIFIED ONLY | Offline FMC-shaped capture; live endpoint contract blocked | Synthetic capture parsing | No device/FMC lab or write path |
| Check Point Management | FIXTURE VERIFIED ONLY | Offline management-shaped capture; live API/Gaia blocked | Synthetic capture parsing and object resolution | No lab, policy-install state validation, or remediation |
| Sophos Firewall | FIXTURE VERIFIED ONLY | Offline XML only | Synthetic secure/weak/unknown XML parsing | No live API, exact deployed firmware proof, or remediation |
| Palo Alto PAN-OS | FIXTURE VERIFIED ONLY | Offline XML only | Local-vsys synthetic XML parsing | No Panorama/live committed-state validation or remediation |
| Cisco router IOS/IOS-XE | FIXTURE VERIFIED ONLY | Offline text/config import only | Synthetic config/show parsing; M20-M33 predicate subset | No Netmiko/Scrapli live path or firmware lab; custom model covers three actions only |
| Cisco managed switch IOS/IOS-XE | FIXTURE VERIFIED ONLY | Offline text/config import only | VLAN/interface/security facts and predicates from fixtures | No live transport; NX-OS unsupported; inventory applicability remains caller-supplied |

## Cross-platform behavior

- Credentials are injected through provider protocols or environment-backed development providers; passwords are not CLI arguments.
- Remote Windows requires HTTPS and certificate validation; Linux/ASA SSH reject unknown host keys.
- Timeout and structured error paths are tested, but retry orchestration is not a uniform cross-vendor feature.
- Evidence contains identifiers, timestamps, source identity, SHA-256, facts, explicit errors, and capability lists.
- No platform is `LIVE VERIFIED`. No live lab was authorized or available during this audit.
