# Adapter matrix

All rows are required target families. Status distinguishes synthetic fixtures, local
smoke evidence, and authorized live lab testing. No central evaluation or remediation
is implemented here.

| Family | Implementation | Fixture tests | Live lab tests | Firmware / OS limits | Unavailable capabilities |
|---|---|---|---|---|---|
| Windows 11 Enterprise | PHASE2_PARTIAL | Secure synthetic capture | Local smoke attempted; identity denied | Requires Windows 11 caption, workstation ProductType and Enterprise edition | Effective domain policy, compliance evaluation, remediation |
| Windows 11 Standalone | PHASE2_PARTIAL | Weak standalone synthetic capture | None | Standalone is deployment context, not edition | Effective domain policy, compliance evaluation, remediation |
| Windows Server 2019 | PHASE2_PARTIAL | Unknown/access-denied synthetic capture | None | Requires Server ProductType and Server 2019 caption | Effective domain policy, compliance evaluation, remediation |
| Ubuntu 20.04 LTS | PHASE3_PARTIAL | Secure/weak/unknown native captures | None | Exact ID/version only; compatible SCAP content unavailable here | Live/lab proof, validated CIS mapping, remediation |
| Ubuntu 22.04 LTS | PHASE3_PARTIAL | Secure/weak/unknown native captures + synthetic XCCDF | None | Exact ID/version only; supplied content must prove compatibility | Live/lab proof, validated CIS mapping, remediation |
| RHEL 8 | PHASE3_PARTIAL | Secure/weak/unknown native captures | None | Exact `rhel` ID and major version; minor versions unvalidated | Live/lab proof, validated CIS mapping, remediation |
| RHEL 9 | PHASE3_PARTIAL | Secure/weak/unknown native captures | None | Exact `rhel` ID and major version; minor versions unvalidated | Live/lab proof, validated CIS mapping, remediation |
| Fortinet FortiOS | PHASE4_PARTIAL | Secure/weak/unknown | None | Illustrative 7.2 only; API matrix unverified | Live collection/evaluation/remediation |
| Cisco ASA | PHASE4_PARTIAL | Secure/weak/unknown | SSH mock only | Illustrative 9.18; real variants unverified | Live proof/evaluation/remediation |
| Cisco FTD/FMC | PHASE4_PARTIAL | Secure/weak/unknown | None | Illustrative 7.4; FMC API matrix unverified | Live collection/deployment proof/evaluation |
| Check Point | PHASE4_PARTIAL | Secure/weak/unknown | None | Illustrative R81.20; Gaia separate/unavailable | Live collection/install proof/evaluation |
| Sophos Firewall | PHASE5_PARTIAL | API-shaped XML secure/weak/unknown | None | XML 1905.2 subset only | Live collection/complete syntax/evaluation |
| Palo Alto PAN-OS | PHASE5_PARTIAL | XML secure/weak/unknown | None | 10.2/11.0 local vsys; no Panorama | Live collection/inheritance/evaluation |
| Cisco router | PHASE6_PARTIAL | IOS/IOS-XE text secure/weak/unknown + offline import | None | IOS 15, IOS-XE 16/17 subset | Live collection/effective exposure/remediation |
| Cisco managed switch | PHASE6_PARTIAL | IOS-XE text/show secure/weak/unknown + offline import | None | IOS 15, IOS-XE 16/17; NX-OS rejected | Live collection/role evaluation/remediation |

In Phase 6, `cisco_router` and `cisco_managed_switch` support deterministic predicate evaluation
for M20–M33 (`evaluate_network_controls`) and offline configuration snapshot import (`import_offline_file`).
M10 and M11 remain PARTIAL: offline snapshot parsing and predicate evaluation do not constitute
live-lab vendor support.

The predicate engine evaluates VTY transport, SSH version, key authentication, session timeout,
ACL rules and shadowing, switch port shutdown/security, DHCP snooping, DAI, VLAN 1 separation,
syslog, NTP configuration and operational synchronization, and SNMPv3 security levels. It does
not establish effective network exposure across uncollected paths, nor perform remediation.

Phase 7 adds only fixture-tested Cisco IOS/IOS-XE remediation preparation: three no-write
preview templates, conditional recovery specifications, and local encrypted-artifact boundary.
No vendor has live execution, live backup, or tested rollback support.

Phase 9 adds a vendor-neutral, fake-device-tested coordinator only. It provides no live execution
transport, durable worker lock, approval system, vendor recovery integration, or validated rollout.

Phase 8 is vendor-neutral offline simulation over normalized input, not a vendor adapter.
The custom model has fixture-tested Cisco IOS/IOS-XE candidate effects only; it does not
establish any firewall-vendor service behavior. Batfish snapshot/service integration is open.
reachability, NTP synchronization, key authentication, or compliance.

Windows offline ingestion and the fixed local PowerShell path are implemented. The local
smoke ran once without elevation but CIM OS identity was denied, so no supported-host
claim was made. WinRM is implemented with HTTPS/certificate validation and mocked
failure tests, but has no authorized lab evidence and remains live-untested.

Linux local collection and SSH are implemented but not live-tested: this host is Windows,
WSL enumeration was denied, and no authorized SSH lab was supplied. XCCDF ingestion is
fixture-tested. Local OpenSCAP execution is mock-tested only because `oscap` and suitable
content/profile are absent. Ubuntu 20.04 content is never substituted with 22.04 content.

Phase 4 firewall parsers preserve contexts, rule order, objects, bindings, NAT, and
deployment uncertainty. No firewall family has authorized live-lab compatibility proof.
