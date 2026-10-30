# 88-feature ownership and source map

Source: supplied PRD v1, pages 6-9. All source requirement and acceptance text is retained in `feature-register.json`.

One accountable owner per feature; shared responsibility never grants permission to edit another owner's folders. R/A/C/I assignments are proposed for team review. Everyone is R or C where relevant; an empty I column is intentional. Product status UNTESTED means no product acceptance claim. Phase 0 DONE means only source registration is complete.

| ID | Feature | Domain | A | R | C | Product status | Source |
|---|---|---|---|---|---|---|---|
| M01 | Windows 11 | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M02 | Windows Server 2019 | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M03 | Ubuntu 20.04/22.04 | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M04 | RHEL 8/9 | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M05 | Fortinet firewall | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M06 | Cisco firewall | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M07 | Check Point firewall | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M08 | Sophos firewall | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M09 | Palo Alto firewall | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M10 | Cisco router | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M11 | Cisco switch | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M12 | Live collection | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M13 | Central multi-target audits | orchestration | Mandar | Mandar, Vidhi, Apoorva | - | UNTESTED | PRD p6 |
| M14 | OS collectors | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M15 | Network collectors | collection | Vidhi | Vidhi, Mandar | Apoorva | UNTESTED | PRD p6 |
| M16 | Deterministic rule engine | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p6 |
| M17 | Modular structured rule files | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p6 |
| M18 | Custom baselines | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p6 |
| M19 | Benchmark update maintenance | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p6 |
| M20 | Management plane security | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p6 |
| M21 | SSHv2, key auth, timeout | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M22 | Over-permissive ACLs | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M23 | Sensitive port exposure | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M24 | Shadowed rules | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M25 | Default-deny policy | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M26 | Unused switch ports | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M27 | Port security / MAC binding | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M28 | DHCP snooping | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M29 | Dynamic ARP inspection | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M30 | VLAN 1 management traffic | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M31 | Syslog forwarding | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M32 | NTP synchronization | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M33 | SNMP security | policy | Mandar | Mandar, Vidhi | Apoorva | UNTESTED | PRD p7 |
| M34 | Central GUI dashboard | dashboard | Apoorva | Apoorva, Mandar | Vidhi | UNTESTED | PRD p7 |
| M35 | Compliance/severity breakdown | results | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p7 |
| M36 | Expected vs actual findings | results | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p7 |
| M37 | Actionable remediation | results | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p7 |
| M38 | Reports and scale | reporting | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p7 |
| E01 | Asset inventory | inventory | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p7 |
| E02 | Authorized discovery | collection | Vidhi | Vidhi, Mandar, Apoorva | - | UNTESTED | PRD p7 |
| E03 | Tag/group assets | inventory | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p7 |
| E04 | Scheduled scans | orchestration | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p7 |
| E05 | Drift alerts | history | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E06 | Configuration snapshots | evidence | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E07 | Compliance trends | history | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E08 | Selective audits | orchestration | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E09 | Distributed workers | orchestration | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E10 | Offline config assessment | collection | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E11 | CIS profile selection | policy | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E12 | Manual-review workflow | policy | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E13 | Risk ranking | risk | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E14 | Policy exceptions | policy | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E15 | Role-based access control | identity | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E16 | Multi-factor authentication | identity | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E17 | Secrets vault | secrets | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E18 | Read-only audit mode | orchestration | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E19 | Application audit trail | evidence | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E20 | Policy version history | policy | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E21 | Approved auto- remediation | hardening | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E22 | Dry-run preview | simulation | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E23 | Approval workflow | approvals | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E24 | Backup/recovery | recovery | Vidhi | Vidhi, Mandar, Apoorva | - | UNTESTED | PRD p8 |
| E25 | Post-fix re-audit | verification | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p8 |
| E26 | Alerts/webhooks | integrations | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E27 | Ticket integrations | integrations | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E28 | Executive reporting | reporting | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p8 |
| E29 | Search/filter interface | dashboard | Apoorva | Apoorva, Mandar | Vidhi | UNTESTED | PRD p9 |
| E30 | External integration API | integrations | Mandar | Mandar, Apoorva | Vidhi | UNTESTED | PRD p9 |
| I01 | Infrastructure relationship graph | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I02 | Cross-device correlation | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I03 | Config-based path analysis | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I04 | Root-cause reasoning | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I05 | Evidence-backed risk explanation | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I06 | Minimal-change optimization | planning | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I07 | Alternative fix comparison | planning | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I08 | Cross-vendor planning | planning | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I09 | Remediation conflict checks | planning | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I10 | Change sequencing | planning | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I11 | Cross-layer what-if | simulation | Vidhi | Vidhi, Mandar, Apoorva | - | UNTESTED | PRD p9 |
| I12 | Service-safety contracts | approvals | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I13 | Blast-radius estimation | simulation | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I14 | Safety-gated execution | approvals | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I15 | Staged rollout | approvals | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I16 | Dual verification | verification | Vidhi | Vidhi, Mandar, Apoorva | - | UNTESTED | PRD p9 |
| I17 | Residual risk measurement | risk | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I18 | Proof-of-Hardening dossier | evidence | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I19 | Benchmark upgrade preview | policy | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
| I20 | Explainable coverage decisions | policy | Mandar | Mandar, Apoorva, Vidhi | - | UNTESTED | PRD p9 |
