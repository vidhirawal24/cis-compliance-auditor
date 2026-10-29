# Phase 0 feature coverage

Status vocabulary: `INTERFACE_ONLY` means this foundation defines an integration
boundary but does not implement the feature. `NOT_STARTED` means no implementation or
test evidence exists. Nothing in this table is `DONE`.

Ownership is copied from the Vidhi Parallel Development Guide's frozen 88-feature
ownership table. “Interface/review” is Vidhi's role, not shared primary ownership.

| ID | Feature | Primary owner | Vidhi role | Phase 0 status |
|---|---|---|---|---|
| M01 | Windows 11 | Vidhi | PRIMARY | NOT_STARTED |
| M02 | Windows Server 2019 | Vidhi | PRIMARY | NOT_STARTED |
| M03 | Ubuntu 20.04/22.04 | Vidhi | PRIMARY | NOT_STARTED |
| M04 | RHEL 8/9 | Vidhi | PRIMARY | NOT_STARTED |
| M05 | Fortinet firewall | Vidhi | PRIMARY | NOT_STARTED |
| M06 | Cisco firewall | Vidhi | PRIMARY | NOT_STARTED |
| M07 | Check Point firewall | Vidhi | PRIMARY | NOT_STARTED |
| M08 | Sophos firewall | Vidhi | PRIMARY | NOT_STARTED |
| M09 | Palo Alto firewall | Vidhi | PRIMARY | NOT_STARTED |
| M10 | Cisco router | Vidhi | PRIMARY | NOT_STARTED |
| M11 | Cisco switch | Vidhi | PRIMARY | NOT_STARTED |
| M12 | Live configuration collection | Vidhi | PRIMARY | INTERFACE_ONLY |
| M13 | Central multi-target audits | Mandar | Interface / review | NOT_STARTED |
| M14 | OS collectors | Vidhi | PRIMARY | INTERFACE_ONLY |
| M15 | Network collectors | Vidhi | PRIMARY | INTERFACE_ONLY |
| M16 | Deterministic CIS evaluation | Mandar | Interface / review | NOT_STARTED |
| M17 | Modular YAML/JSON/XML rules | Mandar | Interface / review | NOT_STARTED |
| M18 | Custom baselines | Mandar | Interface / review | NOT_STARTED |
| M19 | Benchmark update maintenance | Mandar | Interface / review | NOT_STARTED |
| M20 | Management plane security | Vidhi | PRIMARY | NOT_STARTED |
| M21 | SSHv2/key authentication/timeout | Vidhi | PRIMARY | NOT_STARTED |
| M22 | Over-permissive ACLs | Vidhi | PRIMARY | NOT_STARTED |
| M23 | Sensitive-port exposure | Vidhi | PRIMARY | NOT_STARTED |
| M24 | Shadowed rules | Vidhi | PRIMARY | NOT_STARTED |
| M25 | Default-deny policy | Vidhi | PRIMARY | NOT_STARTED |
| M26 | Unused switch ports | Vidhi | PRIMARY | NOT_STARTED |
| M27 | Port security / MAC binding | Vidhi | PRIMARY | NOT_STARTED |
| M28 | DHCP snooping | Vidhi | PRIMARY | NOT_STARTED |
| M29 | Dynamic ARP inspection | Vidhi | PRIMARY | NOT_STARTED |
| M30 | VLAN 1 management traffic | Vidhi | PRIMARY | NOT_STARTED |
| M31 | Syslog forwarding | Vidhi | PRIMARY | NOT_STARTED |
| M32 | NTP synchronization | Vidhi | PRIMARY | NOT_STARTED |
| M33 | SNMP security | Vidhi | PRIMARY | NOT_STARTED |
| M34 | Central GUI dashboard | Apoorva | Interface / review | NOT_STARTED |
| M35 | Compliance/severity breakdown | Apoorva | Interface / review | NOT_STARTED |
| M36 | Expected vs actual finding | Apoorva | Interface / review | NOT_STARTED |
| M37 | Actionable remediation | Vidhi | PRIMARY | INTERFACE_ONLY |
| M38 | PDF/HTML/CSV/JSON reports and scale | Mandar | Interface / review | NOT_STARTED |
| E01 | Asset inventory | Mandar | Interface / review | NOT_STARTED |
| E02 | Authorized discovery | Mandar | Interface / review | NOT_STARTED |
| E03 | Asset tagging/grouping | Mandar | Interface / review | NOT_STARTED |
| E04 | Scheduled scans | Mandar | Interface / review | NOT_STARTED |
| E05 | Configuration drift alerts | Vidhi | PRIMARY | NOT_STARTED |
| E06 | Configuration snapshots | Mandar | Interface / review | NOT_STARTED |
| E07 | Compliance trends | Mandar | Interface / review | NOT_STARTED |
| E08 | Selective audits | Mandar | Interface / review | NOT_STARTED |
| E09 | Distributed workers | Mandar | Interface / review | NOT_STARTED |
| E10 | Offline configuration assessment | Vidhi | PRIMARY | NOT_STARTED |
| E11 | CIS Level 1/2 profiles | Mandar | Interface / review | NOT_STARTED |
| E12 | Manual review workflow | Mandar | Interface / review | NOT_STARTED |
| E13 | Risk-based prioritization | Mandar | Interface / review | NOT_STARTED |
| E14 | Policy exceptions | Mandar | Interface / review | NOT_STARTED |
| E15 | Role-based authorization | Mandar | Interface / review | NOT_STARTED |
| E16 | Multi-factor authentication | Mandar | Interface / review | NOT_STARTED |
| E17 | Device credential vault | Mandar | Interface / review | NOT_STARTED |
| E18 | Read-only audit mode | Mandar | Interface / review | INTERFACE_ONLY |
| E19 | Application audit trail | Mandar | Interface / review | NOT_STARTED |
| E20 | Policy version history | Mandar | Interface / review | NOT_STARTED |
| E21 | Approved auto-remediation | Vidhi | PRIMARY | NOT_STARTED |
| E22 | Dry-run preview | Vidhi | PRIMARY | NOT_STARTED |
| E23 | Approval workflow | Mandar | Interface / review | NOT_STARTED |
| E24 | Backup/recovery | Vidhi | PRIMARY | NOT_STARTED |
| E25 | Post-fix re-audit | Vidhi | PRIMARY | NOT_STARTED |
| E26 | Alerts/webhooks | Mandar | Interface / review | NOT_STARTED |
| E27 | Ticket integrations | Mandar | Interface / review | NOT_STARTED |
| E28 | Executive reporting | Mandar | Interface / review | NOT_STARTED |
| E29 | Search/filter interface | Apoorva | Interface / review | NOT_STARTED |
| E30 | External integration API | Mandar | Interface / review | NOT_STARTED |
| I01 | Infrastructure relationship graph | Mandar | Interface / review | NOT_STARTED |
| I02 | Cross-device correlation | Mandar | Interface / review | NOT_STARTED |
| I03 | Configuration-based path analysis | Mandar | Interface / review | NOT_STARTED |
| I04 | Root-cause reasoning | Mandar | Interface / review | NOT_STARTED |
| I05 | Evidence-backed risk explanation | Mandar | Interface / review | NOT_STARTED |
| I06 | Minimal-change optimization | Mandar | Interface / review | NOT_STARTED |
| I07 | Alternative fix comparison | Mandar | Interface / review | NOT_STARTED |
| I08 | Cross-vendor remediation planning | Mandar | Interface / review | NOT_STARTED |
| I09 | Remediation conflict checks | Mandar | Interface / review | NOT_STARTED |
| I10 | Change sequencing | Mandar | Interface / review | NOT_STARTED |
| I11 | Cross-layer what-if simulation | Vidhi | PRIMARY | NOT_STARTED |
| I12 | Service-safety contracts | Vidhi | PRIMARY | INTERFACE_ONLY |
| I13 | Blast-radius estimation | Vidhi | PRIMARY | NOT_STARTED |
| I14 | Safety-gated execution | Mandar | Interface / review | NOT_STARTED |
| I15 | Staged hardening rollout | Vidhi | PRIMARY | NOT_STARTED |
| I16 | Dual verification | Vidhi | PRIMARY | NOT_STARTED |
| I17 | Residual-risk analysis | Mandar | Interface / review | NOT_STARTED |
| I18 | Proof-of-Hardening dossier | Mandar | Interface / review | NOT_STARTED |
| I19 | Benchmark upgrade impact preview | Mandar | Interface / review | NOT_STARTED |
| I20 | Explainable coverage decisions | Mandar | Interface / review | NOT_STARTED |

Count check: 38 M + 30 E + 20 I = 88 retained feature IDs.
