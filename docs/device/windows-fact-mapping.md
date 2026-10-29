# Windows fact-to-control-family mapping

This is a project integration map, not an official CIS mapping. Exact CIS control IDs
remain **PENDING** until an authorized benchmark version/profile is available.

| Normalized fact path | Evidence source | Privilege considerations | Applicability / limitation | Feature IDs | Official mapping |
|---|---|---|---|---|---|
| `facts.os.value` | Win32_OperatingSystem + EditionID | CIM can be denied | Workstation/server classification requires ProductType and caption | M01, M02, M14 | PENDING |
| `facts.deployment.domain_membership` | Win32_ComputerSystem | CIM can be denied | Membership only; not effective domain GPO | M01, M02, M14 | PENDING |
| `facts.account_policy.value` | `net accounts` or structured capture | Locale/domain context limits parsing | Local versus command-reported scope retained | M01, M02, M14 | PENDING |
| `facts.local_security_policy.value` | `secedit /export` allowlisted keys | Often needs elevated policy access | Configured local policy, not verified effective domain policy | M01, M02, M14 | PENDING |
| `facts.audit_policy.value` | `auditpol /get` | Query may be denied | Intended effective audit source; localized output may remain unparsed | M01, M02, M14 | PENDING |
| `facts.firewall_profiles.value` | Get-NetFirewallProfile ActiveStore | Firewall policy read can be denied | Profile state only; no rule-level exposure claim | M01, M02, M14 | PENDING |
| `facts.services.value` | Win32_Service allowlist | CIM can be denied | Startup configuration differs from current state | M01, M02, M14 | PENDING |
| `facts.registry_settings.value` | Get-ItemProperty allowlist | Per-key ACL | Missing differs from disabled/enabled and denied | M01, M02, M14 | PENDING |
| `facts.permissions.value` | Get-Acl path allowlist | Per-path ACL | Counts/protection only; no identity or full effective-access proof | M01, M02, M14 | PENDING |
