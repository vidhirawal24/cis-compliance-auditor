# Linux fact-to-control-family mapping

This is a project mapping, not an official CIS mapping. Exact control IDs are PENDING an
authorized benchmark release/profile and reviewed rule mapping.

| Fact path | Primary source | Limitation | Feature IDs |
|---|---|---|---|
| `facts.os_identity` | `/etc/os-release` | Exact distro/version classification only | M03, M04, M14 |
| `facts.ssh` | selected `sshd_config` + `sshd -T` | Match contexts incomplete; no reachability proof | M03, M04, M14, M20, M21 |
| `facts.pam` | selected fixed PAM files | Includes/order may require manual review | M03, M04, M14 |
| `facts.account_policy` | login.defs/pwquality/faillock selections | Configuration is not password strength | M03, M04, M14 |
| `facts.audit` | auditd selected files + service facts | Configured and runtime/service state differ | M03, M04, M14, M31 |
| `facts.sysctl` | fixed sysctl keys and selected config | Configured and runtime values differ | M03, M04, M14 |
| `facts.firewall` | UFW/firewalld/nft fixed commands | No effective external exposure proof | M03, M04, M14, M20 |
| `facts.services` | systemctl fixed allowlist | Enabled differs from active | M03, M04, M14 |
| `facts.packages` | selected package inventory/cached updates | Not patch compliance | M03, M04, M14 |
| `facts.permissions` | `stat` fixed path allowlist | Numeric ownership only | M03, M04, M14 |
| `facts.selinux` | config + getenforce | RHEL only; configured/runtime differ | M04, M14 |

M32/M33 require later NTP/SNMP-specific fact expansion; they are not claimed complete.
