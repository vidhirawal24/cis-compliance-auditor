# Linux collection

## Supported identity

Only exact `/etc/os-release` identities are supported: `ID=ubuntu` with `VERSION_ID`
20.04 or 22.04, and `ID=rhel` with major version 8 or 9. Derivatives and compatible
distributions are not silently classified as Ubuntu/RHEL. Missing or denied identity
returns `LINUX_IDENTITY_UNAVAILABLE`; positively identified unsupported systems return
`UNSUPPORTED_LINUX_VERSION`.

## Fixed collector

The packaged Python 3.11 script uses only fixed argument lists and selected files. It
never uses `eval`, sudo, package refresh/install/update, service/firewall/sysctl writes,
or remediation. It reads selected SSH/PAM/account/audit/sysctl/firewall/service/package/
permission/SELinux evidence and emits one JSON document.

Important boundaries:

- `sshd -T` is retained separately from configured text and does not cover every Match
  user/source/host context without explicit `-C` contexts.
- Service enablement and running state are separate.
- Sysctl configured and runtime values are separate.
- Cached update information is not patch compliance.
- Firewall output is not proof of effective exposure.
- Account configuration is not proof of password strength.
- SELinux configured and runtime modes are separate.
- Missing commands/files and permission denial produce unknown/unavailable values.

SSH uses Paramiko only when requested, loads an explicit `known_hosts`, installs a reject
policy for unknown keys, uses bounded time/output, and runs only the fixed `python3 -`
collector. Credentials come from `SSHSecretProvider`; CLI password arguments do not
exist. The target requires Python 3.11.

Privilege requirements vary by file/command. The collector never elevates. Audit rules,
firewall state, some SSH/PAM files and SELinux data may be denied to ordinary users; the
denial is evidence rather than a secure result.
