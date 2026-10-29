# Windows collection

## Scope and safety

Phase 2 supports synthetic offline captures for Windows 11 Enterprise, Windows 11 in a
standalone/workgroup deployment context, and Windows Server 2019. It also provides an
explicit local PowerShell path and optional authorized WinRM transport.

The fixed Windows PowerShell 5.1 script is packaged at
`cisguard_device/scripts/windows_collect.ps1`. It accepts no command/script input and
uses a fixed allowlist. It does not install software, elevate, enable WinRM, modify the
registry/firewall/policy, start services, or disable certificate validation.

`secedit /export` writes to a unique temporary directory and that directory is removed
in `finally`. Export does not apply policy.

## Collected fact groups

- OS caption, version, build, ProductType and edition ID via CIM plus a fixed registry
  edition lookup.
- Domain/workgroup membership without claiming effective domain policy.
- Account-policy command output with locale uncertainty retained.
- Selected configured local security-policy values from `secedit` export.
- Effective audit-policy command output with locale limitations.
- Domain, Private and Public active firewall profile settings.
- Allowlisted service startup mode and current state as separate values.
- Allowlisted registry values with `present`, `missing` and `denied` distinctions.
- Selected path ACL metadata without usernames, SIDs or individual access rules.

The exact source capture is SHA-256 hashed before JSON parsing. Routine CLI diagnostics
never print the raw capture.

## Privileges and limitations

| Source | Typical requirement | Phase-2 treatment |
|---|---|---|
| Win32_OperatingSystem / Win32_ComputerSystem | CIM/WMI read access | Denial returns `WINDOWS_IDENTITY_UNAVAILABLE`; known unsupported versions use a separate error |
| `net accounts` | Ordinary command access; domain behavior depends on context | Raw bounded text retained; locale labels are not guessed |
| `secedit /export` | May require administrative/security-policy access | Denial/error produces null facts |
| `auditpol /get` | Audit-policy query access; often restricted | Denial/error produces null facts |
| Get-NetFirewallProfile ActiveStore | Firewall policy read access | Denial produces null profiles |
| Win32_Service | CIM service read access | Startup mode and running state remain separate |
| Selected HKLM values | Key-specific read ACL | Missing, denied and configured values stay distinct |
| Selected path ACLs | Path read/ACL access | SID and account identities intentionally omitted |

No code auto-elevates. A non-administrator run is valid evidence even when some sources
are denied.

## Commands

From `services/device-engine`:

```powershell
.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport offline `
  --fixture fixtures\windows\windows11_enterprise_secure\manifest.json

.\.venv\Scripts\python.exe -m cisguard_device windows-collect --transport local `
  --org-id 11111111-1111-4111-8111-111111111111 `
  --asset-id 22222222-2222-4222-8222-222222222222 `
  --model local-windows-host --timeout 120
```

WinRM requires explicit `--transport winrm`, an authorized `https://...:5986/wsman`
target, certificate validation, optional `pywinrm`, and a runtime `SecretProvider`.
Basic authentication over HTTP is rejected. Automated tests use mocks and make no
network calls. No authorized remote lab was supplied, so WinRM is live-untested.

## Microsoft supporting diagnostics

Microsoft Security Compliance Toolkit, LGPO and Policy Analyzer may be used manually in
an authorized lab to compare Microsoft baseline/GPO material. They are not downloaded or
bundled. Microsoft baselines are not CIS Benchmarks and are never treated as equivalent.
Any future CIS mapping requires an authorized benchmark release, profile and review.

## Windows 11 Home diagnostic mode

Windows 11 Home is not classified as Enterprise and is outside the supported benchmark scope.
For explicitly requested local fact diagnostics only, `windows-collect --transport local
--collection-only-diagnostic` emits `windows_11_home_diagnostic` and marks
`benchmark_applicability` unsupported. It does not make Enterprise/domain controls applicable;
unavailable sources remain unavailable and must not be treated as secure defaults.

Windows classification is edition-first: Home/Core is rejected by default even when the device is
in a workgroup; workgroup context does not override Enterprise edition either. Source errors retain
safe source state and exit status while command stderr remains redacted.

## Observed non-elevated Home diagnostic evidence

A real non-elevated Windows 11 Home Single Language diagnostic collection completed successfully
outside the sandbox and classified as `windows_11_home_diagnostic`. `auditpol` exit 1314 is mapped
to `AUDITPOL_PRIVILEGE_REQUIRED`; `secedit` exit 740 is mapped to
`SECEDIT_ELEVATION_REQUIRED`. Both remain unknown/unassessed facts and non-retryable in an
unchanged privilege context. No elevation was attempted. Enterprise benchmark applicability remains
unverified.
