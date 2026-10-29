# Remediation catalog

| Template | Check / feature | Preview commands | Validation |
|---|---|---|---|
| `ios_disable_http` | DEV-M21-001 / M20 | `no ip http server` | fixture-tested, no live lab |
| `ios_set_vty_timeout` | DEV-M21-004 / M21 | line-VTY `exec-timeout` | fixture-tested, no live lab |
| `ios_shutdown_unused_interface` | DEV-M26-001 / M26 | interface `shutdown` | fixture-tested, no live lab |

These are syntactic previews for IOS 15 / IOS-XE 16-17 fact subsets, not broad firmware compatibility claims. Candidate generation requires matching org/asset predicate evidence, a FAIL status, supported platform/firmware, and current fact preconditions. It rejects unknown facts, unverified VTY inventory, absent interfaces, invalid identifiers, and raw commands. Mandar owns planning, approval, authorization, and persistence.

Cisco documents `no ip http server` for disabling standard HTTP and `exec-timeout` as a line-configuration command. See the [HTTP Services guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/xe-17/https-xe-17-book/HTTPS--HTTP_Server_and_Client_with_SSL_3-0.html) and [line command reference](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/iosxe/qualified-cli-command-reference-guide/m-line-commands.html).
