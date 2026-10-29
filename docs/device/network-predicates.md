# Network Control Predicates (M20–M33)

This document specifies the 21 evidence-aware device predicates implemented in Phase 6 within `cisguard_device.network_predicates`.

## Design Principles

1. **Deterministic & Evidence-Aware:** A `PASS` requires sufficient positive evidence for the specific claim. The absence of failure evidence does not justify a `PASS`.
2. **Distinct Check IDs:** Stable internal check IDs (`DEV-Mxx-NNN`) are strictly distinct from official CIS benchmark rule numbers.
3. **Structured Non-PASS Reasons:** Any check unable to prove compliance returns `FAIL`, `NOT_ASSESSED`, `NOT_APPLICABLE`, or `ERROR` with structured explanations, actual vs. expected evidence, limitations, and error codes.
4. **Typed Policy Parameters:** Evaluators accept validated `NetworkControlPolicy` instances. No executable expressions, dynamic shell commands, or caller code are accepted.
5. **Partial Capture Downgrade:** If import/collection metadata indicates `partial` or `unknown` completeness, any negative-assertion `PASS` is downgraded to `NOT_ASSESSED` (`INCOMPLETE_CAPTURE`).

---

## Policy Contract (`NetworkControlPolicy`)

| Field | Type | Default | Description |
|---|---|---|---|
| `session_timeout_seconds` | `int` | **Required (No default)** | Maximum permitted idle session timeout in seconds (must be ≥ 1). |
| `sensitive_ports` | `list[int]` | `[22, 23, 80, 443, 3389]` | TCP/UDP ports monitored for broad inbound exposure. |
| `required_vlans` | `list[str] \| None` | `None` | VLAN IDs where DHCP snooping and DAI are mandated. |
| `designated_unused_ports` | `list[str] \| None` | `None` | Explicit list of interface names designated unused. |
| `management_interface_inventory`| `list[str] \| None` | `None` | Interfaces explicitly designated for management traffic. |
| `management_interface_inventory_complete` | `bool` | `False` | Whether the management interface inventory is known to be exhaustive. |
| `interface_roles` | `dict[str, str] \| None` | `None` | Explicit interface roles (`access`, `trunk`, `routed`, `unused`). |
| `max_acl_complexity` | `int` | `500` | Safety limit for ACL shadowing analysis complexity. |

---

## Supported ACL Subset (E06, M22–M25)

The ACL evaluation engine supports a bounded, mathematically verifiable subset of Cisco IOS/IOS-XE IPv4 access lists:

### Supported Features
- Standard and Extended IPv4 ACLs (`access-list <n>` and `ip access-list extended <name>`).
- Terminal actions: `permit` and `deny`.
- Supported protocols: `ip`, `tcp`, `udp`, `icmp`.
- Source and Destination Addresses:
  - `any` (evaluated as `0.0.0.0/0`).
  - `host <ip>` (evaluated as `<ip>/32`).
  - `<ip> <wildcard>` where wildcard is contiguous inverse mask (e.g. `0.0.0.255` -> `/24`).
- Port specifications (TCP/UDP):
  - Single port: `eq <n>`.
  - Port range: `range <lo> <hi>`.
  - Comparisons: `gt <n>`, `lt <n>`.
- Shadowing Detection:
  - Exact match-set containment: Rule $B$ is shadowed by earlier Rule $A$ if and only if $\text{Match}(B) \subseteq \text{Match}(A)$ and $A$ is an enabled terminal rule.
  - Action comparison: Distinguishes full shadowing with identical action (redundancy) vs differing action (blocking conflict).
  - Disabled rules are excluded from shadowing calculation.

### Unsupported & Blocking Constructs
The evaluator detects and explicitly blocks or returns `NOT_ASSESSED` (`UNSUPPORTED_ACL_CONSTRUCT`) when encountering:
- IPv6 ACL rules (`ipv6 access-list`).
- Non-contiguous wildcard masks (e.g., `0.0.255.255` or OSPF-style discontiguous bitmasks).
- Object groups and FQDN objects (`object-group network`, `object-group service`).
- Application-layer matching or NBAR inspect rules (`class-map`, `policy-map`).
- Dynamic/stateful rules (`reflect`, `evaluate`, `established`, `time-range`).
- NAT interactions: Inbound rules evaluated without verified destination NAT translation mappings remain configuration-level findings, not verified external exposures.

---

## Detailed Check Specification

### Management Controls (M20–M21, Feature E05)

#### `DEV-M20-001`: Telnet Management Disabled
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** All configured VTY lines explicitly configure `transport input ssh`, Telnet is not permitted, and complete VTY line range (0–15) is verified.
- **FAIL:** Any VTY line permits Telnet (e.g., `transport input telnet` or `transport input all`).
- **NOT_ASSESSED:** Telnet appears disabled but VTY line range coverage is incomplete (`error_code="INCOMPLETE_VTY_COVERAGE"`), or transport settings are absent/unparsed.
- **Limitations:** Does not verify external reachability across upstream routers or firewalls.

#### `DEV-M21-001`: HTTP Management Server Disabled
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Configuration explicitly contains `no ip http server`.
- **FAIL:** Configuration contains `ip http server`.
- **NOT_ASSESSED:** Neither `no ip http server` nor `ip http server` appears in the snapshot.

#### `DEV-M21-002`: SSH Protocol Version 2
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Configuration explicitly contains `ip ssh version 2`.
- **FAIL:** Configuration contains `ip ssh version 1` or explicitly allows SSHv1.
- **NOT_ASSESSED:** SSH version setting is omitted (device may default to 1.99 or 1.0 depending on IOS version).

#### `DEV-M21-003`: SSH Key-Based Authentication Enforced
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** VTY lines use public-key authentication or an AAA profile enforcing key authentication; password-only authentication (`login local` without key configuration) is absent.
- **FAIL:** VTY lines configure `login local` or password authentication without key enforcement.
- **NOT_ASSESSED:** VTY login method cannot be definitively verified from the running configuration.
- **Limitations:** Configuration of SSHv2 does not prove key-only authentication.

#### `DEV-M21-004`: Configured VTY Session Timeout
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** All configured VTY lines specify an `exec-timeout` $\le$ `policy.session_timeout_seconds` and $> 0$.
- **FAIL:** Any VTY line has `exec-timeout` exceeding the policy threshold or set to `0 0` (unlimited).
- **NOT_ASSESSED:** VTY `exec-timeout` is omitted on one or more lines (IOS default of 10 minutes cannot be presumed without verified defaults).

---

### ACL & Firewall Controls (M22–M25, Feature E06)

#### `DEV-M22-001`: Broad Inbound Permissive Rules Absent
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Bound inbound ACLs contain no overly broad permit rules (e.g., `permit ip any any` or `/0` sources with `/0` destinations).
- **FAIL:** One or more inbound bound ACLs contain `permit ip any any` or equivalent unconstrained rules.
- **NOT_ASSESSED:** ACLs contain unsupported syntax, object-groups, or interface bindings are unknown.

#### `DEV-M23-001`: Sensitive Port Exposure
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** No inbound bound ACL permits access to `policy.sensitive_ports` from broad sources (`any` or masks smaller than `/24`).
- **FAIL:** Inbound ACL allows traffic to sensitive ports (e.g. 22, 23, 80, 443, 3389) from `any` or broad CIDR ranges.
- **NOT_ASSESSED:** Port ranges cannot be parsed or ACL semantics are unsupported.

#### `DEV-M24-001`: Shadowed Rule Analysis
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** No bound ACL contains rules that are completely shadowed by preceding rules.
- **FAIL:** One or more rules are fully shadowed (match-set is a complete subset of an earlier rule's match criteria).
- **NOT_ASSESSED:** ACL complexity exceeds `policy.max_acl_complexity` or contains unsupported constructs.
- **Limitations:** Partial overlaps are reported as informational context but do not trigger full shadow FAIL.

#### `DEV-M25-001`: Default-Deny Policy Evidence
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Bound ACL explicitly terminates with `deny ip any any` or verified implicit default deny with logging.
- **FAIL:** Bound ACL terminates with an explicit permit or has no verifiable default-deny mechanism.
- **NOT_ASSESSED:** Default action of the platform/context is unverified.

---

### Switch Controls (M26–M30, Feature E07)

#### `DEV-M26-001`: Designated-Unused Ports Shut Down
- **Platforms:** `cisco_switch` (`NOT_APPLICABLE` on `cisco_router`)
- **PASS:** All ports identified in `policy.designated_unused_ports` have `shutdown` administratively configured.
- **FAIL:** One or more designated unused ports lack administrative `shutdown`.
- **NOT_ASSESSED:** `policy.designated_unused_ports` is not supplied and device configuration does not tag unused ports.
- **Limitations:** Operational `down` state is NOT inferred as unused.

#### `DEV-M27-001`: Port Security on Access Ports
- **Platforms:** `cisco_switch` (`NOT_APPLICABLE` on `cisco_router`)
- **PASS:** All interfaces operating in `switchport mode access` have `switchport port-security` enabled.
- **FAIL:** One or more access switchports lack port security.
- **NOT_ASSESSED:** Interface switchport modes are undefined or missing from inventory.
- **Limitations:** Trunk and uplink ports are excluded unless designated as access in policy.

#### `DEV-M28-001`: DHCP Snooping Active on Required VLANs
- **Platforms:** `cisco_switch` (`NOT_APPLICABLE` on `cisco_router`)
- **PASS:** Global `ip dhcp snooping` is enabled AND all VLANs in `policy.required_vlans` are explicitly covered by `ip dhcp snooping vlan <vlans>`.
- **FAIL:** DHCP snooping is disabled globally or missing for one or more required VLANs.
- **NOT_ASSESSED:** `policy.required_vlans` is not provided and active VLAN inventory is unverified.
- **Limitations:** Global enablement without VLAN-specific configuration is not a PASS.

#### `DEV-M29-001`: Dynamic ARP Inspection Active on Required VLANs
- **Platforms:** `cisco_switch` (`NOT_APPLICABLE` on `cisco_router`)
- **PASS:** `ip arp inspection vlan <vlans>` covers all VLANs in `policy.required_vlans`.
- **FAIL:** DAI is not configured or fails to cover all required VLANs.
- **NOT_ASSESSED:** `policy.required_vlans` is not provided.

#### `DEV-M30-001`: VLAN 1 Management Separation
- **Platforms:** `cisco_switch` (`NOT_APPLICABLE` on `cisco_router`)
- **PASS:** Active management SVI (`interface VlanX` with IP address) is not on VLAN 1, and management interfaces are separate.
- **FAIL:** `interface Vlan1` possesses an active configured IP address used for management.
- **NOT_ASSESSED:** Management interface inventory is incomplete (`management_interface_inventory_complete=False`).
- **Limitations:** Existence of unaddressed `interface Vlan1` alone is not evaluated as a failure.

---

### Telemetry Controls (M31–M33, Feature E08)

#### `DEV-M31-001`: Remote Syslog Configuration
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** At least one remote syslog server is configured (`logging host <ip>`).
- **FAIL:** No remote syslog servers are configured.
- **NOT_ASSESSED:** Logging configuration block is absent or denied in collection.

#### `DEV-M32-001`: NTP Server Configuration
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** At least one valid NTP server is configured (`ntp server <ip>`).
- **FAIL:** No NTP servers are configured.
- **NOT_ASSESSED:** NTP configuration evidence is missing.

#### `DEV-M32-002`: Operational NTP Synchronization
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Operational command output contains positive synchronization evidence (`Clock is synchronized`).
- **FAIL:** Operational output confirms unsynchronized state (`Clock is not synchronized`).
- **NOT_ASSESSED:** Operational show output was not collected or was unavailable in snapshot.
- **Limitations:** Running configuration cannot prove operational clock synchronization.

#### `DEV-M33-001`: SNMPv3 User Configuration
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** At least one SNMPv3 user is configured (`snmp-server user <user> <group> v3`).
- **FAIL:** SNMP is configured or active but no SNMPv3 users exist.
- **NOT_ASSESSED:** SNMP service presence cannot be determined from snapshot.

#### `DEV-M33-002`: Absence of Insecure SNMPv1/v2c
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** No `snmp-server community` strings are configured.
- **FAIL:** One or more legacy SNMPv1/v2c communities are present.
- **NOT_ASSESSED:** SNMP configuration state is unknown.

#### `DEV-M33-003`: Absence of Default Community Strings
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** Default community names (`public`, `private`) are not present in configuration.
- **FAIL:** `public` or `private` community strings are detected.
- **NOT_ASSESSED:** Community configuration is absent or unparsed.
- **Security Guarantee:** Exact community values are never logged, stored in evidence, or emitted in result output.

#### `DEV-M33-004`: SNMPv3 authPriv Security Level
- **Platforms:** `cisco_router`, `cisco_switch`
- **PASS:** SNMPv3 user configuration includes explicit `auth` and `priv` encryption settings (e.g. `auth sha ... priv aes ...`).
- **FAIL:** SNMPv3 users are configured with `noAuthNoPriv` or `authNoPriv`.
- **NOT_ASSESSED:** SNMPv3 user configuration is absent or unobservable.
