# Firewall fact mapping

The envelope shares structures only where semantics overlap. ASA (`cisco_asa`) stays
distinct from FTD managed by FMC (`cisco_ftd_fmc`).

| Fact | Preserved semantics |
|---|---|
| `context` | VDOM, security context, FMC domain/device, or Check Point domain/package; Gaia is separate |
| `ordered_rules` | vendor ID, order, enablement, action, source, destination, service, application/user constraints |
| `objects` / `object_resolution` | raw definitions, values, unresolved names, cycles, unsupported types, depth limit |
| `bindings` | ACL-to-interface/direction or policy/package-to-device assignment |
| `nat` | identity, type, original and translated values; unknown stays unknown |
| `deployment` | saved/published separately from confirmed installed/deployed |
| management groups | Telnet, HTTP, logging, NTP, and SNMP configuration evidence |

The normalizer does not infer shadowing, reachability, exposure, implicit action,
effective NAT, or compliance. Unsupported constructs remain vendor-specific.

## Vendor limits

- FortiOS: VDOM and requested fact groups are fixture-tested; live endpoint matrix is unverified.
- ASA: fixed CLI collection is mock-tested; real multi-context and object-NAT variants need labs.
- FTD/FMC: stored policy/assignment is separate from deployment; app/user rules are preserved.
- Check Point: management publication and installation are separate. Gaia evidence is unavailable.
