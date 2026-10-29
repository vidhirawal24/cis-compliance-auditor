# Switch fact mapping

| Fact | Meaning and uncertainty |
|---|---|
| `configured_shutdown` | Explicit configuration only; false is not a violation |
| `operational_status` | Separate observed show state; down does not mean unused |
| `designated_unused` | Inventory-derived boolean, or null when inventory is absent |
| `switchport_mode` / `access_vlan` | Interface role evidence; applicability is evaluated later |
| `port_security_configured` | Presence only; trunks/uplinks are not automatically expected to use it |
| `dhcp_snooping.enabled` / `vlans` | Global command and covered VLANs remain separate |
| `dynamic_arp_inspection.vlans` | Exact configured VLAN scope, never global protection |
| `management_svis` | SVI evidence; VLAN 1 existence alone is not management use |
| `ntp` | Configured servers separate from observed synchronization |
| `snmp` | v3 presence and insecure v1/v2c presence are simultaneous independent facts |

ACL order and bindings are preserved. Reachability, exposure, shadowing, port-role
applicability, and compliance verdicts are intentionally outside this collector.
