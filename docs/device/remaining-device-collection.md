# Remaining device collection

## Supported source formats

- Sophos: synthetic XML shaped as a versioned API 1905.2 response, including identity,
  objects, ordered rules, NAT, management, logging, NTP, and SNMP attributes.
- PAN-OS: successful XML API response containing a 10.2 or 11.0 local `config` tree,
  vsys rulebase, objects, NAT names, management, and NTP. Candidate/running state is an
  explicit wrapper attribute. Panorama, pre-rules, post-rules, and inheritance are unsupported.
- Cisco: IOS 15 / IOS-XE 16-17 running configuration with separate bounded show output.
  NX-OS is rejected. The subset covers interfaces, ACLs/bindings, VTY/SSH, VLAN scope,
  port security, DHCP snooping, DAI, management SVIs, syslog, NTP, and SNMP security facts.

Each source is hashed independently before parsing. DTDs and entity declarations are
rejected. Missing/denied sources remain errors. SNMP community strings normalize only
to `<redacted>` while insecure v1/v2c presence is retained.

## Live status

All Phase 5 live transports are explicitly unsupported. `device-collect --transport
live` returns a structured error and never substitutes a fixture. No TLS credential flow
or SSH command transport is claimed in this phase.

Official references consulted include Sophos API XML payload/tag documentation, PAN-OS
XML API configuration actions, and Cisco IOS-XE DHCP snooping and Dynamic ARP Inspection
configuration guides. The fixtures are documentation-shaped, not device captures.
