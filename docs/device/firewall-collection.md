# Firewall collection

## Offline replay

From `services/device-engine`, set `PYTHONPATH=src`, then run:

```text
python -m cisguard_device firewall-collect --transport offline --fixture fixtures/firewalls/fortios/secure/manifest.json
python -m cisguard_device firewall-collect --transport offline --fixture fixtures/firewalls/cisco_asa/secure/manifest.json
python -m cisguard_device firewall-collect --transport offline --fixture fixtures/firewalls/cisco_ftd_fmc/secure/manifest.json
python -m cisguard_device firewall-collect --transport offline --fixture fixtures/firewalls/checkpoint_management/secure/manifest.json
```

Each fixture is explicitly synthetic with illustrative—not lab-tested—version metadata,
completeness, and policy state. Exact capture bytes are SHA-256 hashed. Permission
denial produces a canonical error and unknown values, never an empty secure policy.

## Transport status

| Family | Offline | Live status | Identity controls required |
|---|---|---|---|
| FortiOS | fixture-tested | API blocked/unverified | HTTPS, validated certificate/custom CA, header token |
| ASA | fixture-tested | SSH SDK mock-tested | known_hosts, fixed commands, secret provider |
| FTD/FMC | fixture-tested | API blocked/unverified | HTTPS, validated certificate/custom CA, version/domain |
| Check Point | fixture-tested | API blocked/unverified | HTTPS, validated certificate/custom CA, session provider |

The CLI rejects `--transport live` and never substitutes fixtures. ASA's SDK boundary
rejects unknown host keys and arbitrary commands; responses are bounded. Pagination
helpers reject repeated cursors, duplicate pages, and page-limit exhaustion.

## Official sources consulted

- FortiOS 7.2.7 Administration Guide, “Using APIs”: header bearer token, HTTPS,
  trusted hosts, least privilege, and example address path.
- Cisco ASA command reference and ASA 9.18 NAT guide: ordered ACEs,
  `show running-config access-list`, access-group bindings, and NAT display behavior.
- Cisco Security Cloud Control Firewall Manager documentation: on-premises-compatible
  FMC access-policy path shape and cdFMC prefix; this is not universal compatibility.
- Check Point R81.20 Security Management guide and current API reference:
  `/web_api/<command>`, HTTPS POST, login session ID, domain selection, and logout.

Authentication headers, tokens, passwords, and sensitive responses are not logged.
Production artifact encryption remains an ingestion/storage dependency.
