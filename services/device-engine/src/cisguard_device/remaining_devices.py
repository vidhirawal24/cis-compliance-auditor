"""Phase-5 vendor-shaped offline parsers for remaining device families."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .errors import DeviceEngineError, FixtureInputError
from .models import CanonicalError, EvidenceReference, FactsEnvelope

PLATFORMS = ("sophos_firewall", "palo_alto_panos", "cisco_router", "cisco_switch")
MAX_SOURCE_BYTES = 4 * 1024 * 1024


class RemainingDeviceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    synthetic: bool
    label: str
    platform: str
    illustrative_version: str
    model: str
    org_id: UUID
    asset_id: UUID
    collected_at: datetime
    sources: list[dict[str, Any]]
    completeness: str
    designated_unused_ports: list[str] | None = None


def parse_sophos_xml(content: bytes) -> dict[str, Any]:
    root = _safe_xml(content)
    if root.tag != "Response" or root.get("APIVersion") != "1905.2":
        raise FixtureInputError("UNSUPPORTED_SOPHOS_SCHEMA", "Expected API 1905.2 XML shape.")
    objects = {
        e.get("Name"): {"type": e.tag, "value": e.get("Value")}
        for e in root.findall("./Objects/*")
        if e.get("Name")
    }
    rules = [
        {
            "id": e.get("Name"),
            "order": index,
            "enabled": e.get("Status") == "Enable",
            "action": e.get("Action"),
            "source": _csv(e.get("Source")),
            "destination": _csv(e.get("Destination")),
            "services": _csv(e.get("Services")),
            "zones": {"source": e.get("SourceZones"), "destination": e.get("DestinationZones")},
        }
        for index, e in enumerate(root.findall("./FirewallRules/FirewallRule"), 1)
    ]
    return {
        "identity": _attrs(root.find("Identity")),
        "ordered_rules": rules,
        "objects": objects,
        "nat": [_attrs(e) for e in root.findall("./NATRules/NATRule")],
        "management": _attrs(root.find("Management")),
        "logging": _attrs(root.find("Logging")),
        "ntp": _attrs(root.find("NTP")),
        "snmp": _attrs(root.find("SNMP")),
        "parser": {"scope": "Sophos API XML 1905.2 subset"},
    }


def parse_panos_xml(content: bytes) -> dict[str, Any]:
    root = _safe_xml(content)
    if root.tag != "response" or root.get("status") != "success":
        raise FixtureInputError(
            "UNSUPPORTED_PANOS_RESPONSE", "Expected successful PAN-OS XML response."
        )
    config = root.find("./result/config")
    if config is None or config.get("version") not in {"10.2", "11.0"}:
        raise FixtureInputError(
            "UNSUPPORTED_PANOS_VERSION", "Supported PAN-OS XML versions are 10.2/11.0."
        )
    rules = []
    for order, entry in enumerate(
        config.findall("./devices/entry/vsys/entry/rulebase/security/rules/entry"), 1
    ):
        rules.append(
            {
                "id": entry.get("name"),
                "order": order,
                "enabled": _text(entry, "disabled") != "yes",
                "action": _text(entry, "action"),
                "source_zones": _members(entry, "from"),
                "destination_zones": _members(entry, "to"),
                "source": _members(entry, "source"),
                "destination": _members(entry, "destination"),
                "services": _members(entry, "service"),
                "applications": _members(entry, "application"),
            }
        )
    addresses = {
        e.get("name"): (_text(e, "ip-netmask") or _text(e, "fqdn"))
        for e in config.findall("./devices/entry/vsys/entry/address/entry")
    }
    return {
        "identity": {"hostname": _text(config, "deviceconfig/system/hostname")},
        "context": {
            "vsys": _first_name(config, "./devices/entry/vsys/entry"),
            "device_group": None,
            "panorama_supported": False,
        },
        "configuration_state": root.get("config-state", "unknown"),
        "ordered_rules": rules,
        "objects": addresses,
        "nat": [
            e.get("name")
            for e in config.findall("./devices/entry/vsys/entry/rulebase/nat/rules/entry")
        ],
        "management": {"permitted_ip": _text(config, "deviceconfig/system/permitted-ip")},
        "ntp": {"servers": [e.text for e in config.findall(".//ntp-servers/*") if e.text]},
        "parser": {"scope": "local vsys rulebase only", "pre_post_rules_supported": False},
    }


def parse_cisco_ios_sources(
    config: bytes,
    operational: bytes | None,
    *,
    platform: str,
    designated_unused_ports: list[str] | None,
) -> dict[str, Any]:
    text = _decode(config)
    op = _decode(operational) if operational is not None else ""
    if not re.search(r"^version (?:15|16|17)\.", text, re.M):
        raise FixtureInputError(
            "UNSUPPORTED_IOS_VERSION", "Only IOS 15 and IOS-XE 16/17 syntax is supported."
        )
    interfaces: list[dict[str, Any]] = []
    for match in re.finditer(r"^interface (\S+)\n((?:[ \t].*\n?)*)", text, re.M):
        name, body = match.group(1), match.group(2)
        status = _oper_status(op, name)
        interfaces.append(
            {
                "name": name,
                "configured_shutdown": bool(re.search(r"^ shutdown$", body, re.M)),
                "operational_status": status,
                "switchport_mode": _capture(body, r"switchport mode (\S+)"),
                "access_vlan": _capture(body, r"switchport access vlan (\d+)"),
                "port_security_configured": "switchport port-security" in body,
                "dhcp_snooping_trust": "ip dhcp snooping trust" in body,
                "dai_trust": "ip arp inspection trust" in body,
                "designated_unused": (
                    name in designated_unused_ports if designated_unused_ports is not None else None
                ),
            }
        )
    communities = re.findall(r"^snmp-server community (\S+)\s+(\S+)", text, re.M)
    # Detect default community names (public/private) without exposing the strings.
    _raw_community_names = [c[0] for c in communities]
    default_community_present: bool | None
    if _raw_community_names:
        default_community_present = any(
            n.lower() in {"public", "private"} for n in _raw_community_names
        )
    elif bool(re.search(r"^snmp-server\b", text, re.M)):
        default_community_present = False
    else:
        default_community_present = None
    acls = [
        {"id": m.group(1), "order": i, "syntax": m.group(2)}
        for i, m in enumerate(re.finditer(r"^access-list (\S+) (.+)$", text, re.M), 1)
    ]
    # Parse named extended ACL entries
    named_acl_entries: list[dict[str, Any]] = []
    for acl_match in re.finditer(
        r"^ip access-list (?:extended|standard) (\S+)\n((?:[ \t].*\n?)*)", text, re.M
    ):
        acl_id = acl_match.group(1)
        acl_body = acl_match.group(2)
        order = 0
        for raw_line in acl_body.splitlines():
            line_str = raw_line.strip()
            if not line_str or line_str.startswith("!") or line_str.lower().startswith("remark"):
                continue
            order += 1
            line_m = re.match(r"^(?:\d+\s+)?(permit|deny)\s+(.+)$", line_str)
            syntax = (
                f"{line_m.group(1)} {line_m.group(2).strip()}"
                if line_m
                else line_str  # Preserve unknown/unparsed syntax so it is not dropped
            )
            named_acl_entries.append(
                {
                    "id": acl_id,
                    "order": order,
                    "syntax": syntax,
                    "named": True,
                }
            )
    all_acl_items = [{"id": a["id"], "order": a["order"], "syntax": a["syntax"]} for a in acls] + [
        {"id": e["id"], "order": e["order"], "syntax": e["syntax"]} for e in named_acl_entries
    ]
    acls_structured = [
        {
            "id": entry["id"],
            "order": entry["order"],
            "syntax": entry["syntax"],
            "parsed": _parse_acl_entry(entry["syntax"]),
        }
        for entry in all_acl_items
    ]
    unsupported_acl_semantics = []
    if re.search(r"^ipv6 access-list\b", text, re.M):
        unsupported_acl_semantics.append("ipv6_acl")
    if re.search(r"^(?:ip nat|nat\s)\b", text, re.M):
        unsupported_acl_semantics.append("nat")
    if re.search(
        r"^(?:zone security|zone-pair security|class-map type inspect|policy-map type inspect)\b",
        text,
        re.M,
    ):
        unsupported_acl_semantics.append("zone_policy")
    if re.search(r"^(?:object-group|object network|object service)\b", text, re.M):
        unsupported_acl_semantics.append("object_group")
    has_pubkey = bool(
        re.search(r"^ip ssh pubkey-chain\b", text, re.M)
        or re.search(r"^crypto key pubkey-chain\b", text, re.M)
        or re.search(r"^aaa authentication (?:login|ssh) .* (?:pubkey|key)\b", text, re.M)
    )
    # Parse VTY line blocks with complete evidence
    vty_lines: list[dict[str, Any]] = []
    covered_vty_lines: set[int] = set()
    for vty_match in re.finditer(r"^line vty (\d+(?:\s+\d+)?)\n((?:[ \t][^\n]*\n?)*)", text, re.M):
        vty_name = vty_match.group(1).strip()
        line_numbers = [int(number) for number in vty_name.split()]
        covered_vty_lines.update(
            range(line_numbers[0], line_numbers[-1] + 1) if len(line_numbers) == 2 else line_numbers
        )
        vty_body = vty_match.group(2)
        transport_parts = re.findall(r"^\s*transport input (.+)$", vty_body, re.M)
        transport = transport_parts[0].strip() if transport_parts else None
        timeout_m = re.search(r"^\s*exec-timeout (\d+) (\d+)", vty_body, re.M)
        timeout_sec: int | None = (
            int(timeout_m.group(1)) * 60 + int(timeout_m.group(2)) if timeout_m else None
        )
        has_login_local = bool(re.search(r"^\s*login local\s*$", vty_body, re.M))
        has_login_auth = bool(re.search(r"^\s*login authentication\s", vty_body, re.M))
        has_line_pubkey = bool(
            re.search(r"^\s*login authentication .*(?:key|pubkey)\b", vty_body, re.M)
        )
        login_method: str | None
        if has_line_pubkey:
            login_method = "key"
        elif has_login_local:
            login_method = "local"
        elif has_login_auth:
            login_method = "authentication_profile"
        elif re.search(r"^\s*login\s*$", vty_body, re.M):
            login_method = "password"
        else:
            login_method = None
        vty_lines.append(
            {
                "name": vty_name,
                "transport_input": transport,
                "exec_timeout_seconds": timeout_sec,
                "login_method": login_method,
            }
        )
    # Record parsed lines. Complete coverage is not universally assumed (e.g. 0-15);
    # uncertainty is preserved unless verified platform evidence or explicit policy is provided.
    vty_coverage_complete: bool | None = None
    _transports = [v["transport_input"] for v in vty_lines if v["transport_input"] is not None]
    telnet_enabled: bool | None
    if any("telnet" in t.lower() or t.lower() == "all" for t in _transports):
        telnet_enabled = True
    elif vty_lines and all(
        v["transport_input"] is not None and v["transport_input"].strip().lower() == "ssh"
        for v in vty_lines
    ):
        telnet_enabled = False
    else:
        telnet_enabled = None
    # HTTP management evidence
    http_enabled: bool | None
    if re.search(r"^no ip http server\b", text, re.M):
        http_enabled = False
    elif re.search(r"^ip http server\b", text, re.M):
        http_enabled = True
    else:
        http_enabled = None
    https_enabled: bool | None
    if re.search(r"^no ip http secure-server\b", text, re.M):
        https_enabled = False
    elif re.search(r"^ip http secure-server\b", text, re.M):
        https_enabled = True
    else:
        https_enabled = None
    ntp_synchronized: bool | None = None
    if re.search(r"\bClock is synchronized\b", op, re.I):
        ntp_synchronized = True
    elif re.search(r"\bClock is (?:not synchronized|unsynchronized)\b", op, re.I):
        ntp_synchronized = False
    # Scoped SNMPv3 token parsing
    valid_auth_algos = {"md5", "sha", "sha-224", "sha-256", "sha-384", "sha-512"}
    valid_priv_algos = {"des", "3des", "aes"}
    v3_users: list[dict[str, Any]] = []
    v3_authpriv_count = 0

    for u_match in re.finditer(r"^snmp-server user (\S+)\s+(\S+)\s+v3\b(.*)$", text, re.M):
        u_name = u_match.group(1)
        u_grp = u_match.group(2)
        tokens = u_match.group(3).strip().split()
        u_auth = None
        u_priv = None
        t_idx = 0
        while t_idx < len(tokens):
            w = tokens[t_idx].lower()
            if w == "auth" and t_idx + 1 < len(tokens):
                cand = tokens[t_idx + 1].lower()
                if cand in valid_auth_algos:
                    u_auth = cand
                    t_idx += 2
                    if t_idx < len(tokens) and tokens[t_idx].lower() not in {"priv", "access"}:
                        t_idx += 1
                    continue
            elif w == "priv" and t_idx + 1 < len(tokens):
                cand = tokens[t_idx + 1].lower()
                if cand in valid_priv_algos:
                    u_priv = cand
                    t_idx += 2
                    if t_idx < len(tokens) and tokens[t_idx] in {"128", "192", "256"}:
                        u_priv = f"{cand}-{tokens[t_idx]}"
                        t_idx += 1
                    if t_idx < len(tokens) and tokens[t_idx].lower() not in {"access"}:
                        t_idx += 1
                    continue
            t_idx += 1
        is_ap = bool(u_auth and u_priv)
        if is_ap:
            v3_authpriv_count += 1
        v3_users.append(
            {"user": u_name, "group": u_grp, "auth": u_auth, "priv": u_priv, "authpriv": is_ap}
        )

    snmp_configured = bool(re.search(r"^snmp-server\b", text, re.M))
    no_snmp_configured = bool(re.search(r"^no snmp-server\b", text, re.M))

    v3_users_present: bool | None
    v3_authpriv_users_present: bool | None
    insecure_v1_v2c_present: bool | None

    if snmp_configured:
        v3_users_present = bool(v3_users)
        v3_authpriv_users_present = bool(v3_authpriv_count > 0)
        insecure_v1_v2c_present = bool(communities)
    elif no_snmp_configured:
        v3_users_present = False
        v3_authpriv_users_present = False
        insecure_v1_v2c_present = False
    else:
        v3_users_present = None
        v3_authpriv_users_present = None
        insecure_v1_v2c_present = None

    return {
        "identity": {
            "hostname": _capture(text, r"^hostname (\S+)", re.M),
            "version": _capture(text, r"^version (\S+)", re.M),
        },
        "management": {
            "ssh_version": _capture(text, r"^ip ssh version (\d+)", re.M),
            "vty_transport": re.findall(r"^ transport input (.+)$", text, re.M),
            "vty_lines": vty_lines,
            "parsed_vty_lines": sorted(covered_vty_lines),
            "vty_coverage_complete": vty_coverage_complete,
            "telnet_enabled": telnet_enabled,
            "has_pubkey": has_pubkey,
            "http_enabled": http_enabled,
            "https_enabled": https_enabled,
        },
        "interfaces": interfaces,
        "acls": acls,
        "named_acl_entries": named_acl_entries,
        "acls_structured": acls_structured,
        "acl_bindings": [
            {
                "interface": match.group(1),
                "acl_id": acl.group(1),
                "direction": acl.group(2),
            }
            for match in re.finditer(r"^interface (\S+)\n((?:[ \t].*\n?)*)", text, re.M)
            for acl in re.finditer(r"^[ \t]+ip access-group (\S+) (in|out)$", match.group(2), re.M)
        ],
        "acl_default_action": "deny",
        "unsupported_acl_semantics": unsupported_acl_semantics,
        "dhcp_snooping": {
            "enabled": bool(re.search(r"^ip dhcp snooping$", text, re.M)),
            "vlans": _vlan_set(text, "ip dhcp snooping vlan"),
        },
        "dynamic_arp_inspection": {"vlans": _vlan_set(text, "ip arp inspection vlan")},
        "management_svis": [i for i in interfaces if i["name"].lower().startswith("vlan")],
        "logging": {"destinations": re.findall(r"^logging host (\S+)", text, re.M)},
        "ntp": {
            "configured_servers": re.findall(r"^ntp server (\S+)", text, re.M),
            "synchronized": ntp_synchronized,
        },
        "snmp": {
            "v3_users_present": v3_users_present,
            "v3_authpriv_users_present": v3_authpriv_users_present,
            "v3_users": v3_users,
            "insecure_v1_v2c_present": insecure_v1_v2c_present,
            "communities": ["<redacted>" for _ in communities],
            "default_community_present": default_community_present,
        },
        "capabilities": {"switching": platform == "cisco_switch"},
        "parser": {
            "platform": platform,
            "nx_os_supported": False,
            "unused_inventory_supplied": designated_unused_ports is not None,
        },
    }


def collect_remaining_fixture(
    manifest_path: Path, *, max_bytes: int = MAX_SOURCE_BYTES
) -> FactsEnvelope:
    manifest = _manifest(manifest_path)
    refs, payloads, errors = [], {}, []
    for source in manifest.sources:
        identity, state = source["identity"], source.get("state", "collected")
        if state != "collected":
            errors.append(
                CanonicalError(
                    code=f"SOURCE_{state.upper()}",
                    message=f"{identity} unavailable.",
                    request_id=manifest.asset_id,
                    details={"source_identity": identity},
                    retryable=False,
                )
            )
            continue
        path = _contained(manifest_path, source["file"])
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raise FixtureInputError("SOURCE_TOO_LARGE", "Source exceeds limit.")
        payloads[identity] = raw
        refs.append(
            EvidenceReference(
                sha256=hashlib.sha256(raw).hexdigest(),
                source_identity=identity,
                artifact_location=str(path),
                timestamp=manifest.collected_at,
            )
        )
    if manifest.platform == "sophos_firewall":
        facts = parse_sophos_xml(_required(payloads, "sophos_api_xml"))
    elif manifest.platform == "palo_alto_panos":
        facts = parse_panos_xml(_required(payloads, "panos_config_xml"))
    else:
        facts = parse_cisco_ios_sources(
            _required(payloads, "running_config"),
            payloads.get("show_output"),
            platform=manifest.platform,
            designated_unused_ports=manifest.designated_unused_ports,
        )
    facts["collection"] = {"completeness": manifest.completeness, "synthetic": True}
    if isinstance(facts.get("snmp"), dict):
        facts["snmp"]["configuration_complete"] = manifest.completeness == "complete"
    return FactsEnvelope(
        org_id=manifest.org_id,
        asset_id=manifest.asset_id,
        platform=manifest.platform,
        vendor={
            "sophos_firewall": "Sophos",
            "palo_alto_panos": "Palo Alto Networks",
            "cisco_router": "Cisco",
            "cisco_switch": "Cisco",
        }[manifest.platform],
        model=manifest.model,
        os_or_firmware_version=manifest.illustrative_version,
        collector_version="0.1.0",
        collection_method="offline_vendor_shaped_fixture",
        collected_at=manifest.collected_at,
        facts=facts,
        evidence_refs=refs,
        supported_capabilities=["vendor_shaped_parse", "deterministic_replay"],
        unsupported_capabilities=["live_collection", "evaluation", "simulation", "remediation"],
        errors=errors,
    )


def probe_remaining_fixture(path: Path) -> dict[str, Any]:
    m = _manifest(path)
    return {
        "schema_version": "1.0.0",
        "platform": m.platform,
        "synthetic": True,
        "label": m.label,
        "illustrative_version": m.illustrative_version,
        "live_transport": "UNSUPPORTED",
    }


def _safe_xml(content: bytes) -> ET.Element:
    if len(content) > MAX_SOURCE_BYTES:
        raise FixtureInputError("SOURCE_TOO_LARGE", "XML exceeds limit.")
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise FixtureInputError("UNSAFE_XML", "DTD and entity declarations are rejected.")
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise FixtureInputError("MALFORMED_XML", "Vendor XML is malformed.") from exc


def _manifest(path: Path) -> RemainingDeviceManifest:
    try:
        m = RemainingDeviceManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FixtureInputError("MALFORMED_DEVICE_MANIFEST", "Manifest invalid.") from exc
    if not m.synthetic or m.platform not in PLATFORMS:
        raise FixtureInputError("UNSUPPORTED_DEVICE_FIXTURE", "Fixture rejected.")
    return m


def _contained(manifest: Path, relative: str) -> Path:
    base = manifest.resolve().parent
    candidate = (base / relative).resolve()
    if Path(relative).is_absolute() or (candidate != base and base not in candidate.parents):
        raise FixtureInputError("INVALID_FIXTURE_PATH", "Source escapes fixture directory.")
    return candidate


def _required(payloads: dict[str, bytes], identity: str) -> bytes:
    if identity not in payloads:
        raise DeviceEngineError("REQUIRED_SOURCE_UNAVAILABLE", f"{identity} unavailable.")
    return payloads[identity]


def _decode(value: bytes | None) -> str:
    try:
        return (value or b"").decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        raise FixtureInputError("INVALID_ENCODING", "Source must be UTF-8.") from exc


def _attrs(element: ET.Element | None) -> dict[str, Any] | None:
    return dict(element.attrib) if element is not None else None


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _text(e: ET.Element, path: str) -> str | None:
    return e.findtext(path)


def _members(e: ET.Element, path: str) -> list[str]:
    return [m.text or "" for m in e.findall(f"{path}/member")]


def _first_name(e: ET.Element, path: str) -> str | None:
    return x.get("name") if (x := e.find(path)) is not None else None


def _capture(text: str, pattern: str, flags: int = 0) -> str | None:
    return m.group(1) if (m := re.search(pattern, text, flags)) else None


def _oper_status(text: str, name: str) -> str | None:
    return _capture(text, rf"^{re.escape(name)}\s+(up|down|administratively down)\b", re.M)


def _vlan_set(text: str, prefix: str) -> list[str]:
    return [
        v
        for line in re.findall(rf"^{re.escape(prefix)} (.+)$", text, re.M)
        for v in line.split(",")
    ]


def _wildcard_to_cidr(ip_str: str, wildcard_str: str) -> str | None:
    try:
        w_int = int(ipaddress.IPv4Address(wildcard_str))
        mask_int = 0xFFFFFFFF ^ w_int
        binary_mask = f"{mask_int:032b}"
        if "01" in binary_mask:
            return None
        prefix_len = binary_mask.count("1")
        net = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
        return str(net)
    except Exception:
        return None


def _parse_acl_host_group(parts: list[str]) -> tuple[dict[str, Any] | None, list[str]]:
    if not parts:
        return None, parts
    token = parts[0].lower()
    if token == "any":
        return {"type": "any", "cidr": "0.0.0.0/0"}, parts[1:]
    if token == "host" and len(parts) > 1:
        ip = parts[1]
        return {"type": "host", "address": ip, "cidr": f"{ip}/32"}, parts[2:]
    if len(parts) > 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
        ip = parts[0]
        wildcard = parts[1]
        cidr = _wildcard_to_cidr(ip, wildcard)
        return {"type": "network", "address": ip, "wildcard": wildcard, "cidr": cidr}, parts[2:]
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
        return {"type": "host", "address": token, "cidr": f"{token}/32"}, parts[1:]
    return None, parts


def _parse_acl_port(parts: list[str]) -> tuple[dict[str, Any] | None, list[str]]:
    if not parts:
        return None, parts
    op = parts[0].lower()
    NAMED_PORTS = {
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "domain": 53,
        "http": 80,
        "www": 80,
        "pop3": 110,
        "ntp": 123,
        "snmp": 161,
        "https": 443,
        "rdp": 3389,
    }
    if op in ("eq", "neq", "gt", "lt") and len(parts) > 1:
        port_raw = parts[1].lower()
        port_num = NAMED_PORTS.get(port_raw)
        if port_num is None:
            try:
                port_num = int(port_raw)
            except ValueError:
                port_num = None
        ports = [port_num] if port_num is not None else [port_raw]
        return {"operator": op, "ports": ports}, parts[2:]
    if op == "range" and len(parts) > 2:
        p1_raw = parts[1].lower()
        p2_raw = parts[2].lower()
        p1 = NAMED_PORTS.get(p1_raw, p1_raw)
        p2 = NAMED_PORTS.get(p2_raw, p2_raw)
        try:
            ports = list(range(int(p1), int(p2) + 1))
        except (ValueError, TypeError):
            ports = [p1, p2]
        return {"operator": "range", "ports": ports}, parts[3:]
    return None, parts


def _parse_acl_entry(syntax: str) -> dict[str, Any]:
    syntax = syntax.strip()
    parts = syntax.split()
    if not parts:
        return {"raw": syntax, "parsed": False}
    action = parts[0].lower()
    if action not in {"permit", "deny"}:
        return {"raw": syntax, "parsed": False}
    rest = parts[1:]
    PROTOCOLS = {"ip", "tcp", "udp", "icmp", "ospf", "eigrp", "gre", "esp", "ahp"}
    protocol = "ip"
    if rest and rest[0].lower() in PROTOCOLS:
        protocol = rest[0].lower()
        rest = rest[1:]
    elif rest and rest[0].isdigit():
        protocol = rest[0]
        rest = rest[1:]

    src, rest = _parse_acl_host_group(rest)
    src_port, rest = _parse_acl_port(rest)
    dst, rest = _parse_acl_host_group(rest)
    dst_port, rest = _parse_acl_port(rest)

    return {
        "raw": syntax,
        "parsed": True,
        "action": action,
        "protocol": protocol,
        "src": src,
        "src_port": src_port,
        "dst": dst,
        "dst_port": dst_port,
    }
