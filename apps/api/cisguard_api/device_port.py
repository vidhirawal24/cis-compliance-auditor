"""Synthetic device-engine port and capability registry.

Follows the canonical v1 contracts. Provides typed collection, failure isolation
simulation, and strict CIDR safety checking for SSRF mitigation.
"""

from datetime import datetime, timezone
import hashlib
import ipaddress
from typing import Any
from uuid import UUID

from cisguard_contracts.v1.models import Capabilities
from .fixture_mode import enabled as fixture_enabled


class DevicePortError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


# Capabilities by platform and family
CAPABILITIES_CATALOG: dict[str, dict[str, list[str]]] = {
    "windows": {
        "supported": [
            "auditpol.subcategory",
            "registry.policy",
            "powershell.security",
            "windows.firewall",
            "windows.services",
            "lgpo.export",
        ],
        "unsupported": [
            "selinux.state",
            "iptables.rules",
            "cisco.ios.acl",
        ],
    },
    "linux": {
        "supported": [
            "sshd.config",
            "pam.auth",
            "auditd.rules",
            "sysctl.params",
            "systemctl.services",
            "ufw.status",
            "nftables.rules",
            "openscap.oval",
        ],
        "unsupported": [
            "registry.policy",
            "windows.defender",
            "cisco.show.running",
        ],
    },
    "firewall": {
        "supported": [
            "firewall.policies",
            "admin.access.ssh_https",
            "logging.syslog",
            "ntp.configuration",
            "banner.login",
            "firmware.version",
        ],
        "unsupported": [
            "windows.registry",
            "systemd.services",
        ],
    },
    "router": {
        "supported": [
            "cisco.ios.running_config",
            "acl.inbound_outbound",
            "snmp.v3_only",
            "line_vty.transport",
            "ospf.auth",
            "logging.buffered",
        ],
        "unsupported": [
            "pam.auth",
            "registry.policy",
        ],
    },
    "switch": {
        "supported": [
            "port_security.max_mac",
            "bpdu_guard.enabled",
            "dhcp_snooping.vlan",
            "vtp.mode_transparent",
            "dot1x.authentication",
            "mgmt_vlan.restricted",
        ],
        "unsupported": [
            "windows.registry",
            "auditpol.subcategory",
        ],
    },
}


def get_asset_capabilities(asset_id: UUID, family: str, platform: str, vendor: str) -> Capabilities:
    """Return deterministic capabilities based on asset family, platform, and vendor."""
    if not fixture_enabled():
        return Capabilities(asset_id=asset_id, supported=[], unsupported=['device_engine_not_connected'], compatibility_status='UNTESTED')
    family_lower = family.lower()
    cat = CAPABILITIES_CATALOG.get(family_lower, {
        "supported": ["basic.connectivity", "syslog.check"],
        "unsupported": ["advanced.vendor_api"],
    })
    return Capabilities(
        asset_id=asset_id,
        supported=cat["supported"],
        unsupported=cat["unsupported"],
        compatibility_status="FIXTURE_TESTED",
    )


def validate_discovery_cidr(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate that CIDR is well-formed and disallow dangerous/metadata networks (SSRF mitigation)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from exc

    # Reject loopback, link-local, multicast, unspecified
    if network.is_loopback:
        raise ValueError(f"Loopback addresses forbidden: {cidr}")
    if network.is_link_local:
        raise ValueError(f"Link-local addresses (including cloud metadata 169.254.0.0/16) forbidden: {cidr}")
    if network.is_multicast:
        raise ValueError(f"Multicast addresses forbidden: {cidr}")
    if network.is_unspecified:
        raise ValueError(f"Unspecified network forbidden: {cidr}")

    # Specific check for AWS/GCP/Azure link-local metadata address 169.254.169.254
    metadata_ip = ipaddress.ip_address("169.254.169.254")
    if isinstance(network, ipaddress.IPv4Network) and metadata_ip in network:
        raise ValueError(f"Cloud instance metadata network forbidden: {cidr}")

    return network


def collect_device_facts(asset: Any, mode: str = "read_only") -> dict[str, Any]:
    """Execute typed collection against the asset port using synthetic fixture stub.

    Detects simulated failure targets for test isolation.
    """
    if mode != 'read_only':
        raise DevicePortError('UNSUPPORTED','Only read-only collection is allowed')
    if not fixture_enabled():
        raise DevicePortError('UNSUPPORTED','Device engine is not connected; no real evidence collected')
    target = getattr(asset, "target", "") or ""
    tags = getattr(asset, "tags", []) or []

    # Simulated failure modes for testing multi-target failure isolation (M13)
    if "simulate_timeout" in tags or target.endswith(".timeout"):
        raise DevicePortError("TIMEOUT", f"Connection to target {target} timed out after 30s", retryable=True)
    if "simulate_auth_failed" in tags or target.endswith(".authfail"):
        raise DevicePortError("AUTH_FAILED", f"Credential authentication rejected by target {target}", retryable=False)
    if "simulate_unreachable" in tags or target.endswith(".unreachable"):
        raise DevicePortError("DEVICE_UNAVAILABLE", f"Host {target} is unreachable / host down", retryable=True)

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    family = getattr(asset, "family", "linux")
    asset_id = str(getattr(asset, "id", getattr(asset, "asset_id", "")))
    org_id = str(getattr(asset, "org_id", ""))

    content_str = f"snapshot:{org_id}:{asset_id}:{target}:{now}"
    sha256_hash = hashlib.sha256(content_str.encode()).hexdigest()

    return {
        "status": "SUCCEEDED",
        "collected_at": now,
        "mode": mode,
        "provenance": {
            "asset_id": asset_id,
            "org_id": org_id,
            "target": target,
            "family": family,
            "collector_version": "1.0.0-synthetic",
        },
        "artifact_ref": f"private://config-snapshots/{org_id}/{asset_id}/{sha256_hash}",
        "content_sha256": sha256_hash,
    }

