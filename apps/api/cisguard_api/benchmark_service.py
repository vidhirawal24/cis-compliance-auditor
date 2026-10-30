"""Benchmark management registry, versioning, diff engine, and SCAP bridge adapter.

Implements M16, M17, M19, E11, E12, E20, I19:
- Modular YAML, JSON, and XML policy pack parsing and validation.
- Canonical content hashing (content_sha256) for reproducible immutability.
- Source attribution and rights metadata enforcement:
  source: authorized_cis_mapping, organizational, validated_scap_mapping
  rights_status: UNREVIEWED, AUTHORIZED, RESTRICTED
- Benchmark version diff calculation (added, removed, modified controls).
- Benchmark upgrade preview across organization assets.
- Secure SCAP / XCCDF XML bridge with XXE mitigation.
- Supplementary SCAP data labeling (never automatically equivalent to CIS).
"""

from copy import deepcopy
import hashlib
import json
import logging
from typing import Any
from uuid import UUID, uuid4

import yaml
from lxml import etree
from sqlalchemy import select
from sqlalchemy.orm import Session

from cisguard_contracts.v1.models import (
    PolicyDiff,
    PolicyPack as WirePolicyPack,
)
from .db_models import (
    Asset,
    PolicyPack as DBPolicyPack,
    PolicyRule as DBPolicyRule,
)
from .policy_engine import is_platform_applicable

logger = logging.getLogger("cisguard.benchmark_service")

SCAP_SUPPLEMENTARY_DISCLAIMER = (
    "OpenSCAP / ComplianceAsCode content is supplementary; "
    "never automatically equivalent to official CIS benchmarks without review."
)


# ============================================================================
# Content Hashing & Serialization (M17, M19)
# ============================================================================


def compute_content_sha256(data: dict[str, Any] | list[Any] | str | bytes) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON representation."""
    if isinstance(data, (dict, list)):
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return hashlib.sha256(payload).hexdigest()


# ============================================================================
# Policy Pack Validation & Parsing (M17, E11)
# ============================================================================


def parse_policy_pack_document(raw_content: str | bytes) -> dict[str, Any]:
    """Parse YAML or JSON document defining a policy pack with rules.

    Raises ValueError if document syntax or schema is invalid.
    """
    if isinstance(raw_content, bytes):
        raw_text = raw_content.decode("utf-8")
    else:
        raw_text = raw_content

    raw_text = raw_text.strip()
    if not raw_text:
        raise ValueError("Policy pack document is empty")

    try:
        if raw_text.startswith("{") or raw_text.startswith("["):
            data = json.loads(raw_text)
        else:
            data = yaml.safe_load(raw_text)
    except Exception as exc:
        raise ValueError(f"Failed to parse policy pack document: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Root of policy pack document must be a dictionary")

    # Validate mandatory header fields
    required_fields = ["benchmark_id", "benchmark_release", "pack_version", "profiles", "rules"]
    for req in required_fields:
        if req not in data:
            raise ValueError(f"Policy pack document missing required field: '{req}'")

    if not isinstance(data["profiles"], list) or not data["profiles"]:
        raise ValueError("Field 'profiles' must be a non-empty list of profile names")

    if not isinstance(data["rules"], list):
        raise ValueError("Field 'rules' must be a list of rule definitions")

    # Validate rights_status
    rights = data.get("rights_status", "UNREVIEWED")
    if rights not in ("UNREVIEWED", "AUTHORIZED", "RESTRICTED"):
        raise ValueError(f"Invalid rights_status '{rights}'; must be UNREVIEWED, AUTHORIZED, or RESTRICTED")

    # Validate source
    source = data.get("source", "authorized_cis_mapping")
    if source not in ("authorized_cis_mapping", "organizational", "validated_scap_mapping"):
        raise ValueError(f"Invalid source '{source}'; must be authorized_cis_mapping, organizational, or validated_scap_mapping")

    # Validate individual rules
    seen_controls: set[str] = set()
    for idx, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule at index {idx} must be a dictionary")

        control_id = rule.get("control_id")
        if not control_id or not isinstance(control_id, str):
            raise ValueError(f"Rule at index {idx} has invalid or missing 'control_id'")

        if control_id in seen_controls:
            raise ValueError(f"Duplicate control_id '{control_id}' in policy pack")
        seen_controls.add(control_id)

        # Validate operator
        op = rule.get("operator", "equals")
        valid_ops = {"equals", "contains", "regex", "range", "set_membership", "cidr_contains", "ordered_acl", "xccdf_oval"}
        if op not in valid_ops:
            raise ValueError(f"Rule '{control_id}' has invalid operator '{op}'. Allowed: {sorted(valid_ops)}")

        # Validate severity
        sev = rule.get("severity", "MEDIUM")
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise ValueError(f"Rule '{control_id}' has invalid severity '{sev}'")

        # Validate applicability platforms
        platforms = rule.get("applicability_platforms", [])
        if not isinstance(platforms, list) or not platforms:
            raise ValueError(f"Rule '{control_id}' must specify a non-empty list for 'applicability_platforms'")

    return data


# ============================================================================
# Benchmark Diff Engine (M19, E20)
# ============================================================================


def compute_benchmark_diff(
    from_pack: DBPolicyPack | WirePolicyPack,
    to_pack: DBPolicyPack | WirePolicyPack,
    from_rules: list[DBPolicyRule | dict[str, Any]],
    to_rules: list[DBPolicyRule | dict[str, Any]],
) -> PolicyDiff:
    """Compute version diff identifying added, removed, and modified controls between two benchmark packs."""
    from_map: dict[str, dict[str, Any]] = {}
    for r in from_rules:
        cid = r.control_id if hasattr(r, "control_id") else r["control_id"]
        defn = r.definition if hasattr(r, "definition") else r
        from_map[cid] = defn

    to_map: dict[str, dict[str, Any]] = {}
    for r in to_rules:
        cid = r.control_id if hasattr(r, "control_id") else r["control_id"]
        defn = r.definition if hasattr(r, "definition") else r
        to_map[cid] = defn

    from_cids = set(from_map.keys())
    to_cids = set(to_map.keys())

    added = sorted(to_cids - from_cids)
    removed = sorted(from_cids - to_cids)
    modified = []

    common = from_cids & to_cids
    critical_fields = ["operator", "expected", "fact_path", "severity", "applicability_platforms", "requires_manual_review"]

    for cid in sorted(common):
        r1 = from_map[cid]
        r2 = to_map[cid]
        for field in critical_fields:
            v1 = r1.get(field)
            v2 = r2.get(field)
            if v1 != v2:
                modified.append(cid)
                break

    to_pack_id = getattr(to_pack, "id", getattr(to_pack, "policy_pack_id", uuid4()))

    return PolicyDiff(
        policy_pack_id=to_pack_id,
        from_version=from_pack.pack_version,
        to_version=to_pack.pack_version,
        added_control_ids=added,
        removed_control_ids=removed,
        modified_control_ids=modified,
    )


# ============================================================================
# Upgrade Preview Engine (I19)
# ============================================================================


def preview_benchmark_upgrade(
    db: Session,
    org_id: UUID,
    from_pack_id: UUID,
    to_pack_id: UUID,
) -> dict[str, Any]:
    """Preview benchmark upgrade impact across organization assets (I19)."""
    from_pack = db.scalar(
        select(DBPolicyPack).where(DBPolicyPack.org_id == org_id, DBPolicyPack.id == from_pack_id)
    )
    if not from_pack:
        raise ValueError(f"Origin policy pack {from_pack_id} not found")

    to_pack = db.scalar(
        select(DBPolicyPack).where(DBPolicyPack.org_id == org_id, DBPolicyPack.id == to_pack_id)
    )
    if not to_pack:
        raise ValueError(f"Target policy pack {to_pack_id} not found")

    from_rules = db.scalars(
        select(DBPolicyRule).where(DBPolicyRule.org_id == org_id, DBPolicyRule.policy_pack_id == from_pack_id)
    ).all()
    to_rules = db.scalars(
        select(DBPolicyRule).where(DBPolicyRule.org_id == org_id, DBPolicyRule.policy_pack_id == to_pack_id)
    ).all()

    diff = compute_benchmark_diff(from_pack, to_pack, list(from_rules), list(to_rules))

    # Query active organization assets
    assets = db.scalars(
        select(Asset).where(Asset.org_id == org_id, Asset.retired.is_(False))
    ).all()

    # Rule definitions for checking applicability
    to_rule_map = {r.control_id: r.definition for r in to_rules}
    from_rule_map = {r.control_id: r.definition for r in from_rules}

    affected_assets_count = 0
    asset_impacts = []

    for a in assets:
        added_app = 0
        for cid in diff.added_control_ids:
            rule_defn = to_rule_map.get(cid, {})
            platforms = rule_defn.get("applicability_platforms", [])
            if is_platform_applicable(platforms, a.platform, a.family, a.os_or_firmware_version or ""):
                added_app += 1

        removed_app = 0
        for cid in diff.removed_control_ids:
            rule_defn = from_rule_map.get(cid, {})
            platforms = rule_defn.get("applicability_platforms", [])
            if is_platform_applicable(platforms, a.platform, a.family, a.os_or_firmware_version or ""):
                removed_app += 1

        modified_app = 0
        for cid in diff.modified_control_ids:
            rule_defn = to_rule_map.get(cid, {})
            platforms = rule_defn.get("applicability_platforms", [])
            if is_platform_applicable(platforms, a.platform, a.family, a.os_or_firmware_version or ""):
                modified_app += 1

        is_affected = (added_app + removed_app + modified_app) > 0
        if is_affected:
            affected_assets_count += 1

        asset_impacts.append({
            "asset_id": str(a.id),
            "name": a.name,
            "platform": a.platform,
            "family": a.family,
            "added_applicable_controls": added_app,
            "removed_applicable_controls": removed_app,
            "modified_applicable_controls": modified_app,
            "is_affected": is_affected,
        })

    return {
        "diff": diff.model_dump(mode="json"),
        "total_assets": len(assets),
        "affected_assets": affected_assets_count,
        "asset_impacts": asset_impacts,
    }


# ============================================================================
# SCAP Bridge Adapter (E12, supplementary SCAP ingestion)
# ============================================================================


def parse_scap_xccdf_xml(xml_content: str | bytes) -> dict[str, Any]:
    """Parse SCAP XCCDF XML into a normalized CISGuard policy pack structure.

    Security protection:
    - XXE is mitigated by disabling entity resolution and network access in lxml.
    - Labels output as supplementary SCAP mapping with explicit attribution disclaimer.
    """
    if isinstance(xml_content, str):
        xml_bytes = xml_content.encode("utf-8")
    else:
        xml_bytes = xml_content

    # Secure XML parser prohibiting XXE and network resolution
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )

    try:
        root = etree.fromstring(xml_bytes, parser=parser)
    except Exception as exc:
        raise ValueError(f"Failed to parse SCAP XML: {exc}") from exc

    # Namespaces
    _ns = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
    }

    benchmark_id = root.attrib.get("id", f"scap-benchmark-{uuid4().hex[:8]}")
    title_el = root.find(".//{*}title")
    title = title_el.text.strip() if title_el is not None and title_el.text else benchmark_id

    version_el = root.find(".//{*}version")
    version = version_el.text.strip() if version_el is not None and version_el.text else "1.0.0"

    # Extract profiles
    profiles = []
    for prof in root.findall(".//{*}Profile"):
        prof_id = prof.attrib.get("id", "")
        prof_title_el = prof.find("{*}title")
        prof_name = prof_title_el.text.strip() if prof_title_el is not None and prof_title_el.text else prof_id
        if prof_name:
            profiles.append(prof_name)
    if not profiles:
        profiles = ["Default - Standard Profile"]

    # Extract rules
    rules: list[dict[str, Any]] = []
    for rule_el in root.findall(".//{*}Rule"):
        rule_id = rule_el.attrib.get("id", "")
        if not rule_id:
            continue

        rule_title_el = rule_el.find("{*}title")
        rule_title = rule_title_el.text.strip() if rule_title_el is not None and rule_title_el.text else rule_id

        severity_raw = rule_el.attrib.get("severity", "medium").upper()
        severity = severity_raw if severity_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"

        # Platform check
        platforms = []
        for plat_el in rule_el.findall(".//{*}platform"):
            if plat_el.attrib.get("idref"):
                platforms.append(plat_el.attrib["idref"].split(":")[-1].lower())
            elif plat_el.text:
                platforms.append(plat_el.text.strip().lower())
        if not platforms:
            platforms = ["linux"]

        # Control mapping
        rules.append({
            "control_id": rule_id,
            "feature_ids": ["M16", "M17"],
            "fact_path": f"os_security.scap.{rule_id.split('_')[-1]}",
            "operator": "xccdf_oval",
            "expected": {"result": "pass", "source": "openscap"},
            "severity": severity,
            "applicability_platforms": platforms,
            "requires_manual_review": False,
            "remediation_template_id": None,
            "title": rule_title,
            "profiles": profiles,
            "limitations": [SCAP_SUPPLEMENTARY_DISCLAIMER],
        })

    if not rules:
        raise ValueError("SCAP document does not contain any parseable XCCDF Rules")

    content_sha256 = compute_content_sha256(xml_bytes)

    return {
        "benchmark_id": benchmark_id,
        "benchmark_release": "scap-supplementary",
        "pack_version": version,
        "profiles": profiles,
        "source": "validated_scap_mapping",
        "source_reference": f"SCAP-XCCDF Import: {title} ({SCAP_SUPPLEMENTARY_DISCLAIMER})",
        "rights_status": "UNREVIEWED",
        "evaluator_version": "1.0.0-scap-bridge",
        "content_sha256": content_sha256,
        "rules": rules,
    }


# ============================================================================
# Canonical Built-in Policy Packs (Ubuntu, Windows, Network)
# ============================================================================


def get_builtin_policy_pack(pack_type: str) -> dict[str, Any]:
    """Provide canonical benchmark packs for standard testing and initial provisioning."""
    if pack_type == "ubuntu-v1":
        rules = [
            {
                "control_id": "5.2.1",
                "feature_ids": ["M16", "M03"],
                "fact_path": "os_security.sshd.permit_root_login",
                "operator": "equals",
                "expected": "no",
                "severity": "CRITICAL",
                "applicability_platforms": ["linux", "ubuntu"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Server", "Level 2 - Server"],
                "title": "Ensure SSH PermitRootLogin is disabled",
            },
            {
                "control_id": "5.2.2",
                "feature_ids": ["M16", "M03"],
                "fact_path": "os_security.sshd.password_authentication",
                "operator": "equals",
                "expected": "no",
                "severity": "HIGH",
                "applicability_platforms": ["linux", "ubuntu"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Server", "Level 2 - Server"],
                "title": "Ensure SSH PasswordAuthentication is disabled",
            },
            {
                "control_id": "5.2.3",
                "feature_ids": ["M16", "M03"],
                "fact_path": "os_security.sshd.max_auth_tries",
                "operator": "range",
                "expected": {"min": 1, "max": 4},
                "severity": "MEDIUM",
                "applicability_platforms": ["linux", "ubuntu"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Server"],
                "title": "Ensure SSH MaxAuthTries is between 1 and 4",
            },
            {
                "control_id": "5.2.4",
                "feature_ids": ["M16", "M03"],
                "fact_path": "os_security.sshd.ciphers",
                "operator": "set_membership",
                "expected": ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
                "severity": "HIGH",
                "applicability_platforms": ["linux", "ubuntu"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 2 - Server"],
                "title": "Ensure only approved ciphers are used",
            },
            {
                "control_id": "1.7.1",
                "feature_ids": ["M16", "M03", "E12"],
                "fact_path": "management.banner",
                "operator": "contains",
                "expected": "Authorized access only",
                "severity": "LOW",
                "applicability_platforms": ["linux", "ubuntu"],
                "requires_manual_review": True,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Server"],
                "title": "Ensure message of the day is configured (Manual review)",
            },
        ]
        return {
            "benchmark_id": "cis-ubuntu-linux",
            "benchmark_release": "22.04-lts",
            "pack_version": "1.0.0",
            "profiles": ["Level 1 - Server", "Level 2 - Server"],
            "source": "authorized_cis_mapping",
            "source_reference": "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0",
            "rights_status": "AUTHORIZED",
            "evaluator_version": "1.0.0-deterministic",
            "rules": rules,
        }

    if pack_type == "ubuntu-v2":
        # Upgraded version with 1 added, 1 removed, 1 modified control for diff testing (M19, E20, I19)
        base = get_builtin_policy_pack("ubuntu-v1")
        base["pack_version"] = "2.0.0"
        base["source_reference"] = "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0"
        rules = deepcopy(base["rules"])
        # Remove 5.2.3
        rules = [r for r in rules if r["control_id"] != "5.2.3"]
        # Modify 5.2.1 expected or severity
        for r in rules:
            if r["control_id"] == "5.2.1":
                r["severity"] = "CRITICAL"
                r["operator"] = "equals"
                r["expected"] = "prohibit-password"  # modified expected
        # Add new rule 3.4.1
        rules.append({
            "control_id": "3.4.1",
            "feature_ids": ["M16", "M03"],
            "fact_path": "network_policy.firewall.enabled",
            "operator": "equals",
            "expected": True,
            "severity": "HIGH",
            "applicability_platforms": ["linux", "ubuntu"],
            "requires_manual_review": False,
            "remediation_template_id": None,
            "profiles": ["Level 1 - Server"],
            "title": "Ensure UFW or nftables firewall is active",
        })
        base["rules"] = rules
        return base

    if pack_type == "windows-v1":
        rules = [
            {
                "control_id": "2.3.1.1",
                "feature_ids": ["M16", "M01"],
                "fact_path": "os_security.registry.uac_admin_approval_mode",
                "operator": "equals",
                "expected": 1,
                "severity": "HIGH",
                "applicability_platforms": ["windows", "windows-11"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Enterprise"],
                "title": "Ensure User Account Control: Admin Approval Mode is Enabled",
            },
            {
                "control_id": "2.3.17.1",
                "feature_ids": ["M16", "M01"],
                "fact_path": "os_security.windows_defender.realtime_protection",
                "operator": "equals",
                "expected": 1,
                "severity": "CRITICAL",
                "applicability_platforms": ["windows", "windows-11"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1 - Enterprise"],
                "title": "Ensure Windows Defender Real-time Protection is Enabled",
            },
        ]
        return {
            "benchmark_id": "cis-windows-11",
            "benchmark_release": "23h2",
            "pack_version": "1.0.0",
            "profiles": ["Level 1 - Enterprise"],
            "source": "authorized_cis_mapping",
            "source_reference": "CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0",
            "rights_status": "AUTHORIZED",
            "evaluator_version": "1.0.0-deterministic",
            "rules": rules,
        }

    # Default fallback network benchmark
    return {
        "benchmark_id": "cis-network-devices",
        "benchmark_release": "1.0.0",
        "pack_version": "1.0.0",
        "profiles": ["Level 1"],
        "source": "authorized_cis_mapping",
        "source_reference": "CIS Network Devices Benchmark v1.0.0",
        "rights_status": "AUTHORIZED",
        "evaluator_version": "1.0.0-deterministic",
        "rules": [
            {
                "control_id": "1.1",
                "feature_ids": ["M16", "M05"],
                "fact_path": "management.banner",
                "operator": "contains",
                "expected": "Authorized access only",
                "severity": "LOW",
                "applicability_platforms": ["firewall", "router", "switch"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1"],
                "title": "Ensure login banner is configured",
            },
            {
                "control_id": "2.1",
                "feature_ids": ["M16", "M05"],
                "fact_path": "network_policy.acl.inbound",
                "operator": "ordered_acl",
                "expected": {"sequence": ["permit", "deny"], "require_final_deny": True},
                "severity": "HIGH",
                "applicability_platforms": ["firewall", "router"],
                "requires_manual_review": False,
                "remediation_template_id": None,
                "profiles": ["Level 1"],
                "title": "Ensure inbound ACL terminates with default deny",
            },
        ],
    }


# ============================================================================
# Database Installation & Persistence (M17, M19)
# ============================================================================


def install_policy_pack_in_db(
    db: Session,
    org_id: UUID,
    pack_data: dict[str, Any],
) -> tuple[DBPolicyPack, list[DBPolicyRule]]:
    """Install or retrieve a parsed policy pack and its rules in tenant database."""
    content_sha256 = pack_data.get("content_sha256") or compute_content_sha256(pack_data)

    # Check if pack already exists
    existing = db.scalar(
        select(DBPolicyPack).where(
            DBPolicyPack.org_id == org_id,
            DBPolicyPack.benchmark_id == pack_data["benchmark_id"],
            DBPolicyPack.pack_version == pack_data["pack_version"],
        )
    )
    if existing:
        rules = db.scalars(
            select(DBPolicyRule).where(
                DBPolicyRule.org_id == org_id,
                DBPolicyRule.policy_pack_id == existing.id,
            )
        ).all()
        return existing, list(rules)

    pack_id = uuid4()
    db_pack = DBPolicyPack(
        id=pack_id,
        org_id=org_id,
        benchmark_id=pack_data["benchmark_id"],
        benchmark_release=pack_data["benchmark_release"],
        pack_version=pack_data["pack_version"],
        profiles=pack_data["profiles"],
        source=pack_data.get("source", "authorized_cis_mapping"),
        source_reference=pack_data.get("source_reference", "https://cisecurity.org"),
        rights_status=pack_data.get("rights_status", "AUTHORIZED"),
        evaluator_version=pack_data.get("evaluator_version", "1.0.0-deterministic"),
        content_sha256=content_sha256,
    )
    db.add(db_pack)
    db.flush()

    db_rules: list[DBPolicyRule] = []
    for r in pack_data.get("rules", []):
        rule_record = DBPolicyRule(
            id=uuid4(),
            org_id=org_id,
            policy_pack_id=pack_id,
            control_id=r["control_id"],
            definition=r,
        )
        db.add(rule_record)
        db_rules.append(rule_record)

    db.flush()
    return db_pack, db_rules

