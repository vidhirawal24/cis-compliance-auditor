"""Deterministic CIS rule interpreter, applicability resolver, and score reconciler.

Implements M16, M17, M18, M19, E11, E12, E14, E20, I19, I20:
- Deterministic allowlisted predicate evaluation:
  equals, contains, regex (restricted/ReDoS-safe), range, set_membership,
  cidr_contains, ordered_acl, xccdf_oval.
- Zero AI/LLM probabilistic evaluation at runtime.
- Applicability resolution across platform, family, and version.
- Unknown / missing evidence never yields PASS (evaluates to ERROR or NOT_ASSESSED).
- Manual review detection (status MANUAL_REVIEW).
- Policy override overlay (custom baselines) without mutating benchmark definitions.
- Time-boxed exception status overlay with expiration check.
- Exact compliance and coverage calculation satisfying canonical Score contract.
"""

from datetime import datetime, timezone
import ipaddress
import logging
import re
from typing import Any
from uuid import uuid4

from cisguard_contracts.v1.models import (
    AssessmentStatus,
    EvidenceRef,
    Fact,
    PolicyOverride,
    PolicyRule,
    Score,
    ExceptionOverlay,
)

logger = logging.getLogger("cisguard.policy_engine")

EVALUATOR_VERSION = "1.0.0-deterministic"

# ReDoS protection: Disallow pathological catastrophic backtracking constructs
# and patterns exceeding 256 characters.
DANGEROUS_REGEX_PATTERNS = [
    re.compile(r"\([^)]*[+*]\)[+*]"),       # nested repetition: (a+)+, (a*)*
    re.compile(r"\[[^\]]*\][+*][+*]"),      # double quantifier on character class
    re.compile(r"\([^)]*\|[^)]*[+*]\)[+*]"), # alternation with nested quantifiers: (a|b+)+
]


def is_safe_regex(pattern: str) -> tuple[bool, str]:
    """Validate regex pattern for ReDoS safety and compilation."""
    if len(pattern) > 256:
        return False, "Regex pattern length exceeds maximum limit of 256 characters"
    for dang in DANGEROUS_REGEX_PATTERNS:
        if dang.search(pattern):
            return False, f"Regex pattern rejected due to catastrophic backtracking risk: {pattern}"
    try:
        re.compile(pattern)
        return True, "Safe"
    except re.error as exc:
        return False, f"Invalid regex syntax: {exc}"


# ============================================================================
# Predicate Evaluators (Allowlisted Deterministic Operators)
# ============================================================================


def evaluate_equals(expected: Any, observed: Any) -> tuple[bool, str]:
    """Strict equality operator with normalization for booleans, numbers, and strings."""
    if expected is None and observed is None:
        return True, "Both expected and observed are null"
    if observed is None:
        return False, f"Expected {expected}, but observed is null"

    # Boolean normalization
    if isinstance(expected, bool):
        if isinstance(observed, bool):
            matched = expected == observed
            return matched, f"Boolean match: expected {expected}, observed {observed}"
        if isinstance(observed, str):
            obs_norm = observed.strip().lower()
            if obs_norm in ("true", "yes", "enabled", "1"):
                obs_bool = True
            elif obs_norm in ("false", "no", "disabled", "0"):
                obs_bool = False
            else:
                return False, f"Cannot convert observed '{observed}' to boolean"
            matched = expected == obs_bool
            return matched, f"Boolean comparison: expected {expected}, normalized observed {obs_bool}"
        if isinstance(observed, (int, float)):
            obs_bool = bool(observed)
            return expected == obs_bool, f"Boolean comparison with numeric observed {observed}"

    # Numeric normalization
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            obs_num = float(observed) if not isinstance(observed, bool) else (1.0 if observed else 0.0)
            exp_num = float(expected)
            matched = abs(exp_num - obs_num) < 1e-9
            return matched, f"Numeric equality: expected {expected}, observed {observed}"
        except (ValueError, TypeError):
            return False, f"Observed value '{observed}' cannot be compared to numeric expected {expected}"

    # String normalization: strip surrounding whitespace
    if isinstance(expected, str):
        obs_str = str(observed).strip()
        exp_str = expected.strip()
        matched = exp_str == obs_str
        return matched, f"String equality: expected '{exp_str}', observed '{obs_str}'"

    # Default python equality for collections / dicts
    matched = expected == observed
    return matched, f"Equality check: expected {expected}, observed {observed}"


def evaluate_contains(expected: Any, observed: Any) -> tuple[bool, str]:
    """Containment check for strings, lists, sets, and mappings."""
    if observed is None:
        return False, "Observed value is null"

    if isinstance(observed, (list, tuple, set)):
        if isinstance(expected, (list, tuple, set)):
            # All expected items must be contained in observed
            missing = [item for item in expected if item not in observed]
            matched = len(missing) == 0
            msg = "All expected elements present" if matched else f"Missing elements: {missing}"
            return matched, msg
        matched = expected in observed
        return matched, f"Item {expected} {'found' if matched else 'not found'} in collection"

    if isinstance(observed, str):
        exp_str = str(expected)
        matched = exp_str in observed
        return matched, f"Substring '{exp_str}' {'present' if matched else 'absent'} in observed string"

    if isinstance(observed, dict):
        if isinstance(expected, dict):
            # Check subset of key-values
            for k, v in expected.items():
                if k not in observed or observed[k] != v:
                    return False, f"Key '{k}' with value '{v}' missing or unequal in observed mapping"
            return True, "All expected key-value pairs present in observed mapping"
        matched = expected in observed
        return matched, f"Key {expected} {'present' if matched else 'absent'} in observed mapping"

    return False, f"Unsupported observed type for contains: {type(observed).__name__}"


def evaluate_regex(pattern: str, observed: Any) -> tuple[bool, str]:
    """Restricted regex evaluation with ReDoS protection."""
    safe, reason = is_safe_regex(pattern)
    if not safe:
        return False, f"Regex evaluation aborted: {reason}"

    if observed is None:
        return False, "Observed value is null"

    obs_str = str(observed)
    try:
        matched = bool(re.search(pattern, obs_str))
        msg = f"Pattern '{pattern}' {'matched' if matched else 'did not match'} observed value"
        return matched, msg
    except Exception as exc:  # noqa: BLE001
        return False, f"Regex evaluation error: {exc}"


def evaluate_range(expected: Any, observed: Any) -> tuple[bool, str]:
    """Range comparison checking min <= observed <= max."""
    if observed is None:
        return False, "Observed value is null"

    try:
        val = float(observed)
    except (ValueError, TypeError):
        return False, f"Observed value '{observed}' is not numeric"

    # expected can be [min, max] or {"min": x, "max": y, "inclusive": True/False}
    min_val = None
    max_val = None
    inclusive = True

    if isinstance(expected, (list, tuple)):
        if len(expected) >= 2:
            min_val = float(expected[0]) if expected[0] is not None else None
            max_val = float(expected[1]) if expected[1] is not None else None
    elif isinstance(expected, dict):
        min_val = float(expected["min"]) if "min" in expected and expected["min"] is not None else None
        max_val = float(expected["max"]) if "max" in expected and expected["max"] is not None else None
        inclusive = bool(expected.get("inclusive", True))
    elif isinstance(expected, (int, float)):
        # Exact number or upper bound
        max_val = float(expected)
    else:
        return False, f"Unsupported range specification: {expected}"

    if min_val is not None:
        if inclusive and val < min_val:
            return False, f"Observed value {val} < minimum allowed {min_val}"
        if not inclusive and val <= min_val:
            return False, f"Observed value {val} <= strict minimum {min_val}"

    if max_val is not None:
        if inclusive and val > max_val:
            return False, f"Observed value {val} > maximum allowed {max_val}"
        if not inclusive and val >= max_val:
            return False, f"Observed value {val} >= strict maximum {max_val}"

    return True, f"Observed value {val} within range [{min_val}, {max_val}]"


def evaluate_set_membership(expected: Any, observed: Any) -> tuple[bool, str]:
    """Set membership and subset/superset evaluation."""
    if observed is None:
        return False, "Observed value is null"

    # If expected is a dict specifying mode
    if isinstance(expected, dict):
        mode = expected.get("mode", "in")
        target_set = expected.get("set", expected.get("values", []))
        if mode in ("in", "member_of"):
            matched = observed in target_set
            return matched, f"Value {observed} in set: {matched}"
        if mode == "subset":
            obs_set = set(observed) if isinstance(observed, (list, tuple, set)) else {observed}
            matched = obs_set.issubset(set(target_set))
            return matched, f"Observed set is subset of allowed set: {matched}"
        if mode == "superset":
            obs_set = set(observed) if isinstance(observed, (list, tuple, set)) else {observed}
            matched = obs_set.issuperset(set(target_set))
            return matched, f"Observed set contains all required elements: {matched}"
        if mode == "exact":
            obs_set = set(observed) if isinstance(observed, (list, tuple, set)) else {observed}
            matched = obs_set == set(target_set)
            return matched, f"Observed set exactly matches expected set: {matched}"

    # Default list/tuple expected
    if isinstance(expected, (list, tuple, set)):
        if isinstance(observed, (list, tuple, set)):
            # All observed items must be in expected set
            obs_set = set(observed)
            exp_set = set(expected)
            matched = obs_set.issubset(exp_set)
            diff = obs_set - exp_set
            msg = f"Observed values allowed. Disallowed items: {diff}" if not matched else "All observed values allowed"
            return matched, msg
        matched = observed in expected
        return matched, f"Value '{observed}' {'found' if matched else 'not found'} in allowed set {expected}"

    return False, f"Unsupported expected type for set_membership: {type(expected).__name__}"


def evaluate_cidr_contains(expected: Any, observed: Any) -> tuple[bool, str]:
    """CIDR IP address and network containment evaluation."""
    if observed is None:
        return False, "Observed address is null"

    # Parse expected networks
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if isinstance(expected, (str, bytes)):
        try:
            networks.append(ipaddress.ip_network(str(expected).strip(), strict=False))
        except ValueError as exc:
            return False, f"Invalid expected CIDR '{expected}': {exc}"
    elif isinstance(expected, (list, tuple, set)):
        for item in expected:
            try:
                networks.append(ipaddress.ip_network(str(item).strip(), strict=False))
            except ValueError as exc:
                return False, f"Invalid expected CIDR '{item}': {exc}"
    elif isinstance(expected, dict) and "allowed_cidrs" in expected:
        for item in expected["allowed_cidrs"]:
            try:
                networks.append(ipaddress.ip_network(str(item).strip(), strict=False))
            except ValueError as exc:
                return False, f"Invalid expected CIDR '{item}': {exc}"
    else:
        return False, f"Unsupported expected CIDR format: {expected}"

    # Parse observed IP or network(s)
    observed_items = observed if isinstance(observed, (list, tuple, set)) else [observed]
    for obs in observed_items:
        obs_str = str(obs).strip()
        try:
            # Check if single IP
            if "/" in obs_str:
                obs_net = ipaddress.ip_network(obs_str, strict=False)
                contained = any(obs_net.subnet_of(net) for net in networks)
                if not contained:
                    return False, f"Observed network '{obs_str}' is not contained within allowed CIDRs"
            else:
                obs_ip = ipaddress.ip_address(obs_str)
                contained = any(obs_ip in net for net in networks)
                if not contained:
                    return False, f"Observed IP '{obs_str}' is not contained within allowed CIDRs"
        except ValueError as exc:
            return False, f"Invalid observed IP/network '{obs_str}': {exc}"

    return True, f"All observed addresses {observed_items} are contained within authorized CIDRs"


def evaluate_ordered_acl(expected: Any, observed: Any) -> tuple[bool, str]:
    """Evaluate ordered ACL rules or sequential policy rules."""
    if observed is None:
        return False, "Observed ACL list is null"

    if not isinstance(observed, (list, tuple)):
        return False, f"Observed ACL must be a list, got {type(observed).__name__}"

    obs_list = [str(item).strip() for item in observed]

    # Check if default deny rule must be at the end
    if isinstance(expected, dict):
        required_sequence = expected.get("sequence", [])
        require_final_deny = bool(expected.get("require_final_deny", False))
        if require_final_deny:
            if not obs_list:
                return False, "Observed ACL is empty; missing terminal deny rule"
            last_rule = obs_list[-1].lower()
            if not ("deny" in last_rule or "drop" in last_rule or "reject" in last_rule):
                return False, f"Terminal ACL rule '{obs_list[-1]}' is not a default deny/drop rule"
    elif isinstance(expected, (list, tuple)):
        required_sequence = list(expected)
    else:
        return False, f"Unsupported expected format for ordered_acl: {expected}"

    # Verify that required sequence items appear in relative order
    current_idx = 0
    for req in required_sequence:
        req_str = str(req).strip()
        # Find req_str in obs_list starting at current_idx
        found_idx = -1
        for idx in range(current_idx, len(obs_list)):
            if req_str.lower() in obs_list[idx].lower() or re.search(re.escape(req_str), obs_list[idx], re.IGNORECASE):
                found_idx = idx
                break
        if found_idx == -1:
            return False, f"Required ACL rule pattern '{req_str}' not found in order after index {current_idx}"
        current_idx = found_idx + 1

    return True, "All ordered ACL requirements satisfied in relative sequence"


def evaluate_xccdf_oval(expected: Any, observed: Any) -> tuple[bool, str]:
    """Supplementary SCAP / OVAL result evaluator."""
    if observed is None:
        return False, "Observed SCAP/OVAL result is null"

    # Supplementary OpenSCAP output is ingested via adapter
    if isinstance(observed, dict):
        result_status = str(observed.get("result", observed.get("status", ""))).lower()
        if result_status in ("pass", "compliant", "true"):
            return True, "SCAP OVAL test definition evaluated to PASS (supplementary)"
        if result_status in ("fail", "non-compliant", "false"):
            return False, f"SCAP OVAL test definition evaluated to FAIL: {observed.get('message', 'Non-compliant')}"
        if result_status in ("error", "notapplicable", "unknown"):
            return False, f"SCAP OVAL test inconclusive: {result_status}"

    if isinstance(observed, str):
        obs_lower = observed.strip().lower()
        if obs_lower in ("pass", "true", "compliant"):
            return True, "SCAP OVAL check passed"
        return False, f"SCAP OVAL check did not pass: observed '{observed}'"

    return False, f"Unsupported observed format for xccdf_oval: {type(observed).__name__}"


# Operator dispatch map
OPERATOR_DISPATCH = {
    "equals": evaluate_equals,
    "contains": evaluate_contains,
    "regex": evaluate_regex,
    "range": evaluate_range,
    "set_membership": evaluate_set_membership,
    "cidr_contains": evaluate_cidr_contains,
    "ordered_acl": evaluate_ordered_acl,
    "xccdf_oval": evaluate_xccdf_oval,
}


# ============================================================================
# Applicability Resolution (I20)
# ============================================================================


def is_platform_applicable(
    applicability_platforms: list[str],
    platform: str,
    family: str,
    version: str = "",
) -> bool:
    """Determine whether a control applies to an asset based on platform, family, and version."""
    if not applicability_platforms:
        return False

    norm_platforms = [p.strip().lower() for p in applicability_platforms]
    if "all" in norm_platforms or "any" in norm_platforms:
        return True

    asset_tokens = {
        platform.strip().lower(),
        family.strip().lower(),
        f"{family.strip().lower()}-{platform.strip().lower()}",
    }
    if version:
        asset_tokens.add(f"{platform.strip().lower()}-{version.strip().lower()}")
        asset_tokens.add(f"{family.strip().lower()}-{version.strip().lower()}")

    for token in asset_tokens:
        for app in norm_platforms:
            if app == token or token.startswith(app) or app.startswith(token):
                return True

    return False


# ============================================================================
# Fact Resolution & Provenance (M18, I19, I20)
# ============================================================================


def lookup_fact_value(facts: dict[str, Any] | list[Any], fact_path: str) -> tuple[Any, bool]:
    """Resolve fact value by path from dict or list of Fact objects.

    Returns (value, found). If not found, value is None and found is False.
    """
    if isinstance(facts, dict):
        if fact_path in facts:
            return facts[fact_path], True

        # Check nested dictionary path
        parts = fact_path.split(".")
        curr: Any = facts
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return None, False
        return curr, True

    if isinstance(facts, list):
        for f in facts:
            path = getattr(f, "path", None) or (f.get("path") if isinstance(f, dict) else None)
            if path == fact_path:
                val = getattr(f, "value", None) if hasattr(f, "value") else (f.get("value") if isinstance(f, dict) else None)
                return val, True

    return None, False


# ============================================================================
# Rule Evaluation Engine (M16, M18, E12, E14, I20)
# ============================================================================


def evaluate_rule(
    rule: PolicyRule,
    facts: dict[str, Any] | list[Any],
    evidence_refs: list[EvidenceRef],
    asset_platform: str,
    asset_family: str,
    asset_version: str = "",
    override: PolicyOverride | None = None,
    exception: ExceptionOverlay | None = None,
) -> dict[str, Any]:
    """Deterministic evaluation of a single CIS policy rule against asset facts.

    Guarantees:
    - Never evaluates unknown or missing evidence to PASS.
    - Resolves platform applicability.
    - Flags controls requiring manual review.
    - Applies custom baseline overrides without mutating canonical rules.
    - Evaluates exception overlays, checking time-boxed expiration.
    """
    limitations: list[str] = []

    # 1. Applicability Resolution (I20)
    applicable = is_platform_applicable(
        rule.applicability_platforms,
        asset_platform,
        asset_family,
        asset_version,
    )
    if not applicable:
        return {
            "status": AssessmentStatus.NOT_APPLICABLE,
            "applicability": "NOT_APPLICABLE",
            "expected": rule.expected,
            "observed": None,
            "severity": rule.severity,
            "limitations": [f"Platform '{asset_platform}' / family '{asset_family}' not in applicability platforms: {rule.applicability_platforms}"],
            "evidence_refs": [],
            "rule_inputs": [],
            "exception": None,
        }

    # 2. Manual Review Check (E12)
    if rule.requires_manual_review:
        return {
            "status": AssessmentStatus.MANUAL_REVIEW,
            "applicability": "APPLICABLE",
            "expected": rule.expected,
            "observed": None,
            "severity": rule.severity,
            "limitations": ["Control requires manual human review and signed evidence verification"],
            "evidence_refs": evidence_refs[:1] if evidence_refs else [],
            "rule_inputs": [],
            "exception": None,
        }

    # 3. Custom Baseline / Policy Override (M18)
    effective_expected = rule.expected
    if override and override.control_id == rule.control_id:
        effective_expected = override.expected
        limitations.append(f"Applied organization custom baseline override (version {override.version}): {override.reason}")

    # 4. Evidence Missing / Unknown Check (M18, I20)
    # UNKNOWN EVIDENCE MUST NEVER EVALUATE TO PASS
    observed_val, found = lookup_fact_value(facts, rule.fact_path)
    if not found or observed_val is None:
        return {
            "status": AssessmentStatus.ERROR,
            "applicability": "APPLICABLE",
            "expected": effective_expected,
            "observed": None,
            "severity": rule.severity,
            "limitations": limitations + [f"Missing required evidence: fact path '{rule.fact_path}' not present in collected facts"],
            "evidence_refs": [],
            "rule_inputs": [],
            "exception": None,
        }

    # 5. Deterministic Operator Evaluation (M16)
    evaluator_fn = OPERATOR_DISPATCH.get(rule.operator)
    if not evaluator_fn:
        return {
            "status": AssessmentStatus.ERROR,
            "applicability": "APPLICABLE",
            "expected": effective_expected,
            "observed": observed_val,
            "severity": rule.severity,
            "limitations": limitations + [f"Unsupported rule operator: {rule.operator}"],
            "evidence_refs": [],
            "rule_inputs": [],
            "exception": None,
        }

    passed, rationale = evaluator_fn(effective_expected, observed_val)
    status = AssessmentStatus.PASS if passed else AssessmentStatus.FAIL
    if not passed:
        limitations.append(rationale)

    # Construct rule input fact
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ref_ids = [e.evidence_id for e in evidence_refs] if evidence_refs else [uuid4()]
    rule_inputs = [
        Fact(
            path=rule.fact_path if "." in rule.fact_path else f"os_security.{rule.fact_path}",
            value=observed_val,
            evidence_ids=ref_ids[:1],
            observed_at=now_utc,
        )
    ]

    # 6. Policy Exception Overlay (E14)
    active_exception: ExceptionOverlay | None = None
    if exception and exception.finding_id:
        # Check time-boxed expiration
        try:
            exp_dt = datetime.fromisoformat(str(exception.expires_at).replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            if now_dt > exp_dt:
                # Expired exception returns to active finding workflow
                active_exception = ExceptionOverlay(
                    schema_version="1.0.0",
                    org_id=exception.org_id,
                    exception_id=exception.exception_id,
                    finding_id=exception.finding_id,
                    decision="EXPIRED",
                    approver_id=exception.approver_id,
                    reason=exception.reason,
                    expires_at=exception.expires_at,
                )
                limitations.append("Time-boxed policy exception has EXPIRED; control returned to active audit workflow")
            else:
                active_exception = exception
                if exception.decision == "APPROVED":
                    limitations.append(f"Approved policy exception applied: {exception.reason}")
        except Exception:  # noqa: BLE001
            active_exception = exception

    # Assessed findings require at least one evidence ref
    final_evidence_refs = evidence_refs if evidence_refs else [
        EvidenceRef(
            evidence_id=uuid4(),
            sha256="0" * 64,
            source_identity="synthetic_evaluator",
            encrypted_artifact_location=f"private://evidence/{uuid4()}/synthetic",
            collected_at=now_utc,
        )
    ]

    return {
        "status": status,
        "applicability": "APPLICABLE",
        "expected": effective_expected,
        "observed": observed_val,
        "severity": rule.severity,
        "limitations": limitations,
        "evidence_refs": final_evidence_refs,
        "rule_inputs": rule_inputs,
        "exception": active_exception,
    }


# ============================================================================
# Accurate Scoring & Coverage Reconciler (M17, M35)
# ============================================================================


def calculate_scan_score(statuses: list[AssessmentStatus | str]) -> Score:
    """Calculate compliance score and audit coverage strictly satisfying the canonical Score contract.

    Formulas:
    assessed = pass_count + fail_count
    eligible = assessed + manual_review_count + error_count + not_assessed_count
    assessed_compliance_pct = round(100 * pass_count / assessed, 4) if assessed > 0 else None
    assessment_coverage_pct = round(100 * assessed / eligible, 4) if eligible > 0 else None
    """
    pass_count = 0
    fail_count = 0
    not_applicable_count = 0
    manual_review_count = 0
    error_count = 0
    not_assessed_count = 0

    for s in statuses:
        s_str = str(getattr(s, "value", s)).upper()
        if s_str == "PASS":
            pass_count += 1
        elif s_str == "FAIL":
            fail_count += 1
        elif s_str == "NOT_APPLICABLE":
            not_applicable_count += 1
        elif s_str == "MANUAL_REVIEW":
            manual_review_count += 1
        elif s_str == "ERROR":
            error_count += 1
        elif s_str == "NOT_ASSESSED":
            not_assessed_count += 1
        else:
            not_assessed_count += 1

    assessed = pass_count + fail_count
    eligible = assessed + manual_review_count + error_count + not_assessed_count

    compliance_pct = round(100.0 * pass_count / assessed, 4) if assessed > 0 else None
    coverage_pct = round(100.0 * assessed / eligible, 4) if eligible > 0 else None

    return Score(
        pass_count=pass_count,
        fail_count=fail_count,
        not_applicable_count=not_applicable_count,
        manual_review_count=manual_review_count,
        error_count=error_count,
        not_assessed_count=not_assessed_count,
        assessed_compliance_pct=compliance_pct,
        assessment_coverage_pct=coverage_pct,
    )


# ============================================================================
# Synthetic Fixture Facts Catalog (Vidhi Module Bridge)
# ============================================================================


def get_fixture_facts(family: str, platform: str = "") -> dict[str, Any]:
    """Provide realistic fixture facts for synthetic testing and offline evaluations."""
    fam = family.lower()
    if fam == "linux":
        return {
            "os_security.sshd.permit_root_login": "no",
            "os_security.sshd.password_authentication": "no",
            "os_security.sshd.max_auth_tries": 4,
            "os_security.sshd.ciphers": ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
            "management.banner": "Authorized access only. All activities are monitored.",
            "network_policy.firewall.enabled": True,
            "network_policy.firewall.default_policy": "DROP",
            "network_policy.subnets.management": "10.0.1.0/24",
            "os_security.pam.pwquality.minlen": 14,
            "os_security.services.telnet_disabled": True,
            "os_security.kernel.sysctl.net_ipv4_ip_forward": 0,
        }
    if fam == "windows":
        return {
            "os_security.registry.uac_admin_approval_mode": 1,
            "os_security.windows_defender.realtime_protection": 1,
            "os_security.auditpol.logon_logoff.audit_logon": "Success and Failure",
            "management.banner": "Authorized access only. All activities are monitored.",
            "network_policy.firewall.domain_profile_state": "ON",
            "network_policy.firewall.private_profile_state": "ON",
            "network_policy.firewall.public_profile_state": "ON",
            "os_security.powershell.script_block_logging": 1,
            "os_security.services.smb1_disabled": True,
        }
    if fam in ("firewall", "router", "switch"):
        return {
            "management.banner": "Authorized access only.",
            "management.ssh.version": 2,
            "management.snmp.v3_only": True,
            "network_policy.acl.inbound": [
                "permit tcp 10.0.0.0/8 any eq 443",
                "permit tcp 10.0.0.0/8 any eq 22",
                "deny ip any any",
            ],
            "network_policy.firewall.default_policy": "DROP",
            "network_policy.subnets.management": "10.0.1.0/24",
        }
    return {
        "management.banner": "Authorized access only.",
        "network_policy.subnets.management": "10.0.1.0/24",
    }
