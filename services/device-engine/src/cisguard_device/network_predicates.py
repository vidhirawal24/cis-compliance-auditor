"""Evidence-aware, deterministic device-specific predicates for M20–M33.

OWNERSHIP: This module supplies device-specific predicate results and
candidate finding evidence. It does NOT implement central policy evaluation,
CIS scoring, findings persistence, or compliance percentages — those remain
Mandar's responsibility.

Each predicate result includes:
- A stable internal check ID (DEV-Mxx-NNN), distinct from official CIS IDs
- The project feature ID
- Asset/org identity
- Assessment status using canonical AssessmentStatus enums
- Actual evidence and expected policy requirement
- Evidence references
- Explanation, applicability and coverage limitations
- Structured error code and actionable remediation guidance

SUPPORTED PLATFORMS: cisco_router, cisco_switch (IOS 15 / IOS-XE 16/17)

UNSUPPORTED (explicitly NOT_ASSESSED):
- Sophos, PAN-OS, FortiOS, Cisco ASA/FTD, Check Point — lack the structured
  management/ACL/switch facts required by these predicates.
- Linux/Windows — not network control devices.

EXIT-CODE CONVENTION:
- Assessments containing FAIL findings are STILL a successfully completed
  assessment. The caller (CLI) should exit 0 for a completed assessment,
  even if results contain FAIL findings.
- Exit 2 is reserved for invalid input or execution failure.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from .models import AssessmentStatus, FactsEnvelope, StrictModel

# ---------------------------------------------------------------------------
# Policy parameter model
# ---------------------------------------------------------------------------

_DEFAULT_SENSITIVE_PORTS = [22, 23, 80, 443, 445, 3389]
_SUPPORTED_CISCO_PLATFORMS = {"cisco_router", "cisco_switch"}
_CHECK_FEATURES = {
    "DEV-M20-001": "M20",
    # DEV-M21-001 checks HTTP management; historical internal check ID contains M21,
    # but the documented control belongs to M20 (Management Plane Security).
    "DEV-M21-001": "M20",
    "DEV-M21-002": "M21",
    "DEV-M21-003": "M21",
    "DEV-M21-004": "M21",
    "DEV-M22-001": "M22",
    "DEV-M23-001": "M23",
    "DEV-M24-001": "M24",
    "DEV-M25-001": "M25",
    "DEV-M26-001": "M26",
    "DEV-M27-001": "M27",
    "DEV-M28-001": "M28",
    "DEV-M29-001": "M29",
    "DEV-M30-001": "M30",
    "DEV-M31-001": "M31",
    "DEV-M32-001": "M32",
    "DEV-M32-002": "M32",
    "DEV-M33-001": "M33",
    "DEV-M33-002": "M33",
    "DEV-M33-003": "M33",
    "DEV-M33-004": "M33",
}


def predicate_feature_map() -> dict[str, str]:
    """Return a copy of the documented M20-M33 feature mapping.

    Check IDs are stable internal identifiers.  Feature IDs deliberately use the
    project M-control IDs, not unrelated delivery feature IDs (for example E05/E08).
    """
    return dict(_CHECK_FEATURES)


class NetworkControlPolicy(StrictModel):
    """Typed, validated policy parameters for M20–M33 network predicates.

    All fields have safe defaults. No executable expressions, shell commands,
    or eval()-able content are accepted.
    """

    session_timeout_seconds: int = Field(
        ge=1,
        description=(
            "Maximum permitted VTY idle timeout in seconds, supplied by organizational policy."
        ),
    )
    sensitive_ports: list[int] = Field(
        default_factory=lambda: list(_DEFAULT_SENSITIVE_PORTS),
        description="TCP/UDP port numbers considered sensitive for M23 ACL checks.",
    )
    required_vlans: list[str] | None = Field(
        default=None,
        description="VLANs that must have DHCP snooping and DAI (M28/M29). None → NOT_ASSESSED.",
    )
    designated_unused_ports: list[str] | None = Field(
        default=None,
        description=(
            "Explicit inventory of interface names designated as unused (M26). "
            "None → NOT_ASSESSED. Do NOT infer from operational down state."
        ),
    )
    management_interface_inventory: list[str] | None = Field(
        default=None,
        description=(
            "Explicit inventory of management-use interfaces (M30). "
            "None → NOT_ASSESSED. SVI existence alone is not management-use evidence."
        ),
    )
    management_interface_inventory_complete: bool = Field(
        default=False,
        description="Whether management_interface_inventory is complete for this asset.",
    )
    interface_roles: (
        dict[str, Literal["access", "trunk", "uplink", "management", "unused"]] | None
    ) = Field(
        default=None,
        description=(
            "Explicit interface-role inventory; required to assess access-port applicability."
        ),
    )
    max_acl_complexity: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum ACL rule count before shadowing analysis returns MANUAL_REVIEW.",
    )
    broad_source_prefix_threshold: int = Field(
        default=8,
        ge=0,
        le=32,
        description=(
            "Maximum CIDR prefix length considered a broadly permissive source in M22/M23. "
            "Supplied by organizational policy (default 8, meaning /8 or broader is broad)."
        ),
    )
    expected_vty_lines: list[int] | list[str] | None = Field(
        default=None,
        description=(
            "Explicit declared or verified VTY lines inventory (e.g. [0, 1, 2, 3, 4]). "
            "Required to establish complete VTY coverage when platform evidence is absent."
        ),
    )

    @field_validator("sensitive_ports")
    @classmethod
    def _validate_sensitive_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("sensitive_ports values must be between 1 and 65535")
        return sorted(set(values))

    @field_validator("required_vlans")
    @classmethod
    def _validate_required_vlans(cls, values: list[str] | None) -> list[str] | None:
        if values is not None and any(
            not value.isdigit() or not 1 <= int(value) <= 4094 for value in values
        ):
            raise ValueError("required_vlans must contain VLAN IDs from 1 through 4094")
        return list(dict.fromkeys(values)) if values is not None else None


# ---------------------------------------------------------------------------
# Predicate result model
# ---------------------------------------------------------------------------


class PredicateResult(StrictModel):
    """Device-specific predicate result for a single check.

    This is evidence, not a finding. Mandar's policy engine maps check_id
    to official CIS controls, applies applicability decisions, manages
    exceptions, and persists findings.
    """

    check_id: str = Field(
        description="Stable internal check ID (DEV-Mxx-NNN). Not an official CIS ID."
    )
    feature_id: str = Field(description="Project feature ID.")
    org_id: UUID
    asset_id: UUID
    status: AssessmentStatus
    actual: dict[str, Any] = Field(description="Observed evidence values.")
    expected: dict[str, Any] = Field(description="Policy requirement supplied as input.")
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Source identities from the FactsEnvelope that support this result.",
    )
    explanation: str
    applicability_note: str = Field(
        default="",
        description="Why this check applies or does not apply to this asset.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Coverage and evidence limitations for this result.",
    )
    error_code: str | None = None
    remediation: str | None = Field(
        default=None,
        description="Actionable remediation guidance where technically justified.",
    )


# ---------------------------------------------------------------------------
# Public evaluation entry point
# ---------------------------------------------------------------------------


def evaluate_network_controls(
    envelope: FactsEnvelope,
    policy: NetworkControlPolicy,
) -> list[PredicateResult]:
    """Evaluate M20–M33 network control predicates against a FactsEnvelope.

    Returns a list of PredicateResult objects — one per check. The list is
    always returned; individual results carry their own status.

    An assessment containing FAIL results is still a successfully completed
    assessment. The return value is never empty for supported platforms.

    Unsupported platforms return a single NOT_ASSESSED result explaining why.

    Args:
        envelope: The FactsEnvelope produced by collect_remaining_fixture()
                  or import_offline_file() for a Cisco IOS device.
        policy:   Optional typed policy parameters. Safe defaults are used
                  when None. No executable content is accepted.

    Returns:
        List[PredicateResult] — one per defined check.
    """
    platform = envelope.platform
    if platform not in _SUPPORTED_CISCO_PLATFORMS:
        return _unsupported_platform_results(envelope, platform)

    facts = envelope.facts
    ctx = _CheckContext(
        org_id=envelope.org_id,
        asset_id=envelope.asset_id,
        platform=platform,
        policy=policy,
        evidence_refs=[r.source_identity for r in envelope.evidence_refs],
    )

    results: list[PredicateResult] = []

    # M20 – No Telnet management
    results.append(_check_m20_telnet(facts, ctx))

    # M21 – Secure management protocol (4 sub-checks)
    results.extend(_check_m21_secure_management(facts, ctx))

    # M22 – No broadly permissive ACL rules
    results.append(_check_m22_broad_permit(facts, ctx))

    # M23 – Sensitive port exposure from broad sources
    results.append(_check_m23_sensitive_ports(facts, ctx))

    # M24 – ACL rule shadowing
    results.append(_check_m24_shadowing(facts, ctx))

    # M25 – Default deny policy
    results.append(_check_m25_default_deny(facts, ctx))

    # M26–M30 — switch controls (applicable to both router and switch;
    # non-applicable checks return NOT_APPLICABLE with justification)
    results.append(_check_m26_unused_ports(facts, ctx))
    results.append(_check_m27_port_security(facts, ctx))
    results.append(_check_m28_dhcp_snooping(facts, ctx))
    results.append(_check_m29_dai(facts, ctx))
    results.append(_check_m30_vlan1_management(facts, ctx))

    # M31–M33 — telemetry controls
    results.append(_check_m31_syslog(facts, ctx))
    results.extend(_check_m32_ntp(facts, ctx))
    results.extend(_check_m33_snmp(facts, ctx))

    # Partial/unknown snapshots cannot establish the absence of a bad setting.
    completeness = facts.get("import", {}).get(
        "completeness", facts.get("collection", {}).get("completeness")
    )
    if completeness in {"partial", "unknown"}:
        results = [
            result.model_copy(
                update={
                    "status": AssessmentStatus.NOT_ASSESSED,
                    "error_code": "INCOMPLETE_CAPTURE",
                    "explanation": (
                        f"{result.explanation} Capture completeness is {completeness}; "
                        "a PASS cannot be established from this snapshot."
                    ),
                    "limitations": [*result.limitations, "Capture completeness is not complete."],
                }
            )
            if result.status in {AssessmentStatus.PASS, AssessmentStatus.NOT_ASSESSED}
            else result
            for result in results
        ]

    processing_errors = [
        error for error in envelope.errors if error.code != "CAPTURE_TIMESTAMP_UNKNOWN"
    ]
    if processing_errors:
        primary_error = processing_errors[0]
        results = [
            result.model_copy(
                update={
                    "status": AssessmentStatus.ERROR,
                    "error_code": primary_error.code,
                    "explanation": (
                        "Evaluation blocked by collection/processing error: "
                        f"{primary_error.message}"
                    ),
                }
            )
            for result in results
        ]

    return results


# ---------------------------------------------------------------------------
# Internal check context
# ---------------------------------------------------------------------------


class _CheckContext:
    __slots__ = ("org_id", "asset_id", "platform", "policy", "evidence_refs")

    def __init__(
        self,
        org_id: UUID,
        asset_id: UUID,
        platform: str,
        policy: NetworkControlPolicy,
        evidence_refs: list[str],
    ) -> None:
        self.org_id = org_id
        self.asset_id = asset_id
        self.platform = platform
        self.policy = policy
        self.evidence_refs = evidence_refs


def _result(
    ctx: _CheckContext,
    *,
    check_id: str,
    feature_id: str | None = None,
    status: AssessmentStatus,
    actual: dict[str, Any],
    expected: dict[str, Any],
    explanation: str,
    applicability_note: str = "",
    limitations: list[str] | None = None,
    error_code: str | None = None,
    remediation: str | None = None,
) -> PredicateResult:
    resolved_feature = _CHECK_FEATURES.get(check_id, feature_id or "UNKNOWN")
    return PredicateResult(
        check_id=check_id,
        feature_id=resolved_feature,
        org_id=ctx.org_id,
        asset_id=ctx.asset_id,
        status=status,
        actual=actual,
        expected=expected,
        evidence_refs=list(ctx.evidence_refs),
        explanation=explanation,
        applicability_note=applicability_note,
        limitations=limitations or [],
        error_code=error_code,
        remediation=remediation,
    )


def _is_vty_coverage_complete(mgmt: dict[str, Any], policy: NetworkControlPolicy) -> bool | None:
    """Evaluate whether VTY lines coverage is complete without universal 0-15 assumption."""
    vty_lines = mgmt.get("vty_lines", [])
    if not vty_lines:
        return False

    parsed_line_nums: set[int] = set()
    for v in vty_lines:
        name = str(v.get("name", "")).strip()
        parts = [int(p) for p in re.split(r"[\s-]+", name) if p.isdigit()]
        if len(parts) == 2:
            parsed_line_nums.update(range(parts[0], parts[1] + 1))
        elif len(parts) == 1:
            parsed_line_nums.add(parts[0])

    if policy.expected_vty_lines is not None:
        expected: set[int] = set()
        for item in policy.expected_vty_lines:
            if isinstance(item, int):
                expected.add(item)
            else:
                p_items = [int(p) for p in re.split(r"[\s-]+", str(item).strip()) if p.isdigit()]
                if len(p_items) == 2:
                    expected.update(range(p_items[0], p_items[1] + 1))
                elif len(p_items) == 1:
                    expected.add(p_items[0])
        return expected.issubset(parsed_line_nums)

    # A fixture's generic "complete" assertion is not platform evidence.  Accept
    # only an explicit collector statement that a platform inventory was verified.
    if mgmt.get("vty_inventory_verified") is True:
        return True
    if mgmt.get("vty_inventory_verified") is False:
        return False

    return None


def _unsupported_platform_results(envelope: FactsEnvelope, platform: str) -> list[PredicateResult]:
    return [
        PredicateResult(
            check_id=check_id,
            feature_id=feature_id,
            org_id=envelope.org_id,
            asset_id=envelope.asset_id,
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"platform": platform},
            expected={"supported_platforms": sorted(_SUPPORTED_CISCO_PLATFORMS)},
            evidence_refs=[reference.source_identity for reference in envelope.evidence_refs],
            explanation=(
                f"Platform '{platform}' is unsupported for {check_id}; "
                "the required Cisco IOS/IOS-XE structured facts are unavailable."
            ),
            applicability_note=(
                "Device-specific predicate support is not implemented for this platform."
            ),
            limitations=[
                "Only Cisco IOS 15 and IOS-XE 16/17 router/switch fact subsets are supported."
            ],
            error_code="UNSUPPORTED_PLATFORM",
        )
        for check_id, feature_id in _CHECK_FEATURES.items()
    ]


# ---------------------------------------------------------------------------
# M20 – No Telnet management
# ---------------------------------------------------------------------------

_M20_LIMITATIONS = [
    "Configured VTY transport restrict is not proof that no Telnet service is reachable.",
    "AUX port and console Telnet sessions are not evaluated.",
    "Network-level Telnet reachability requires routing/firewall evidence not available here.",
]


def _check_m20_telnet(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    mgmt = facts.get("management", {})
    telnet_enabled = mgmt.get("telnet_enabled")  # bool or None

    vty_cov = _is_vty_coverage_complete(mgmt, ctx.policy)
    if telnet_enabled is False:
        if vty_cov is not True:
            return _result(
                ctx,
                check_id="DEV-M20-001",
                feature_id="M20",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={
                    "telnet_enabled": False,
                    "vty_coverage_complete": vty_cov,
                },
                expected={"telnet_enabled": False},
                explanation=(
                    "Parsed VTY lines restrict Telnet, "
                    "but complete VTY range coverage is unverified without verified platform "
                    "evidence or declared inventory."
                ),
                limitations=_M20_LIMITATIONS,
                error_code="INCOMPLETE_VTY_COVERAGE",
            )
        return _result(
            ctx,
            check_id="DEV-M20-001",
            feature_id="M20",
            status=AssessmentStatus.PASS,
            actual={"telnet_enabled": False, "vty_transport_evidence": mgmt.get("vty_transport")},
            expected={"telnet_enabled": False},
            explanation=(
                "All configured VTY lines restrict transport input to SSH; Telnet is not permitted."
            ),
            limitations=_M20_LIMITATIONS,
        )
    if telnet_enabled is True:
        return _result(
            ctx,
            check_id="DEV-M20-001",
            feature_id="M20",
            status=AssessmentStatus.FAIL,
            actual={"telnet_enabled": True, "vty_transport_evidence": mgmt.get("vty_transport")},
            expected={"telnet_enabled": False},
            explanation="One or more VTY lines permit Telnet transport input.",
            limitations=_M20_LIMITATIONS,
            remediation=(
                "Configure 'transport input ssh' on all VTY lines. "
                "Remove 'transport input all' and 'transport input telnet'."
            ),
        )
    # None — insufficient evidence
    return _result(
        ctx,
        check_id="DEV-M20-001",
        feature_id="M20",
        status=AssessmentStatus.NOT_ASSESSED,
        actual={"telnet_enabled": None, "vty_lines_parsed": bool(mgmt.get("vty_lines"))},
        expected={"telnet_enabled": False},
        explanation=(
            "VTY transport input evidence is absent or ambiguous. "
            "Cannot determine whether Telnet management access is permitted."
        ),
        limitations=_M20_LIMITATIONS
        + ["No VTY line blocks were parsed or transport input was not configured."],
        error_code="INSUFFICIENT_EVIDENCE",
    )


# ---------------------------------------------------------------------------
# M21 – Secure management protocol
# ---------------------------------------------------------------------------

_M21_HTTP_LIMITATIONS = [
    "Configured 'no ip http server' disables the IOS HTTP server but does not prove "
    "no other HTTP service is reachable.",
    "NAT, load balancers, and upstream devices may expose HTTP independently.",
]

_M21_SSH_LIMITATIONS = [
    "SSH version configured in running config is not proof of lab-validated SSH implementation.",
    "'ip ssh version 2' does not prove key-only authentication.",
]

_M21_TIMEOUT_LIMITATIONS = [
    "VTY exec-timeout is configured idle timeout; it does not limit session duration "
    "from connection.",
    "Console and AUX timeouts are not evaluated.",
]


def _check_m21_secure_management(
    facts: dict[str, Any], ctx: _CheckContext
) -> list[PredicateResult]:
    results: list[PredicateResult] = []
    mgmt = facts.get("management", {})
    policy = ctx.policy

    # DEV-M21-001: No plaintext HTTP
    http_enabled = mgmt.get("http_enabled")
    if http_enabled is False:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-001",
                feature_id="M20",
                status=AssessmentStatus.PASS,
                actual={"http_enabled": False},
                expected={"http_enabled": False},
                explanation=(
                    "'no ip http server' is configured; IOS HTTP management server is disabled."
                ),
                limitations=_M21_HTTP_LIMITATIONS,
            )
        )
    elif http_enabled is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-001",
                feature_id="M20",
                status=AssessmentStatus.FAIL,
                actual={"http_enabled": True},
                expected={"http_enabled": False},
                explanation="'ip http server' is present; IOS HTTP management server is enabled.",
                limitations=_M21_HTTP_LIMITATIONS,
                remediation="Configure 'no ip http server' in global configuration.",
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-001",
                feature_id="M20",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"http_enabled": None},
                expected={"http_enabled": False},
                explanation=(
                    "No 'ip http server' or 'no ip http server' found; HTTP state is unknown."
                ),
                limitations=_M21_HTTP_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    # DEV-M21-002: SSH version 2 required
    ssh_version = mgmt.get("ssh_version")
    if ssh_version == "2":
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-002",
                feature_id="M21",
                status=AssessmentStatus.PASS,
                actual={"ssh_version": "2"},
                expected={"ssh_version": "2"},
                explanation="'ip ssh version 2' is configured.",
                limitations=_M21_SSH_LIMITATIONS,
            )
        )
    elif ssh_version is not None:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-002",
                feature_id="M21",
                status=AssessmentStatus.FAIL,
                actual={"ssh_version": ssh_version},
                expected={"ssh_version": "2"},
                explanation=f"SSH version {ssh_version} is configured; SSHv2 is required.",
                limitations=_M21_SSH_LIMITATIONS,
                remediation="Configure 'ip ssh version 2' in global configuration.",
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-002",
                feature_id="M21",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"ssh_version": None},
                expected={"ssh_version": "2"},
                explanation="No 'ip ssh version' configuration found; SSH version is unknown.",
                limitations=_M21_SSH_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    # DEV-M21-003: SSH key-only authentication
    # Requirement: Sufficient positive evidence of keys configured, allowed authentication
    # methods, and that password authentication is explicitly excluded.
    # "login local" or generic AAA does NOT establish key-only enforcement -> NOT_ASSESSED.
    vty_lines: list[dict[str, Any]] = mgmt.get("vty_lines", [])
    if not vty_lines:
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-003",
                feature_id="M21",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"vty_lines": []},
                expected={"key_only_enforced": True},
                explanation="No VTY line blocks parsed; cannot assess authentication method.",
                limitations=_M21_SSH_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )
    else:
        vty_cov_ok = _is_vty_coverage_complete(mgmt, ctx.policy) is True
        key_auth_states = [v.get("key_authentication_configured") for v in vty_lines]
        pass_excl_states = [v.get("password_authentication_excluded") for v in vty_lines]
        pass_allow_states = [v.get("password_authentication_allowed") for v in vty_lines]

        keys_configured = mgmt.get("key_authentication_configured") is True or (
            key_auth_states and all(k is True for k in key_auth_states)
        )
        passwords_excluded = mgmt.get("password_authentication_excluded") is True or (
            pass_excl_states and all(p is True for p in pass_excl_states)
        )
        passwords_allowed = mgmt.get("password_authentication_allowed") is True or any(
            p is True for p in pass_allow_states
        )
        key_auth_disabled = mgmt.get("key_authentication_configured") is False or any(
            k is False for k in key_auth_states
        )

        # PASS requires keys, password exclusion, and verified VTY scope.
        if keys_configured and passwords_excluded and not passwords_allowed and vty_cov_ok:
            status = AssessmentStatus.PASS
            explanation = (
                "Verified SSH public-key authentication is configured, "
                "password authentication is excluded, and complete VTY scope is established."
            )
            error_code = None
            remediation_text = None
        elif key_auth_disabled or (passwords_allowed and not keys_configured):
            status = AssessmentStatus.FAIL
            explanation = (
                "Evidence demonstrates key-only authentication is not enforced: "
                "password authentication is permitted or key authentication is not configured."
            )
            error_code = None
            remediation_text = (
                "Configure SSH public-key authentication (for example an SSH public-key chain) "
                "and explicitly disable password and keyboard-interactive authentication for SSH."
            )
        else:
            # Ambiguous: login local, generic AAA, or a pubkey without password exclusion.
            status = AssessmentStatus.NOT_ASSESSED
            ambiguities = []
            if not keys_configured:
                ambiguities.append("SSH public keys or authorized key-chains are not verified")
            if not passwords_excluded:
                ambiguities.append(
                    "exclusion of password authentication cannot be established "
                    "from configuration alone"
                )
            if not vty_cov_ok:
                ambiguities.append("complete VTY line scope is unverified")
            explanation = (
                "Cannot establish key-only authentication requirement: "
                + "; ".join(ambiguities)
                + ". Presence of 'login local' or generic AAA does not prove key-only enforcement."
            )
            error_code = "INSUFFICIENT_EVIDENCE"
            remediation_text = None

        results.append(
            _result(
                ctx,
                check_id="DEV-M21-003",
                feature_id="M21",
                status=status,
                actual={
                    "vty_lines": [
                        {
                            "name": v["name"],
                            "login_method": v.get("login_method"),
                            "key_authentication_configured": v.get("key_authentication_configured"),
                            "password_authentication_excluded": v.get(
                                "password_authentication_excluded"
                            ),
                        }
                        for v in vty_lines
                    ],
                    "keys_configured": keys_configured,
                    "passwords_excluded": passwords_excluded,
                },
                expected={"key_only_enforced": True},
                explanation=explanation,
                limitations=_M21_SSH_LIMITATIONS,
                error_code=error_code,
                remediation=remediation_text,
            )
        )

    # DEV-M21-004: Session timeout
    timeouts = [
        v["exec_timeout_seconds"] for v in vty_lines if v["exec_timeout_seconds"] is not None
    ]
    if (
        not vty_lines
        or len(timeouts) != len(vty_lines)
        or _is_vty_coverage_complete(mgmt, ctx.policy) is not True
    ):
        results.append(
            _result(
                ctx,
                check_id="DEV-M21-004",
                feature_id="M21",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"exec_timeout_seconds": None},
                expected={"max_session_timeout_seconds": policy.session_timeout_seconds},
                explanation=(
                    "No exec-timeout configured on VTY lines; session timeout evidence is absent."
                ),
                limitations=_M21_TIMEOUT_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )
    else:
        max_timeout = max(timeouts)
        threshold = policy.session_timeout_seconds
        if 0 < max_timeout <= threshold:
            results.append(
                _result(
                    ctx,
                    check_id="DEV-M21-004",
                    feature_id="M21",
                    status=AssessmentStatus.PASS,
                    actual={"exec_timeout_seconds": timeouts, "max_timeout_seconds": max_timeout},
                    expected={"max_session_timeout_seconds": threshold},
                    explanation=(
                        f"All VTY exec-timeouts ({timeouts}) are within the "
                        f"{threshold}s policy threshold."
                    ),
                    limitations=_M21_TIMEOUT_LIMITATIONS,
                )
            )
        else:
            results.append(
                _result(
                    ctx,
                    check_id="DEV-M21-004",
                    feature_id="M21",
                    status=AssessmentStatus.FAIL,
                    actual={"exec_timeout_seconds": timeouts, "max_timeout_seconds": max_timeout},
                    expected={"max_session_timeout_seconds": threshold},
                    explanation=(
                        "VTY exec-timeout is disabled (0 seconds)."
                        if max_timeout == 0
                        else (
                            f"Maximum VTY exec-timeout ({max_timeout}s) exceeds the "
                            f"policy threshold of {threshold}s."
                        )
                    ),
                    limitations=_M21_TIMEOUT_LIMITATIONS,
                    remediation=(
                        f"Configure 'exec-timeout {threshold // 60} {threshold % 60}' "
                        "or lower on all VTY lines."
                    ),
                )
            )

    return results


# ---------------------------------------------------------------------------
# ACL helpers
# ---------------------------------------------------------------------------

_ANY_NETWORK = ipaddress.IPv4Network("0.0.0.0/0")
_PROTOCOLS = {"ip", "tcp", "udp"}
_NAMED_PORTS = {
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "www": 80,
    "http": 80,
    "https": 443,
    "snmp": 161,
    "ntp": 123,
    "rdp": 3389,
}
_MAX_PORT_RANGE_WIDTH = 4096


def _wildcard_to_network(host: str, wildcard: str) -> ipaddress.IPv4Network | None:
    """Convert a Cisco host+wildcard pair to an IPv4Network, or None if non-contiguous."""
    try:
        h_int = int(ipaddress.IPv4Address(host))
        w_int = int(ipaddress.IPv4Address(wildcard))
        # Check contiguous mask: wildcard must be all-zeros followed by all-ones
        # i.e. (w_int + 1) must be a power of 2, or w_int == 0
        if w_int != 0 and (w_int & (w_int + 1)) != 0:
            return None  # non-contiguous wildcard — not supported
        mask_int = 0xFFFFFFFF ^ w_int
        prefix_len = bin(mask_int).count("1")
        network_addr = ipaddress.IPv4Address(h_int & mask_int)
        return ipaddress.IPv4Network(f"{network_addr}/{prefix_len}", strict=False)
    except (ValueError, OverflowError):
        return None


def _parse_acl_host_group(
    parts: list[str],
) -> tuple[ipaddress.IPv4Network | None | str, list[str]]:
    """Parse src or dst from tokenized ACL syntax. Returns (network_or_sentinel, remaining)."""
    if not parts:
        return None, parts
    token = parts[0].lower()
    if token == "any":
        return _ANY_NETWORK, parts[1:]
    if token == "host":
        if len(parts) < 2:
            return None, parts
        try:
            net = ipaddress.IPv4Network(f"{parts[1]}/32")
            return net, parts[2:]
        except ValueError:
            return "UNRESOLVED", parts[2:]
    # Try address + wildcard
    if len(parts) >= 2:
        net = _wildcard_to_network(parts[0], parts[1])
        if net is not None:
            return net, parts[2:]
        # Non-contiguous wildcard or FQDN object — unresolvable
        return "UNRESOLVED", parts[2:]
    return "UNRESOLVED", parts[1:]


def _parse_port_spec(
    parts: list[str],
) -> tuple[set[int] | None, list[str]]:
    """Parse optional port specifier (eq/range/gt/lt). Returns (port_set_or_None, remaining)."""
    if not parts:
        return None, parts
    op = parts[0].lower()

    def port_value(value: str) -> int:
        return _NAMED_PORTS.get(value.lower(), int(value) if value.isdigit() else -1)

    if op == "eq" and len(parts) >= 2:
        port = port_value(parts[1])
        return ({port}, parts[2:]) if 0 <= port <= 65535 else (None, parts)
    if op == "range" and len(parts) >= 3:
        lo, hi = port_value(parts[1]), port_value(parts[2])
        return (
            (set(range(lo, hi + 1)), parts[3:])
            if 0 <= lo <= hi <= 65535 and hi - lo + 1 <= _MAX_PORT_RANGE_WIDTH
            else (None, parts)
        )
    return None, parts


def _parse_single_acl_entry(syntax: str) -> dict[str, Any]:
    """Parse one ACL permit/deny line into a structured dict.

    Returns a dict with keys: action, protocol, src, src_port, dst, dst_port,
    parsed (bool), unresolved (bool), unsupported_construct (str|None).
    """
    parts = syntax.strip().split()
    if not parts or parts[0] not in {"permit", "deny"}:
        return {"parsed": False, "raw": syntax, "action": None}

    action = parts[0]
    rest = parts[1:]
    unresolved = False
    unsupported_construct: str | None = None
    protocol: str = "ip"

    if rest and rest[0].lower() in _PROTOCOLS:
        protocol = rest[0].lower()
        rest = rest[1:]
    elif (
        rest
        and rest[0].lower() not in {"any", "host"}
        and not re.match(r"^\d+\.\d+\.\d+\.\d+$", rest[0])
    ):
        unsupported_construct = "protocol"

    src, rest = _parse_acl_host_group(rest)
    if src == "UNRESOLVED":
        unresolved = True
        src = None

    src_ports: set[int] | None = None
    if protocol in {"tcp", "udp"}:
        src_ports, rest = _parse_port_spec(rest)

    dst, rest = _parse_acl_host_group(rest)
    if dst == "UNRESOLVED":
        unresolved = True
        dst = None

    dst_ports: set[int] | None = None
    if protocol in {"tcp", "udp"}:
        dst_ports, rest = _parse_port_spec(rest)

    # Check for unsupported constructs in remaining tokens
    if rest:
        remaining_lower = " ".join(rest).lower()
        for keyword in (
            "reflect",
            "evaluate",
            "time-range",
            "log-input",
            "fragments",
            "established",
            "object-group",
            "log",
            "match-all",
            "match-any",
        ):
            if keyword in remaining_lower:
                unsupported_construct = keyword
                break
    if rest and rest[0].lower() in {"eq", "neq", "range", "gt", "lt"}:
        unsupported_construct = "unsupported_port_spec"

    return {
        "parsed": True,
        "raw": syntax,
        "action": action,
        "protocol": protocol,
        "src": src,
        "src_port": src_ports,
        "dst": dst,
        "dst_port": dst_ports,
        "unresolved": unresolved,
        "unsupported_construct": unsupported_construct,
    }


def _is_broad_source(network: ipaddress.IPv4Network | None, threshold: int = 8) -> bool:
    """Return True if source network covers /threshold or larger, or is any."""
    if network is None:
        return False
    return network == _ANY_NETWORK or network.prefixlen <= threshold


def _network_contains(outer: ipaddress.IPv4Network, inner: ipaddress.IPv4Network) -> bool:
    """Return True if outer contains inner (outer is a supernet-of-or-equal to inner)."""
    return outer.supernet_of(inner) or outer == inner


def _rules_overlap(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    if any(
        rule.get("unresolved") or not rule.get("parsed") or rule.get("unsupported_construct")
        for rule in (earlier, later)
    ):
        return False
    earlier_protocol, later_protocol = earlier.get("protocol", "ip"), later.get("protocol", "ip")
    if earlier_protocol != "ip" and later_protocol != "ip" and earlier_protocol != later_protocol:
        return False
    for key in ("src", "dst"):
        first, second = earlier.get(key), later.get(key)
        if not isinstance(first, ipaddress.IPv4Network) or not isinstance(
            second, ipaddress.IPv4Network
        ):
            return False
        if not first.overlaps(second):
            return False
    if later_protocol in {"tcp", "udp"} or earlier_protocol in {"tcp", "udp"}:
        for key in ("src_port", "dst_port"):
            first, second = earlier.get(key), later.get(key)
            if first is not None and second is not None and not first.intersection(second):
                return False
    return True


def _port_set_covered(earlier_ports: set[int] | None, later_ports: set[int] | None) -> bool:
    """Return True if earlier_ports covers all of later_ports."""
    if earlier_ports is None:
        return True  # earlier rule has no port restriction → covers all ports
    if later_ports is None:
        return False  # later rule covers all ports, earlier only covers some
    return later_ports.issubset(earlier_ports)


def _gather_acl_entries(facts: dict[str, Any], acl_id: str) -> list[dict[str, Any]]:
    """Collect all parsed ACL entries for a given ACL ID (numbered + named)."""
    entries = []
    for entry in facts.get("acls", []):
        if entry["id"] == acl_id and entry.get("enabled", True) is not False:
            parsed = _parse_single_acl_entry(entry["syntax"])
            parsed["order"] = entry["order"]
            entries.append(parsed)
    for entry in facts.get("named_acl_entries", []):
        if entry["id"] == acl_id and entry.get("enabled", True) is not False:
            parsed = _parse_single_acl_entry(entry["syntax"])
            parsed["order"] = entry["order"]
            entries.append(parsed)
    entries.sort(key=lambda e: e["order"])
    return entries


def _binding_fields(binding: dict[str, Any] | list[str] | tuple[str, str]) -> tuple[str, str]:
    if isinstance(binding, dict):
        return str(binding.get("acl_id", "")), str(binding.get("direction", ""))
    return str(binding[0]), str(binding[1])


# ---------------------------------------------------------------------------
# M22 – No broadly permissive ACL rules
# ---------------------------------------------------------------------------

_M22_LIMITATIONS = [
    "A configured broad permit rule is a configuration finding; it does not prove "
    "external reachability.",
    "NAT, routing, upstream filtering, and zone policies are not evaluated here.",
    "Only explicitly bound ACLs with resolved addresses are analyzed.",
    "Named ACLs using address objects, FQDN groups, or application-based matching are unsupported.",
]


def _check_m22_broad_permit(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    bindings = facts.get("acl_bindings", [])  # list of [acl_id, direction]
    if not bindings:
        return _result(
            ctx,
            check_id="DEV-M22-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"acl_bindings": []},
            expected={"no_broad_permit_rules": True},
            explanation="No interface ACL bindings found; cannot assess ACL permissiveness.",
            limitations=_M22_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    broad_rules: list[dict[str, Any]] = []
    unresolved_acls: list[str] = []

    for binding in bindings:
        acl_id, direction = _binding_fields(binding)
        entries = _gather_acl_entries(facts, acl_id)
        if not entries:
            unresolved_acls.append(acl_id)
            continue
        for entry in entries:
            if not entry.get("parsed"):
                unresolved_acls.append(acl_id)
                continue
            if entry.get("unresolved"):
                unresolved_acls.append(acl_id)
                continue
            if entry.get("unsupported_construct"):
                unresolved_acls.append(acl_id)
                continue
            if entry["action"] != "permit":
                continue
            src = entry.get("src")
            dst = entry.get("dst")
            if isinstance(src, ipaddress.IPv4Network) and _is_broad_source(src):
                broad_rules.append(
                    {
                        "acl_id": acl_id,
                        "interface": binding.get("interface")
                        if isinstance(binding, dict)
                        else None,
                        "direction": direction,
                        "order": entry["order"],
                        "raw": entry["raw"],
                        "src_network": str(src),
                    }
                )
            elif (
                isinstance(dst, ipaddress.IPv4Network)
                and dst == _ANY_NETWORK
                and isinstance(src, ipaddress.IPv4Network)
                and src == _ANY_NETWORK
            ):
                broad_rules.append(
                    {
                        "acl_id": acl_id,
                        "direction": direction,
                        "order": entry["order"],
                        "raw": entry["raw"],
                        "dst_network": str(dst),
                    }
                )

    if unresolved_acls and not broad_rules:
        return _result(
            ctx,
            check_id="DEV-M22-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"unresolved_acls": unresolved_acls},
            expected={"no_broad_permit_rules": True},
            explanation=(
                "One or more bound ACLs contain unresolved object references; cannot assess."
            ),
            limitations=_M22_LIMITATIONS,
            error_code="UNRESOLVED_OBJECTS",
        )

    if broad_rules:
        return _result(
            ctx,
            check_id="DEV-M22-001",
            feature_id="E06",
            status=AssessmentStatus.FAIL,
            actual={"broad_permit_rules": broad_rules},
            expected={"no_broad_permit_rules": True},
            explanation=(
                f"{len(broad_rules)} broadly permissive permit rule(s) found in bound ACLs."
            ),
            limitations=_M22_LIMITATIONS,
            remediation=(
                "Replace broad permit rules with source-specific permit rules. "
                "Add explicit deny rules for untrusted source ranges."
            ),
        )

    if unresolved_acls or facts.get("unsupported_acl_semantics"):
        return _result(
            ctx,
            check_id="DEV-M22-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={
                "unresolved_acls": unresolved_acls,
                "unsupported_semantics": facts.get("unsupported_acl_semantics", []),
            },
            expected={"no_broad_permit_rules": True},
            explanation=(
                "Unresolved ACL entries or unsupported semantics prevent a complete conclusion."
            ),
            limitations=_M22_LIMITATIONS,
            error_code="ACL_SCOPE_INCOMPLETE",
        )

    return _result(
        ctx,
        check_id="DEV-M22-001",
        feature_id="E06",
        status=AssessmentStatus.PASS,
        actual={
            "broad_permit_rules": [],
            "analyzed_acls": [_binding_fields(b)[0] for b in bindings],
        },
        expected={"no_broad_permit_rules": True},
        explanation="No broadly permissive permit rules found in bound ACLs.",
        limitations=_M22_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M23 – Sensitive port allowances from broad sources
# ---------------------------------------------------------------------------

_M23_LIMITATIONS = [
    "Only TCP/UDP ACL entries with resolved addresses and explicit port specifiers are analyzed.",
    "IP protocol rules (no port restriction) are checked separately by M22.",
    "This check reports configured exposure, not verified external reachability.",
]


def _check_m23_sensitive_ports(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    bindings = facts.get("acl_bindings", [])
    sensitive_ports = set(ctx.policy.sensitive_ports)
    if not bindings:
        return _result(
            ctx,
            check_id="DEV-M23-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"acl_bindings": []},
            expected={"sensitive_ports_restricted": True, "sensitive_ports": list(sensitive_ports)},
            explanation="No interface ACL bindings found; cannot assess sensitive port exposure.",
            limitations=_M23_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    exposures: list[dict[str, Any]] = []
    for binding in bindings:
        acl_id, direction = _binding_fields(binding)
        entries = _gather_acl_entries(facts, acl_id)
        if not entries:
            continue
        for entry in entries:
            if (
                not entry.get("parsed")
                or entry.get("unresolved")
                or entry.get("unsupported_construct")
            ):
                continue
            if entry["action"] != "permit":
                continue
            if entry["protocol"] not in {"tcp", "udp"}:
                continue
            src = entry.get("src")
            if not isinstance(src, ipaddress.IPv4Network):
                continue
            if not _is_broad_source(src):
                continue
            dst_ports = entry.get("dst_port")
            exposed = sensitive_ports if dst_ports is None else dst_ports & sensitive_ports
            if exposed:
                exposures.append(
                    {
                        "acl_id": acl_id,
                        "interface": binding.get("interface")
                        if isinstance(binding, dict)
                        else None,
                        "direction": direction,
                        "order": entry["order"],
                        "raw": entry["raw"],
                        "src_network": str(src),
                        "exposed_ports": sorted(exposed),
                    }
                )

    if exposures:
        return _result(
            ctx,
            check_id="DEV-M23-001",
            feature_id="E06",
            status=AssessmentStatus.FAIL,
            actual={"sensitive_port_exposures": exposures},
            expected={
                "sensitive_ports_restricted": True,
                "sensitive_ports": sorted(sensitive_ports),
            },
            explanation=f"{len(exposures)} rule(s) allow sensitive ports from broad source ranges.",
            limitations=_M23_LIMITATIONS,
            remediation=(
                "Restrict permit rules for sensitive ports to specific, trusted source networks. "
                "Do not permit administrative ports (SSH 22, RDP 3389) from broad/any source."
            ),
        )

    if (
        facts.get("unsupported_acl_semantics")
        or any(not _gather_acl_entries(facts, _binding_fields(binding)[0]) for binding in bindings)
        or any(
            entry.get("unresolved") or entry.get("unsupported_construct") or not entry.get("parsed")
            for binding in bindings
            for entry in _gather_acl_entries(facts, _binding_fields(binding)[0])
        )
    ):
        return _result(
            ctx,
            check_id="DEV-M23-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"unsupported_semantics": facts.get("unsupported_acl_semantics", [])},
            expected={
                "sensitive_ports_restricted": True,
                "sensitive_ports": sorted(sensitive_ports),
            },
            explanation=(
                "Unresolved or unsupported ACL entries prevent a complete port-range conclusion."
            ),
            limitations=_M23_LIMITATIONS,
            error_code="ACL_SCOPE_INCOMPLETE",
        )

    return _result(
        ctx,
        check_id="DEV-M23-001",
        feature_id="E06",
        status=AssessmentStatus.PASS,
        actual={"sensitive_port_exposures": []},
        expected={"sensitive_ports_restricted": True, "sensitive_ports": sorted(sensitive_ports)},
        explanation="No sensitive port allowances from broad source ranges found.",
        limitations=_M23_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M24 – ACL rule shadowing
# ---------------------------------------------------------------------------

_M24_LIMITATIONS = [
    "Only supported subset: numbered/named IPv4 ACL with resolved addresses and TCP/UDP/IP rules.",
    "Non-contiguous wildcard masks, FQDN objects, application/user rules are NOT supported.",
    "Partial overlap (earlier rule matches some but not all of later rule's traffic) is not "
    "reported as full shadowing.",
    "Disabled rules are not applicable — IOS does not support per-line disable.",
    "NAT, zone policies, and inherited policy are not evaluated.",
    "Complexity limit applies; exceeding it returns MANUAL_REVIEW, not a verdict.",
]


def _is_fully_shadowed(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    """Return True if 'earlier' TERMINAL rule fully shadows 'later' rule.

    Full shadowing means: for every possible packet that matches 'later',
    'earlier' also matches it. This requires:
    - earlier.src ⊇ later.src (earlier src network contains later src network)
    - earlier.dst ⊇ later.dst
    - earlier protocol covers later protocol
    - earlier src_port covers later src_port
    - earlier dst_port covers later dst_port
    """
    if earlier.get("unresolved") or later.get("unresolved"):
        return False
    if not earlier.get("parsed") or not later.get("parsed"):
        return False
    if earlier.get("unsupported_construct") or later.get("unsupported_construct"):
        return False

    # Protocol containment
    ep, lp = earlier.get("protocol", "ip"), later.get("protocol", "ip")
    if ep != "ip" and ep != lp:
        return False  # different specific protocol

    # Source network containment
    e_src = earlier.get("src")
    l_src = later.get("src")
    if not isinstance(e_src, ipaddress.IPv4Network) or not isinstance(l_src, ipaddress.IPv4Network):
        return False
    if not _network_contains(e_src, l_src):
        return False

    # Destination network containment
    e_dst = earlier.get("dst")
    l_dst = later.get("dst")
    if not isinstance(e_dst, ipaddress.IPv4Network) or not isinstance(l_dst, ipaddress.IPv4Network):
        return False
    if not _network_contains(e_dst, l_dst):
        return False

    # Port containment (only relevant for TCP/UDP)
    if lp in {"tcp", "udp"}:
        if not _port_set_covered(earlier.get("src_port"), later.get("src_port")):
            return False
        if not _port_set_covered(earlier.get("dst_port"), later.get("dst_port")):
            return False

    return True


def _check_m24_shadowing(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    bindings = facts.get("acl_bindings", [])
    max_complexity = ctx.policy.max_acl_complexity

    if not bindings:
        return _result(
            ctx,
            check_id="DEV-M24-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"acl_bindings": []},
            expected={"no_shadowed_rules": True},
            explanation="No interface ACL bindings found; shadowing analysis not applicable.",
            limitations=_M24_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    all_shadowed: list[dict[str, Any]] = []
    partial_overlaps: list[dict[str, Any]] = []
    complexity_exceeded = False
    unsupported_entries: list[dict[str, Any]] = []

    for binding in bindings:
        acl_id, direction = _binding_fields(binding)
        if isinstance(binding, dict) and not binding.get("interface"):
            unsupported_entries.append({"acl_id": acl_id, "reason": "unknown_binding_interface"})
        entries = _gather_acl_entries(facts, acl_id)
        if not entries:
            unsupported_entries.append({"acl_id": acl_id, "reason": "no_resolved_rules"})
            continue
        if len(entries) > max_complexity:
            complexity_exceeded = True
            continue

        # Check each rule against all earlier terminal rules
        for i, later_entry in enumerate(entries):
            if (
                not later_entry.get("parsed")
                or later_entry.get("unresolved")
                or later_entry.get("unsupported_construct")
            ):
                unsupported_entries.append({"acl_id": acl_id, "order": later_entry.get("order")})
                continue
            shadowed_by: str | None = None
            for earlier_entry in entries[:i]:
                if (
                    not earlier_entry.get("parsed")
                    or earlier_entry.get("unresolved")
                    or earlier_entry.get("unsupported_construct")
                ):
                    unsupported_entries.append(
                        {"acl_id": acl_id, "order": earlier_entry.get("order")}
                    )
                    continue
                if _is_fully_shadowed(earlier_entry, later_entry):
                    shadowed_by = earlier_entry.get("raw", f"order={earlier_entry['order']}")
                    break
                if _rules_overlap(earlier_entry, later_entry):
                    partial_overlaps.append(
                        {
                            "acl_id": acl_id,
                            "interface": binding.get("interface")
                            if isinstance(binding, dict)
                            else None,
                            "direction": direction,
                            "earlier_order": earlier_entry["order"],
                            "later_order": later_entry["order"],
                            "action_difference": earlier_entry.get("action")
                            != later_entry.get("action"),
                        }
                    )
            if shadowed_by is not None:
                all_shadowed.append(
                    {
                        "acl_id": acl_id,
                        "interface": binding.get("interface")
                        if isinstance(binding, dict)
                        else None,
                        "direction": direction,
                        "rule_order": later_entry["order"],
                        "shadowed_rule": later_entry.get("raw"),
                        "shadowed_by": shadowed_by,
                        "action_difference": (
                            earlier_entry["action"] != later_entry["action"]
                            if earlier_entry.get("action") and later_entry.get("action")
                            else None
                        ),
                    }
                )

    if complexity_exceeded:
        return _result(
            ctx,
            check_id="DEV-M24-001",
            feature_id="E06",
            status=AssessmentStatus.MANUAL_REVIEW,
            actual={"complexity_limit_exceeded": True, "max_acl_complexity": max_complexity},
            expected={"no_shadowed_rules": True},
            explanation=(
                f"One or more ACLs exceed the complexity limit of {max_complexity} rules; "
                "manual review required."
            ),
            limitations=_M24_LIMITATIONS,
            error_code="COMPLEXITY_LIMIT_EXCEEDED",
        )

    if all_shadowed:
        return _result(
            ctx,
            check_id="DEV-M24-001",
            feature_id="E06",
            status=AssessmentStatus.FAIL,
            actual={"shadowed_rules": all_shadowed},
            expected={"no_shadowed_rules": True},
            explanation=f"{len(all_shadowed)} fully shadowed ACL rule(s) found.",
            limitations=_M24_LIMITATIONS,
            remediation=(
                "Remove or reorder fully shadowed ACL rules. "
                "Verify that rule ordering reflects intended security policy."
            ),
        )

    if unsupported_entries or facts.get("unsupported_acl_semantics"):
        return _result(
            ctx,
            check_id="DEV-M24-001",
            feature_id="E06",
            status=AssessmentStatus.MANUAL_REVIEW,
            actual={
                "unsupported_entries": unsupported_entries,
                "unsupported_semantics": facts.get("unsupported_acl_semantics", []),
                "partial_overlaps": partial_overlaps,
                "shadowed_rules": [],
            },
            expected={"no_shadowed_rules": True},
            explanation=(
                "Partial ACL overlap or entries outside the supported first-match IPv4 subset "
                "require manual review."
            ),
            limitations=_M24_LIMITATIONS,
            error_code="UNSUPPORTED_ACL_SEMANTICS",
        )

    return _result(
        ctx,
        check_id="DEV-M24-001",
        feature_id="E06",
        status=AssessmentStatus.PASS,
        actual={"shadowed_rules": [], "partial_overlaps": partial_overlaps},
        expected={"no_shadowed_rules": True},
        explanation=(
            "No fully shadowed ACL rules detected within the supported ACL subset; "
            f"{len(partial_overlaps)} partial overlap(s) were retained separately."
        ),
        limitations=_M24_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M25 – Default deny policy
# ---------------------------------------------------------------------------

_M25_LIMITATIONS = [
    "Cisco IOS/IOS-XE implicit deny is accepted only when the parser verifies the "
    "platform context.",
    "This proves ACL default action, not effective exposure or upstream filtering.",
]


def _check_m25_default_deny(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    bindings = facts.get("acl_bindings", [])
    if not bindings:
        return _result(
            ctx,
            check_id="DEV-M25-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"acl_bindings": []},
            expected={"explicit_default_deny": True},
            explanation="No interface ACL bindings; cannot assess default deny policy.",
            limitations=_M25_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    default_action = facts.get("acl_default_action")
    if default_action not in {"deny", "permit"}:
        return _result(
            ctx,
            check_id="DEV-M25-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"default_action": None},
            expected={"default_action": "deny"},
            explanation="Implicit ACL action is not verified for this device/context.",
            limitations=_M25_LIMITATIONS,
            error_code="DEFAULT_ACTION_UNKNOWN",
        )

    missing_acls: list[str] = []

    for binding in bindings:
        acl_id, _ = _binding_fields(binding)
        entries = _gather_acl_entries(facts, acl_id)
        if not entries:
            missing_acls.append(acl_id)

    if missing_acls:
        return _result(
            ctx,
            check_id="DEV-M25-001",
            feature_id="E06",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"acl_ids_without_resolved_rules": missing_acls},
            expected={"default_action": "deny"},
            explanation=(
                "A bound ACL has no resolved rule evidence; default action cannot be assessed."
            ),
            limitations=_M25_LIMITATIONS,
            error_code="ACL_RULES_UNRESOLVED",
        )

    if default_action != "deny":
        return _result(
            ctx,
            check_id="DEV-M25-001",
            feature_id="E06",
            status=AssessmentStatus.FAIL,
            actual={"default_action": default_action},
            expected={"default_action": "deny"},
            explanation="Verified ACL default action is not deny.",
            limitations=_M25_LIMITATIONS,
            remediation="Set the verified default action to deny and review every bound ACL.",
        )

    return _result(
        ctx,
        check_id="DEV-M25-001",
        feature_id="E06",
        status=AssessmentStatus.PASS,
        actual={"default_action": "deny", "basis": "verified_ios_implicit_deny"},
        expected={"default_action": "deny"},
        explanation="Cisco IOS/IOS-XE implicit deny is verified for each bound ACL context.",
        limitations=_M25_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M26 – Designated unused ports shut down
# ---------------------------------------------------------------------------


def _has_switching_capability(facts: dict[str, Any]) -> bool:
    """Require collected capability evidence; a platform label alone is insufficient."""
    return facts.get("capabilities", {}).get("switching") is True


_M26_LIMITATIONS = [
    "Unused port inventory must be explicitly supplied; operational 'down' state is not "
    "sufficient evidence.",
    "This check evaluates 'shutdown' configuration, not physical disconnect or cable removal.",
]


def _check_m26_unused_ports(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    if not _has_switching_capability(facts):
        return _result(
            ctx,
            check_id="DEV-M26-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"platform": ctx.platform},
            expected={"designated_unused_ports_configured_shutdown": True},
            explanation=("No collected switching capability evidence; M26 is not applicable."),
            applicability_note="cisco_router is not an access-switch interface inventory.",
            limitations=_M26_LIMITATIONS,
        )

    # Use policy-supplied inventory (from manifest or policy override)
    inventory = ctx.policy.designated_unused_ports
    if inventory is None:
        interfaces = facts.get("interfaces", [])
        inventory = [i["name"] for i in interfaces if i.get("designated_unused") is True]
        if not inventory:
            return _result(
                ctx,
                check_id="DEV-M26-001",
                feature_id="E07",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"designated_unused_ports": None},
                expected={"designated_unused_ports_configured_shutdown": True},
                explanation=(
                    "No designated-unused port inventory supplied in policy or manifest. "
                    "Cannot assess without explicit inventory."
                ),
                limitations=_M26_LIMITATIONS,
                error_code="MISSING_INVENTORY",
            )
    interfaces = facts.get("interfaces", [])
    iface_map = {i["name"]: i for i in interfaces}
    not_shut = [
        name
        for name in inventory
        if name in iface_map and not iface_map[name].get("configured_shutdown")
    ]
    shut = [
        name
        for name in inventory
        if name in iface_map and iface_map[name].get("configured_shutdown")
    ]

    missing_interfaces = [
        name for name in inventory if name not in {i.get("name") for i in interfaces}
    ]
    if missing_interfaces:
        return _result(
            ctx,
            check_id="DEV-M26-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"missing_interfaces": missing_interfaces},
            expected={"designated_unused_ports_configured_shutdown": True},
            explanation=(
                "Some designated-unused interfaces are absent from collected configuration."
            ),
            limitations=_M26_LIMITATIONS,
            error_code="INCOMPLETE_INTERFACE_EVIDENCE",
        )
    if not inventory:
        return _result(
            ctx,
            check_id="DEV-M26-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"designated_unused_ports": []},
            expected={"designated_unused_ports_configured_shutdown": True},
            explanation=(
                "The designated-unused inventory is empty; applicability is not established."
            ),
            limitations=_M26_LIMITATIONS,
            error_code="EMPTY_INVENTORY",
        )
    if not_shut:
        return _result(
            ctx,
            check_id="DEV-M26-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={"not_shutdown": not_shut, "shutdown": shut},
            expected={"designated_unused_ports_configured_shutdown": True},
            explanation=(
                f"{len(not_shut)} designated-unused port(s) are not administratively shutdown."
            ),
            limitations=_M26_LIMITATIONS,
            remediation="Apply 'shutdown' to all interfaces designated as unused.",
        )

    return _result(
        ctx,
        check_id="DEV-M26-001",
        feature_id="E07",
        status=AssessmentStatus.PASS,
        actual={"shutdown": shut, "not_shutdown": []},
        expected={"designated_unused_ports_configured_shutdown": True},
        explanation="All designated-unused ports are administratively shut down.",
        limitations=_M26_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M27 – Port security on access ports
# ---------------------------------------------------------------------------

_M27_LIMITATIONS = [
    "Port security applicability is limited to access-mode interfaces; trunks/uplinks are "
    "excluded.",
    "Port security presence is evaluated; MAC binding count and violation mode are not "
    "assessed here.",
    "This check is NOT_APPLICABLE for cisco_router (no switchport concept).",
]


def _check_m27_port_security(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    if not _has_switching_capability(facts):
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"platform": ctx.platform},
            expected={"port_security_on_access_ports": True},
            explanation=(
                "Port security (M27) applies only to cisco_switch; router has no "
                "switchport concept."
            ),
            applicability_note="cisco_router does not support switchport port-security.",
            limitations=_M27_LIMITATIONS,
        )

    interfaces = facts.get("interfaces", [])
    roles = ctx.policy.interface_roles
    if roles is None:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"interface_roles": None},
            expected={"port_security_on_applicable_access_ports": True},
            explanation=(
                "No explicit interface-role inventory supplied; access-port applicability "
                "is unknown."
            ),
            limitations=_M27_LIMITATIONS,
            error_code="MISSING_INTERFACE_ROLE_INVENTORY",
        )
    if not roles:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"interface_roles": {}},
            expected={"port_security_on_applicable_access_ports": True},
            explanation=(
                "The interface-role inventory is empty; access-port applicability is unknown."
            ),
            limitations=_M27_LIMITATIONS,
            error_code="EMPTY_INTERFACE_ROLE_INVENTORY",
        )
    interface_map = {i.get("name"): i for i in interfaces}
    access_ports = [
        interface_map[name]
        for name, role in roles.items()
        if role == "access" and name in interface_map
    ]
    missing_roles = [
        name for name, role in roles.items() if role == "access" and name not in interface_map
    ]
    if missing_roles:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"missing_access_interfaces": missing_roles},
            expected={"port_security_on_applicable_access_ports": True},
            explanation=(
                "Some policy-designated access interfaces are absent from collected configuration."
            ),
            limitations=_M27_LIMITATIONS,
            error_code="INCOMPLETE_INTERFACE_EVIDENCE",
        )
    conflicts = [
        name
        for name, role in roles.items()
        if role == "access"
        and name in interface_map
        and interface_map[name].get("switchport_mode") not in {None, "access"}
    ]
    if conflicts:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.MANUAL_REVIEW,
            actual={"policy_access_but_configured_other_mode": conflicts},
            expected={"port_security_on_applicable_access_ports": True},
            explanation="Policy role and observed switchport mode conflict.",
            limitations=_M27_LIMITATIONS,
            error_code="INTERFACE_ROLE_CONFLICT",
        )
    if (
        roles
        and not access_ports
        and all(role in {"trunk", "uplink", "management", "unused"} for role in roles.values())
    ):
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"applicable_access_ports": []},
            expected={"port_security_on_applicable_access_ports": True},
            explanation="The explicit interface-role inventory contains no access ports.",
            applicability_note="All inventoried interfaces have non-access roles.",
            limitations=_M27_LIMITATIONS,
        )
    if not access_ports:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"access_ports_found": 0},
            expected={"port_security_on_access_ports": True},
            explanation=(
                "No access-mode interfaces found; port security applicability cannot be determined."
            ),
            limitations=_M27_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    unknown = [i["name"] for i in access_ports if i.get("port_security_configured") is None]
    if unknown:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"port_security_unknown": unknown},
            expected={"port_security_on_applicable_access_ports": True},
            explanation="Port-security state is missing for one or more applicable access ports.",
            limitations=_M27_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )
    missing = [i["name"] for i in access_ports if not i.get("port_security_configured")]
    secured = [i["name"] for i in access_ports if i.get("port_security_configured")]

    if missing:
        return _result(
            ctx,
            check_id="DEV-M27-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={"missing_port_security": missing, "secured": secured},
            expected={"port_security_on_access_ports": True},
            explanation=f"{len(missing)} access port(s) lack port-security configuration.",
            limitations=_M27_LIMITATIONS,
            remediation=(
                "Configure 'switchport port-security' on access-mode interfaces. "
                "Set appropriate maximum MAC addresses and violation mode."
            ),
        )

    return _result(
        ctx,
        check_id="DEV-M27-001",
        feature_id="E07",
        status=AssessmentStatus.PASS,
        actual={"secured": secured, "missing_port_security": []},
        expected={"port_security_on_access_ports": True},
        explanation="All access-mode interfaces have port-security configured.",
        limitations=_M27_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M28 – DHCP snooping on required VLANs
# ---------------------------------------------------------------------------

_M28_LIMITATIONS = [
    "Global 'ip dhcp snooping' is necessary but does not cover all VLANs; explicit VLAN "
    "scope is required.",
    "This check is NOT_APPLICABLE for cisco_router.",
    "Required VLAN list must be explicitly supplied; cannot be inferred from configuration alone.",
]


def _check_m28_dhcp_snooping(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    if not _has_switching_capability(facts):
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"platform": ctx.platform},
            expected={"dhcp_snooping_on_required_vlans": True},
            explanation="DHCP snooping (M28) applies only to cisco_switch.",
            applicability_note="cisco_router does not support DHCP snooping in the same way.",
            limitations=_M28_LIMITATIONS,
        )

    required_vlans = ctx.policy.required_vlans
    if required_vlans is None:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"required_vlans": None},
            expected={"dhcp_snooping_on_required_vlans": True},
            explanation=(
                "No required VLAN list supplied in policy; cannot assess DHCP snooping coverage."
            ),
            limitations=_M28_LIMITATIONS,
            error_code="MISSING_POLICY_PARAMETER",
        )
    if not required_vlans:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"required_vlans": []},
            expected={"dhcp_snooping_on_required_vlans": True},
            explanation="Policy explicitly identifies no VLANs requiring DHCP snooping.",
            applicability_note="No VLANs are in scope for this predicate.",
            limitations=_M28_LIMITATIONS,
        )
    if not required_vlans:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"required_vlans": []},
            expected={"dhcp_snooping_on_required_vlans": True},
            explanation="Policy explicitly identifies no VLANs in scope for DHCP snooping.",
            applicability_note="Required VLAN inventory is explicitly empty.",
            limitations=_M28_LIMITATIONS,
        )

    dhcp = facts.get("dhcp_snooping", {})
    global_enabled = dhcp.get("enabled", False)
    configured_vlans = set(dhcp.get("vlans", []))

    missing: list[str] = []
    for vlan in required_vlans:
        if str(vlan) not in configured_vlans:
            missing.append(str(vlan))

    if global_enabled is None or dhcp.get("vlans") is None:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"global_enabled": global_enabled, "configured_vlans": dhcp.get("vlans")},
            expected={"dhcp_snooping_global_enabled": True, "required_vlans": required_vlans},
            explanation="DHCP snooping facts are incomplete; required VLAN coverage is unknown.",
            limitations=_M28_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )
    if not global_enabled:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={"global_enabled": False, "configured_vlans": sorted(configured_vlans)},
            expected={"dhcp_snooping_global_enabled": True, "required_vlans": required_vlans},
            explanation="Global DHCP snooping is not enabled ('ip dhcp snooping' not found).",
            limitations=_M28_LIMITATIONS,
            remediation="Configure 'ip dhcp snooping' globally and then per required VLAN.",
        )

    if missing:
        return _result(
            ctx,
            check_id="DEV-M28-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={
                "global_enabled": True,
                "configured_vlans": sorted(configured_vlans),
                "missing_vlans": missing,
            },
            expected={"required_vlans_covered": required_vlans},
            explanation=f"DHCP snooping is not configured for required VLAN(s): {missing}.",
            limitations=_M28_LIMITATIONS,
            remediation=f"Configure 'ip dhcp snooping vlan {','.join(missing)}'.",
        )

    return _result(
        ctx,
        check_id="DEV-M28-001",
        feature_id="E07",
        status=AssessmentStatus.PASS,
        actual={"global_enabled": True, "configured_vlans": sorted(configured_vlans)},
        expected={"required_vlans_covered": required_vlans},
        explanation="DHCP snooping is globally enabled and covers all required VLANs.",
        limitations=_M28_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M29 – Dynamic ARP Inspection on required VLANs
# ---------------------------------------------------------------------------

_M29_LIMITATIONS = [
    "DAI configured per VLAN does not prove all interfaces in that VLAN are inspected "
    "(trust ports).",
    "This check is NOT_APPLICABLE for cisco_router.",
    "Required VLAN list must be explicitly supplied.",
]


def _check_m29_dai(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    if not _has_switching_capability(facts):
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"platform": ctx.platform},
            expected={"dai_on_required_vlans": True},
            explanation="Dynamic ARP Inspection (M29) applies only to cisco_switch.",
            applicability_note="cisco_router does not support DAI.",
            limitations=_M29_LIMITATIONS,
        )

    required_vlans = ctx.policy.required_vlans
    if required_vlans is None:
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"required_vlans": None},
            expected={"dai_on_required_vlans": True},
            explanation="No required VLAN list supplied; cannot assess DAI coverage.",
            limitations=_M29_LIMITATIONS,
            error_code="MISSING_POLICY_PARAMETER",
        )
    if not required_vlans:
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"required_vlans": []},
            expected={"dai_on_required_vlans": True},
            explanation="Policy explicitly identifies no VLANs requiring DAI.",
            applicability_note="No VLANs are in scope for this predicate.",
            limitations=_M29_LIMITATIONS,
        )
    if not required_vlans:
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"required_vlans": []},
            expected={"dai_on_required_vlans": True},
            explanation="Policy explicitly identifies no VLANs in scope for DAI.",
            applicability_note="Required VLAN inventory is explicitly empty.",
            limitations=_M29_LIMITATIONS,
        )

    dai = facts.get("dynamic_arp_inspection", {})
    if dai.get("vlans") is None:
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"configured_vlans": None},
            expected={"required_vlans_covered": required_vlans},
            explanation="DAI VLAN facts are absent; coverage cannot be assessed.",
            limitations=_M29_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )
    configured_vlans = set(dai.get("vlans", []))
    missing = [str(v) for v in required_vlans if str(v) not in configured_vlans]

    if missing:
        return _result(
            ctx,
            check_id="DEV-M29-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={"configured_vlans": sorted(configured_vlans), "missing_vlans": missing},
            expected={"required_vlans_covered": required_vlans},
            explanation=f"DAI is not configured for required VLAN(s): {missing}.",
            limitations=_M29_LIMITATIONS,
            remediation=f"Configure 'ip arp inspection vlan {','.join(missing)}'.",
        )

    return _result(
        ctx,
        check_id="DEV-M29-001",
        feature_id="E07",
        status=AssessmentStatus.PASS,
        actual={"configured_vlans": sorted(configured_vlans)},
        expected={"required_vlans_covered": required_vlans},
        explanation="DAI is configured for all required VLANs.",
        limitations=_M29_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M30 – No VLAN 1 management use
# ---------------------------------------------------------------------------

_M30_LIMITATIONS = [
    "VLAN 1 SVI existence alone does not prove management traffic; management-use evidence "
    "is required.",
    "Incomplete management-interface inventory results in NOT_ASSESSED.",
    "This check is NOT_APPLICABLE for cisco_router (no VLAN management concept).",
]


def _check_m30_vlan1_management(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    if not _has_switching_capability(facts):
        return _result(
            ctx,
            check_id="DEV-M30-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_APPLICABLE,
            actual={"platform": ctx.platform},
            expected={"vlan1_not_used_for_management": True},
            explanation="VLAN 1 management check (M30) applies only to cisco_switch.",
            applicability_note=(
                "cisco_router does not have VLAN management interfaces in the same context."
            ),
            limitations=_M30_LIMITATIONS,
        )

    inventory = ctx.policy.management_interface_inventory
    if inventory is None:
        return _result(
            ctx,
            check_id="DEV-M30-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"management_interface_inventory": None},
            expected={"vlan1_not_used_for_management": True},
            explanation=(
                "No management interface inventory supplied. "
                "Cannot determine management use of VLAN 1 without explicit inventory."
            ),
            limitations=_M30_LIMITATIONS,
            error_code="MISSING_INVENTORY",
        )

    # Check if any management interfaces are on VLAN 1
    vlan1_mgmt = [
        iface for iface in inventory if "vlan1" in iface.lower() or iface.lower() == "vlan 1"
    ]

    if vlan1_mgmt:
        return _result(
            ctx,
            check_id="DEV-M30-001",
            feature_id="E07",
            status=AssessmentStatus.FAIL,
            actual={"vlan1_management_interfaces": vlan1_mgmt},
            expected={"vlan1_not_used_for_management": True},
            explanation=f"Management interface(s) {vlan1_mgmt} are on VLAN 1.",
            limitations=_M30_LIMITATIONS,
            remediation=(
                "Move management traffic to a dedicated non-VLAN-1 management VLAN. "
                "Configure the management SVI on a separate VLAN (e.g., VLAN 99 or 999)."
            ),
        )

    if not ctx.policy.management_interface_inventory_complete:
        return _result(
            ctx,
            check_id="DEV-M30-001",
            feature_id="E07",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"vlan1_management_interfaces": [], "management_inventory_complete": False},
            expected={"vlan1_not_used_for_management": True},
            explanation=(
                "The management-interface inventory is incomplete; absence of VLAN 1 use "
                "is unproven."
            ),
            limitations=_M30_LIMITATIONS,
            error_code="INCOMPLETE_MANAGEMENT_INVENTORY",
        )

    return _result(
        ctx,
        check_id="DEV-M30-001",
        feature_id="E07",
        status=AssessmentStatus.PASS,
        actual={"vlan1_management_interfaces": [], "management_inventory": inventory},
        expected={"vlan1_not_used_for_management": True},
        explanation="No management interfaces are configured on VLAN 1.",
        limitations=_M30_LIMITATIONS,
    )


# ---------------------------------------------------------------------------
# M31 – Remote syslog configuration
# ---------------------------------------------------------------------------

_M31_LIMITATIONS = [
    "Configured syslog destination does not prove log delivery; network path, transport, "
    "and server availability are not evaluated.",
    "Log severity, format, and filtering are not assessed here.",
]


def _check_m31_syslog(facts: dict[str, Any], ctx: _CheckContext) -> PredicateResult:
    logging_facts = facts.get("logging", {})
    destinations = logging_facts.get("destinations")

    if destinations is None:
        return _result(
            ctx,
            check_id="DEV-M31-001",
            feature_id="E08",
            status=AssessmentStatus.NOT_ASSESSED,
            actual={"logging_destinations": None},
            expected={"remote_syslog_configured": True},
            explanation="Logging facts are absent; cannot assess syslog configuration.",
            limitations=_M31_LIMITATIONS,
            error_code="INSUFFICIENT_EVIDENCE",
        )

    if destinations:
        return _result(
            ctx,
            check_id="DEV-M31-001",
            feature_id="E08",
            status=AssessmentStatus.PASS,
            actual={"logging_destinations": destinations},
            expected={"remote_syslog_configured": True},
            explanation=f"Remote syslog configured to {len(destinations)} destination(s).",
            limitations=_M31_LIMITATIONS,
        )

    return _result(
        ctx,
        check_id="DEV-M31-001",
        feature_id="E08",
        status=AssessmentStatus.FAIL,
        actual={"logging_destinations": []},
        expected={"remote_syslog_configured": True},
        explanation="No remote syslog destinations configured ('logging host' not found).",
        limitations=_M31_LIMITATIONS,
        remediation=(
            "Configure 'logging host <syslog-server-ip>' to send logs to a remote "
            "SIEM/syslog server."
        ),
    )


# ---------------------------------------------------------------------------
# M32 – NTP configured and synchronized
# ---------------------------------------------------------------------------

_M32_LIMITATIONS = [
    "Configured NTP server does not prove synchronization; operational evidence is required.",
    "Synchronization evidence ('Clock is synchronized') comes from show operational "
    "output, not running config.",
    "Single NTP server is a single point of failure; multiple servers are recommended.",
]


def _check_m32_ntp(facts: dict[str, Any], ctx: _CheckContext) -> list[PredicateResult]:
    results: list[PredicateResult] = []
    ntp = facts.get("ntp", {})

    # DEV-M32-001: NTP server configured
    configured = ntp.get("configured_servers")
    if configured is None:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-001",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"configured_servers": None},
                expected={"ntp_configured": True},
                explanation="NTP facts absent; cannot assess NTP server configuration.",
                limitations=_M32_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )
    elif configured:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-001",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"configured_servers": configured},
                expected={"ntp_configured": True},
                explanation=f"NTP configured with {len(configured)} server(s).",
                limitations=_M32_LIMITATIONS,
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-001",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={"configured_servers": []},
                expected={"ntp_configured": True},
                explanation="No NTP servers configured ('ntp server' not found).",
                limitations=_M32_LIMITATIONS,
                remediation="Configure at least two NTP servers using 'ntp server <ip>'.",
            )
        )

    # DEV-M32-002: NTP synchronized
    synchronized = ntp.get("synchronized")
    if synchronized is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-002",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"synchronized": True},
                expected={"ntp_synchronized": True},
                explanation="NTP clock is synchronized (operational evidence confirmed).",
                limitations=_M32_LIMITATIONS,
            )
        )
    elif synchronized is False:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-002",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={"synchronized": False},
                expected={"ntp_synchronized": True},
                explanation=(
                    "NTP clock is not synchronized (operational evidence shows "
                    "unsynchronized state)."
                ),
                limitations=_M32_LIMITATIONS,
                remediation=(
                    "Verify NTP server reachability and configuration. Check 'show ntp status'."
                ),
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M32-002",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"synchronized": None},
                expected={"ntp_synchronized": True},
                explanation=(
                    "NTP synchronization status unknown; operational output ('show ntp status') "
                    "was not collected or did not contain synchronization evidence."
                ),
                limitations=_M32_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    return results


# ---------------------------------------------------------------------------
# M33 – SNMP security
# ---------------------------------------------------------------------------

_M33_LIMITATIONS = [
    "SNMPv3 user presence does not prove authPriv mode or absence of v1/v2c.",
    "Community strings are never exposed in results or logs.",
    "SNMP access control lists and view configurations are not evaluated here.",
    "Linux and Windows SNMP/NTP gaps may remain NOT_ASSESSED unless specific collection "
    "evidence is present.",
]


def _check_m33_snmp(facts: dict[str, Any], ctx: _CheckContext) -> list[PredicateResult]:
    results: list[PredicateResult] = []
    snmp = facts.get("snmp", {})
    configuration_complete = snmp.get("configuration_complete")

    # DEV-M33-001: SNMPv3 present
    v3_present = snmp.get("v3_users_present")
    if v3_present is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-001",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"v3_users_present": True},
                expected={"snmpv3_configured": True},
                explanation="SNMPv3 user(s) are configured.",
                limitations=_M33_LIMITATIONS,
            )
        )
    elif v3_present is False:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-001",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={"v3_users_present": False},
                expected={"snmpv3_configured": True},
                explanation="No SNMPv3 users configured.",
                limitations=_M33_LIMITATIONS,
                remediation=(
                    "Configure SNMPv3 with 'snmp-server user <user> <group> v3 auth sha "
                    "<hash> priv aes 128 <hash>'. "
                    "Remove v1/v2c communities."
                ),
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-001",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"v3_users_present": None},
                expected={"snmpv3_configured": True},
                explanation="SNMP facts absent; cannot assess SNMPv3 configuration.",
                limitations=_M33_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    # DEV-M33-002: No insecure v1/v2c
    insecure = snmp.get("insecure_v1_v2c_present")
    if insecure is False and configuration_complete is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-002",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"insecure_v1_v2c_present": False},
                expected={"no_insecure_snmp_communities": True},
                explanation="No SNMPv1/v2c community strings are configured.",
                limitations=_M33_LIMITATIONS,
            )
        )
    elif insecure is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-002",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={
                    "insecure_v1_v2c_present": True,
                    "community_count": len(snmp.get("communities", [])),
                },
                expected={"no_insecure_snmp_communities": True},
                explanation=(
                    "SNMPv1/v2c community string(s) are configured. Values are not reported."
                ),
                limitations=_M33_LIMITATIONS,
                remediation=(
                    "Remove all 'snmp-server community' entries. "
                    "Use SNMPv3 with authentication and privacy (authPriv)."
                ),
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-002",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={
                    "insecure_v1_v2c_present": insecure,
                    "configuration_complete": configuration_complete,
                },
                expected={"no_insecure_snmp_communities": True},
                explanation=(
                    "SNMP absence cannot be established without complete relevant "
                    "configuration evidence."
                ),
                limitations=_M33_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    # DEV-M33-003: No default community strings (public/private)
    default_community = snmp.get("default_community_present")
    if default_community is False:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-003",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"default_community_present": False},
                expected={"no_default_community_names": True},
                explanation=(
                    "No default community names (public/private) detected. "
                    "Community values are not reported."
                ),
                limitations=_M33_LIMITATIONS,
            )
        )
    elif default_community is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-003",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={"default_community_present": True},
                expected={"no_default_community_names": True},
                explanation=(
                    "A default community name (public or private) is in use. "
                    "The community string value is not reported."
                ),
                limitations=_M33_LIMITATIONS,
                remediation=(
                    "Remove SNMP community strings named 'public' or 'private'. "
                    "Replace with SNMPv3 or a non-default community name if v2c is "
                    "temporarily required."
                ),
            )
        )
    else:
        # None: no communities configured at all
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-003",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"default_community_present": None},
                expected={"no_default_community_names": True},
                explanation=(
                    "No SNMP community configuration present; "
                    "default community check is not applicable without community evidence."
                ),
                limitations=_M33_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    # DEV-M33-004: SNMPv3 authPriv where observable
    authpriv = snmp.get("v3_authpriv_users_present")
    if authpriv is True:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-004",
                feature_id="E08",
                status=AssessmentStatus.PASS,
                actual={"v3_authpriv_users_present": True},
                expected={"snmpv3_security_level": "authPriv"},
                explanation=(
                    "Configuration includes an SNMPv3 user with authentication and privacy "
                    "directives."
                ),
                limitations=_M33_LIMITATIONS,
            )
        )
    elif authpriv is False:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-004",
                feature_id="E08",
                status=AssessmentStatus.FAIL,
                actual={"v3_authpriv_users_present": False},
                expected={"snmpv3_security_level": "authPriv"},
                explanation="SNMPv3 users are present, but authPriv directives were not found.",
                limitations=_M33_LIMITATIONS,
                remediation=(
                    "Configure SNMPv3 users with both authentication and privacy, then "
                    "verify the effective configuration."
                ),
            )
        )
    else:
        results.append(
            _result(
                ctx,
                check_id="DEV-M33-004",
                feature_id="E08",
                status=AssessmentStatus.NOT_ASSESSED,
                actual={"v3_authpriv_users_present": None},
                expected={"snmpv3_security_level": "authPriv"},
                explanation="No observable SNMPv3 authPriv evidence is available.",
                limitations=_M33_LIMITATIONS,
                error_code="INSUFFICIENT_EVIDENCE",
            )
        )

    return results


# ---------------------------------------------------------------------------
# Named ACL regex helper for structured parsing in ACL body
# ---------------------------------------------------------------------------


def _parse_named_acl_entries(text: str) -> list[dict[str, Any]]:
    """Extract structured entries from 'ip access-list extended/standard' blocks."""
    entries: list[dict[str, Any]] = []
    for acl_match in re.finditer(
        r"^ip access-list (?:extended|standard) (\S+)\n((?:[ \t].*\n?)*)", text, re.M
    ):
        acl_id = acl_match.group(1)
        acl_body = acl_match.group(2)
        for order, line_match in enumerate(
            re.finditer(r"^\s+(?:\d+\s+)?(permit|deny)\s+(.+)$", acl_body, re.M), 1
        ):
            entries.append(
                {
                    "id": acl_id,
                    "order": order,
                    "syntax": f"{line_match.group(1)} {line_match.group(2).strip()}",
                    "named": True,
                }
            )
    return entries
