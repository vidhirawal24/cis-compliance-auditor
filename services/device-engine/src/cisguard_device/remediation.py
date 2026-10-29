"""Phase-7 typed remediation preparation; no device writes or recovery execution."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .errors import DeviceEngineError
from .models import AssessmentStatus, FactsEnvelope
from .network_predicates import NetworkControlPolicy, PredicateResult

_SAFE_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9/.-]{0,63}$")
_SAFE_TEMPLATE = re.compile(r"^[a-z0-9_-]{3,80}$")


class RemediationTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_id: str
    version: str
    check_id: str
    feature_id: str
    platforms: list[str]
    firmware_scope: str
    validation_level: str
    required_facts: list[str]
    dependencies: list[str]
    conflicts: list[str]
    risks: list[str]
    backup_requirement: str
    reversibility: str
    recovery_limitations: list[str]
    post_change_checks: list[str]


class RemediationCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    template_id: str
    template_version: str
    org_id: str
    asset_id: str
    platform: str
    target_identity: dict[str, Any]
    parameters: dict[str, Any]
    source_evidence_hashes: list[str]
    expected_preconditions: dict[str, Any]
    commands: list[str]
    status: str = "PREVIEW_ONLY_NOT_APPROVED"


class DryRunPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate: RemediationCandidate
    current: dict[str, Any]
    expected_diff: dict[str, Any]
    dependencies: list[str]
    conflicts: list[str]
    risks: list[str]
    missing_preconditions: list[str]
    service_checks: list[str]
    backup_requirement: str
    recovery_requirement: str
    outcome: str = "PREDICTED_NOT_EXECUTED"


class RecoverySpecification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    inverse_commands: list[str] | None
    prerequisites: list[str]
    drift_concerns: list[str]
    verification: list[str]
    limitations: list[str]
    execution_status: str = "BLOCKED"


class BackupMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    org_id: str
    asset_id: str
    platform: str
    model: str
    firmware: str
    capture_timestamp: datetime | None
    provenance: str
    artifact_kind: str
    completeness: str
    recovery_capability: str


class BackupCipher(Protocol):
    """Mandar/OpenBao integration boundary; implementation must authenticate ciphertext."""

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes: ...


_TEMPLATES = {
    "ios_disable_http": RemediationTemplate(
        template_id="ios_disable_http",
        version="1.0.0",
        check_id="DEV-M21-001",
        feature_id="M20",
        platforms=["cisco_router", "cisco_switch"],
        firmware_scope="IOS 15 / IOS-XE 16-17 syntactic preview only",
        validation_level="fixture_tested_no_live_lab",
        required_facts=["management.http_enabled"],
        dependencies=[],
        conflicts=[],
        risks=["May remove HTTP-based management path."],
        backup_requirement="verified_restorable_backup_or_manual_recovery_plan",
        reversibility="conditional_inverse",
        recovery_limitations=["No tested device rollback or out-of-band access proof."],
        post_change_checks=["show ip http server status", "verify approved management path"],
    ),
    "ios_set_vty_timeout": RemediationTemplate(
        template_id="ios_set_vty_timeout",
        version="1.0.0",
        check_id="DEV-M21-004",
        feature_id="M21",
        platforms=["cisco_router", "cisco_switch"],
        firmware_scope="IOS 15 / IOS-XE 16-17 syntactic preview only",
        validation_level="fixture_tested_no_live_lab",
        required_facts=["management.vty_lines"],
        dependencies=["verified_vty_inventory"],
        conflicts=[],
        risks=["May disconnect idle administrators."],
        backup_requirement="verified_restorable_backup_or_manual_recovery_plan",
        reversibility="conditional_inverse",
        recovery_limitations=["Prior timeout must be known for an inverse."],
        post_change_checks=[
            "show running-config | section line vty",
            "confirm authorized SSH session behavior",
        ],
    ),
    "ios_shutdown_unused_interface": RemediationTemplate(
        template_id="ios_shutdown_unused_interface",
        version="1.0.0",
        check_id="DEV-M26-001",
        feature_id="M26",
        platforms=["cisco_switch"],
        firmware_scope="IOS 15 / IOS-XE 16-17 syntactic preview only",
        validation_level="fixture_tested_no_live_lab",
        required_facts=["interfaces", "designated_unused_inventory"],
        dependencies=["explicit_unused_inventory"],
        conflicts=["uplink_or_management_interface"],
        risks=["Can interrupt connectivity if inventory is stale."],
        backup_requirement="verified_restorable_backup_or_manual_recovery_plan",
        reversibility="conditional_inverse",
        recovery_limitations=["No confirmation that interface was safe to disable."],
        post_change_checks=[
            "show interface status",
            "verify management reachability via approved path",
        ],
    ),
}


def list_remediation_templates() -> list[RemediationTemplate]:
    return [template.model_copy(deep=True) for template in _TEMPLATES.values()]


def generate_candidates(
    envelope: FactsEnvelope,
    results: list[PredicateResult],
    policy: NetworkControlPolicy,
    template_ids: list[str] | None = None,
) -> tuple[list[RemediationCandidate], list[dict[str, str]]]:
    selected = template_ids or list(_TEMPLATES)
    candidates: list[RemediationCandidate] = []
    rejected: list[dict[str, str]] = []
    for template_id in selected:
        template = _TEMPLATES.get(template_id)
        if template is None:
            rejected.append({"template_id": template_id, "reason": "UNSUPPORTED_TEMPLATE"})
            continue
        result = next((r for r in results if r.check_id == template.check_id), None)
        if (
            result is None
            or result.org_id != envelope.org_id
            or result.asset_id != envelope.asset_id
        ):
            rejected.append({"template_id": template_id, "reason": "EVIDENCE_IDENTITY_MISMATCH"})
            continue
        if result.status != AssessmentStatus.FAIL:
            rejected.append({"template_id": template_id, "reason": "NO_ESTABLISHED_FAIL"})
            continue
        if envelope.platform not in template.platforms or not _supported_firmware(envelope):
            rejected.append(
                {"template_id": template_id, "reason": "UNSUPPORTED_PLATFORM_OR_FIRMWARE"}
            )
            continue
        try:
            parameters, commands, expected = _render(template_id, envelope, policy)
        except DeviceEngineError as exc:
            rejected.append({"template_id": template_id, "reason": exc.code})
            continue
        evidence_hashes = sorted(ref.sha256 for ref in envelope.evidence_refs)
        content = {
            "org_id": str(envelope.org_id),
            "asset_id": str(envelope.asset_id),
            "template": template_id,
            "version": template.version,
            "platform": envelope.platform,
            "parameters": parameters,
            "evidence": evidence_hashes,
            "preconditions": expected,
        }
        digest = hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        candidates.append(
            RemediationCandidate(
                candidate_hash=digest,
                template_id=template_id,
                template_version=template.version,
                org_id=str(envelope.org_id),
                asset_id=str(envelope.asset_id),
                platform=envelope.platform,
                target_identity={
                    "model": envelope.model,
                    "firmware": envelope.os_or_firmware_version,
                },
                parameters=parameters,
                source_evidence_hashes=evidence_hashes,
                expected_preconditions=expected,
                commands=commands,
            )
        )
    return candidates, rejected


def preview_dry_run(candidate: RemediationCandidate, envelope: FactsEnvelope) -> DryRunPreview:
    if candidate.org_id != str(envelope.org_id) or candidate.asset_id != str(envelope.asset_id):
        raise DeviceEngineError(
            "CANDIDATE_IDENTITY_MISMATCH", "Candidate does not belong to this envelope."
        )
    template = _TEMPLATES[candidate.template_id]
    current, expected = _preview_values(candidate, envelope)
    return DryRunPreview(
        candidate=candidate,
        current=current,
        expected_diff=expected,
        dependencies=template.dependencies,
        conflicts=template.conflicts,
        risks=template.risks,
        missing_preconditions=[],
        service_checks=template.post_change_checks,
        backup_requirement=template.backup_requirement,
        recovery_requirement=template.reversibility,
    )


def recovery_specification(
    candidate: RemediationCandidate, envelope: FactsEnvelope
) -> RecoverySpecification:
    template = _TEMPLATES[candidate.template_id]
    current, _ = _preview_values(candidate, envelope)
    inverse: list[str] | None = None
    if candidate.template_id == "ios_disable_http" and current["http_enabled"] is True:
        inverse = ["configure terminal", "ip http server", "end"]
    elif candidate.template_id == "ios_set_vty_timeout" and current["vty_timeouts"]:
        inverse = [
            "configure terminal",
            *[f"line vty {name}" for name in current["vty_timeouts"]],
            "end",
        ]
    elif (
        candidate.template_id == "ios_shutdown_unused_interface"
        and current["configured_shutdown"] is False
    ):
        inverse = [
            "configure terminal",
            f"interface {candidate.parameters['interface']}",
            "no shutdown",
            "end",
        ]
    return RecoverySpecification(
        kind="template_inverse" if inverse else "manual_recovery_required",
        inverse_commands=inverse,
        prerequisites=["Current state still matches preview", "Approved out-of-band recovery path"],
        drift_concerns=["Configuration may have changed after preview."],
        verification=template.post_change_checks,
        limitations=[*template.recovery_limitations, "Recovery execution is blocked in Phase 7."],
    )


def create_encrypted_backup(
    path: Path, content: bytes, metadata: BackupMetadata, *, cipher: BackupCipher | None
) -> dict[str, Any]:
    if cipher is None:
        raise DeviceEngineError(
            "BACKUP_KEY_PROVIDER_REQUIRED",
            "Sensitive backup persistence requires an authenticated cipher provider.",
        )
    if len(content) > 4 * 1024 * 1024:
        raise DeviceEngineError("BACKUP_TOO_LARGE", "Backup exceeds 4 MiB limit.")
    meta = metadata.model_dump(mode="json")
    aad = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = cipher.encrypt(content, associated_data=aad)
    record = {
        "metadata": meta,
        "original_sha256": hashlib.sha256(content).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "ciphertext_hex": ciphertext.hex(),
        "encrypted": True,
    }
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return {
        "artifact_path": str(path),
        "original_sha256": record["original_sha256"],
        "encrypted": True,
        "restorable_verified": False,
    }


def read_encrypted_backup(
    path: Path, *, cipher: BackupCipher | None, org_id: str, asset_id: str
) -> bytes:
    if cipher is None:
        raise DeviceEngineError(
            "BACKUP_KEY_PROVIDER_REQUIRED", "Cipher provider required to read backup."
        )
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        meta = BackupMetadata.model_validate(record["metadata"])
    except Exception as exc:
        raise DeviceEngineError("BACKUP_ARTIFACT_INVALID", "Backup artifact is invalid.") from exc
    if meta.org_id != org_id or meta.asset_id != asset_id:
        raise DeviceEngineError(
            "BACKUP_METADATA_MISMATCH", "Backup org/asset metadata does not match."
        )
    try:
        ciphertext = bytes.fromhex(record["ciphertext_hex"])
        ciphertext_hash = record["ciphertext_sha256"]
        original_hash = record["original_sha256"]
    except (KeyError, TypeError, ValueError) as exc:
        raise DeviceEngineError(
            "BACKUP_TAMPERED", "Backup artifact integrity fields are invalid."
        ) from exc
    if hashlib.sha256(ciphertext).hexdigest() != ciphertext_hash:
        raise DeviceEngineError("BACKUP_TAMPERED", "Backup ciphertext integrity check failed.")
    aad = json.dumps(record["metadata"], sort_keys=True, separators=(",", ":")).encode()
    plaintext = cipher.decrypt(ciphertext, associated_data=aad)
    if hashlib.sha256(plaintext).hexdigest() != original_hash:
        raise DeviceEngineError("BACKUP_TAMPERED", "Backup plaintext integrity check failed.")
    return plaintext


def _supported_firmware(envelope: FactsEnvelope) -> bool:
    return bool(
        re.search(
            r"(?:IOS(?:-XE)?\s*)?(?:15|16|17)(?:\.|\b)", envelope.os_or_firmware_version, re.I
        )
    )


def _render(
    template_id: str, envelope: FactsEnvelope, policy: NetworkControlPolicy
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    mgmt = envelope.facts.get("management", {})
    if template_id == "ios_disable_http":
        if mgmt.get("http_enabled") is not True:
            raise DeviceEngineError("PRECONDITION_NOT_MET", "HTTP enabled evidence is required.")
        return {}, ["configure terminal", "no ip http server", "end"], {"http_enabled": True}
    if template_id == "ios_set_vty_timeout":
        lines = mgmt.get("vty_lines", [])
        if not lines or policy.expected_vty_lines is None:
            raise DeviceEngineError("VTY_INVENTORY_REQUIRED", "Declared VTY inventory is required.")
        seconds = policy.session_timeout_seconds
        return (
            {"timeout_seconds": seconds, "vty_inventory": policy.expected_vty_lines},
            [
                "configure terminal",
                "line vty 0 4",
                f"exec-timeout {seconds // 60} {seconds % 60}",
                "end",
            ],
            {"vty_inventory_verified": True},
        )
    if template_id == "ios_shutdown_unused_interface":
        inventory = policy.designated_unused_ports
        if not inventory:
            raise DeviceEngineError(
                "UNUSED_PORT_INVENTORY_REQUIRED", "Explicit unused-port inventory is required."
            )
        interface = inventory[0]
        if not _SAFE_INTERFACE.fullmatch(interface):
            raise DeviceEngineError("INVALID_INTERFACE", "Interface identifier rejected.")
        found = next(
            (i for i in envelope.facts.get("interfaces", []) if i.get("name") == interface), None
        )
        if not found:
            raise DeviceEngineError(
                "INTERFACE_NOT_FOUND", "Interface is absent from collected inventory."
            )
        if found.get("configured_shutdown") is not False:
            raise DeviceEngineError("PRECONDITION_NOT_MET", "Interface is not proven enabled.")
        return (
            {"interface": interface},
            ["configure terminal", f"interface {interface}", "shutdown", "end"],
            {"configured_shutdown": False, "designated_unused": True},
        )
    raise DeviceEngineError("UNSUPPORTED_TEMPLATE", "Template is unsupported.")


def _preview_values(
    candidate: RemediationCandidate, envelope: FactsEnvelope
) -> tuple[dict[str, Any], dict[str, Any]]:
    if candidate.template_id == "ios_disable_http":
        return {"http_enabled": envelope.facts.get("management", {}).get("http_enabled")}, {
            "http_enabled": False
        }
    if candidate.template_id == "ios_set_vty_timeout":
        lines = envelope.facts.get("management", {}).get("vty_lines", [])
        return {
            "vty_timeouts": {str(v.get("name")): v.get("exec_timeout_seconds") for v in lines}
        }, {"exec_timeout_seconds": candidate.parameters["timeout_seconds"]}
    interface = candidate.parameters["interface"]
    found = next(i for i in envelope.facts["interfaces"] if i.get("name") == interface)
    return {"interface": interface, "configured_shutdown": found.get("configured_shutdown")}, {
        "configured_shutdown": True
    }
