from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from cisguard_device.errors import DeviceEngineError
from cisguard_device.models import AssessmentStatus, EvidenceReference, FactsEnvelope
from cisguard_device.network_predicates import NetworkControlPolicy, PredicateResult
from cisguard_device.remediation import (
    BackupMetadata,
    create_encrypted_backup,
    generate_candidates,
    list_remediation_templates,
    preview_dry_run,
    read_encrypted_backup,
    recovery_specification,
)

ORG = UUID("11111111-1111-4111-8111-111111111111")
ASSET = UUID("22222222-2222-4222-8222-222222222222")


class _Cipher:
    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        return bytes(
            value ^ associated_data[index % len(associated_data)]
            for index, value in enumerate(plaintext)
        )

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes:
        return self.encrypt(ciphertext, associated_data=associated_data)


def _envelope() -> FactsEnvelope:
    at = datetime(2026, 10, 29, tzinfo=UTC)
    return FactsEnvelope(
        org_id=ORG,
        asset_id=ASSET,
        platform="cisco_switch",
        vendor="Cisco",
        model="synthetic",
        os_or_firmware_version="IOS-XE 17.9",
        collector_version="test",
        collection_method="fixture",
        collected_at=at,
        facts={
            "management": {
                "http_enabled": True,
                "vty_lines": [{"name": "0-4", "exec_timeout_seconds": 600}],
            },
            "interfaces": [{"name": "GigabitEthernet1/0/2", "configured_shutdown": False}],
        },
        evidence_refs=[
            EvidenceReference(
                sha256="a" * 64,
                source_identity="fixture",
                artifact_location="fixture://x",
                timestamp=at,
            )
        ],
    )


def _result(check_id: str, status: AssessmentStatus = AssessmentStatus.FAIL) -> PredicateResult:
    return PredicateResult(
        check_id=check_id,
        feature_id="M20",
        org_id=ORG,
        asset_id=ASSET,
        status=status,
        actual={},
        expected={},
        explanation="fixture",
    )


def _policy() -> NetworkControlPolicy:
    return NetworkControlPolicy(
        session_timeout_seconds=300,
        expected_vty_lines=[0, 1, 2, 3, 4],
        designated_unused_ports=["GigabitEthernet1/0/2"],
    )


def test_catalog_and_candidate_hash_determinism_and_changes() -> None:
    assert {item.template_id for item in list_remediation_templates()} == {
        "ios_disable_http",
        "ios_set_vty_timeout",
        "ios_shutdown_unused_interface",
    }
    envelope = _envelope()
    result = _result("DEV-M21-001")
    first, rejected = generate_candidates(envelope, [result], _policy(), ["ios_disable_http"])
    second, _ = generate_candidates(envelope, [result], _policy(), ["ios_disable_http"])
    assert not rejected and first[0].candidate_hash == second[0].candidate_hash
    changed = envelope.model_copy(deep=True)
    changed.evidence_refs[0].sha256 = "b" * 64
    third, _ = generate_candidates(changed, [result], _policy(), ["ios_disable_http"])
    assert third[0].candidate_hash != first[0].candidate_hash


def test_candidate_rejects_identity_status_and_preconditions() -> None:
    envelope = _envelope()
    candidates, rejected = generate_candidates(
        envelope, [_result("DEV-M21-001", AssessmentStatus.PASS)], _policy()
    )
    assert not candidates and rejected[0]["reason"] == "NO_ESTABLISHED_FAIL"
    bad = _result("DEV-M21-001")
    bad.asset_id = UUID("33333333-3333-4333-8333-333333333333")
    _, rejected = generate_candidates(envelope, [bad], _policy())
    assert rejected[0]["reason"] == "EVIDENCE_IDENTITY_MISMATCH"
    envelope.facts["management"]["http_enabled"] = None
    _, rejected = generate_candidates(envelope, [_result("DEV-M21-001")], _policy())
    assert rejected[0]["reason"] == "PRECONDITION_NOT_MET"


def test_preview_immutable_recovery_and_interface_validation() -> None:
    envelope = _envelope()
    original = envelope.model_dump(mode="json")
    candidates, _ = generate_candidates(
        envelope, [_result("DEV-M21-001")], _policy(), ["ios_disable_http"]
    )
    preview = preview_dry_run(candidates[0], envelope)
    assert preview.outcome == "PREDICTED_NOT_EXECUTED"
    assert preview.expected_diff == {"http_enabled": False}
    assert envelope.model_dump(mode="json") == original
    recovery = recovery_specification(candidates[0], envelope)
    assert recovery.kind == "template_inverse" and recovery.execution_status == "BLOCKED"
    bad_policy = _policy()
    bad_policy.designated_unused_ports = ["Gi1/0/2;reload"]
    _, rejected = generate_candidates(
        envelope, [_result("DEV-M26-001")], bad_policy, ["ios_shutdown_unused_interface"]
    )
    assert rejected[0]["reason"] == "INVALID_INTERFACE"


def test_encrypted_backup_round_trip_tamper_and_metadata(tmp_path: Path) -> None:
    meta = BackupMetadata(
        org_id=str(ORG),
        asset_id=str(ASSET),
        platform="cisco_switch",
        model="synthetic",
        firmware="17.9",
        capture_timestamp=datetime(2026, 10, 29, tzinfo=UTC),
        provenance="synthetic",
        artifact_kind="offline_snapshot",
        completeness="complete",
        recovery_capability="unverified_snapshot",
    )
    path = tmp_path / "backup.json"
    with pytest.raises(DeviceEngineError, match="requires"):
        create_encrypted_backup(path, b"secret-config", meta, cipher=None)
    result = create_encrypted_backup(path, b"secret-config", meta, cipher=_Cipher())
    assert result["encrypted"] is True and result["restorable_verified"] is False
    assert (
        read_encrypted_backup(path, cipher=_Cipher(), org_id=str(ORG), asset_id=str(ASSET))
        == b"secret-config"
    )
    with pytest.raises(DeviceEngineError):
        read_encrypted_backup(path, cipher=_Cipher(), org_id=str(ORG), asset_id=str(UUID(int=1)))
    path.write_text(
        path.read_text(encoding="utf-8").replace("ciphertext_hex", "tampered_hex"), encoding="utf-8"
    )
    with pytest.raises(DeviceEngineError):
        read_encrypted_backup(path, cipher=_Cipher(), org_id=str(ORG), asset_id=str(ASSET))
