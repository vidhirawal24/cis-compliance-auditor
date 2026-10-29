"""Offline import tests (Phase 6 / E10).

All tests use pre-created fixture files to avoid the pre-existing
.pytest-tmp PermissionError on this Windows host.  tmp_path is not used.

Tests must not contact devices or modify host configuration.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from cisguard_device.errors import FixtureInputError
from cisguard_device.models import AssessmentStatus
from cisguard_device.network_predicates import NetworkControlPolicy, evaluate_network_controls
from cisguard_device.offline_import import (
    SOURCE_TYPE_PLATFORMS,
    SUPPORTED_SOURCE_TYPES,
    EvidenceProvenance,
    OfflineImportMetadata,
    import_offline_file,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
NETWORK = FIXTURES / "network"
ORG_ID = UUID("11111111-1111-4111-8111-111111111111")
ASSET_ID = UUID("22222222-2222-4222-8222-222222222222")


def _metadata(source_type="cisco_ios_running_config", platform="cisco_router", **changes):
    values = {
        "source_type": source_type,
        "platform": platform,
        "org_id": ORG_ID,
        "asset_id": ASSET_ID,
        "capture_timestamp": datetime(2026, 10, 29, 1, tzinfo=UTC),
        "completeness": "complete",
    }
    values.update(changes)
    return OfflineImportMetadata(**values)


# ---------------------------------------------------------------------------
# Provenance and metadata validation
# ---------------------------------------------------------------------------


def test_import_requires_explicit_completeness_and_rejects_live_provenance() -> None:
    """completeness is required; live_collection provenance is rejected."""
    with pytest.raises(ValidationError):
        # Missing completeness (now required)
        OfflineImportMetadata(
            source_type="cisco_ios_running_config",
            platform="cisco_router",
            org_id=ORG_ID,
            asset_id=ASSET_ID,
        )
    with pytest.raises(ValidationError):
        _metadata(provenance=EvidenceProvenance.LIVE_COLLECTION)


def test_supported_source_types_are_documented() -> None:
    """All supported types must have a platform mapping."""
    for source_type in SUPPORTED_SOURCE_TYPES:
        assert source_type in SOURCE_TYPE_PLATFORMS
        assert len(SOURCE_TYPE_PLATFORMS[source_type]) > 0


def test_synthetic_provenance_is_distinct_from_user_capture() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    envelope = import_offline_file(
        source,
        _metadata(provenance=EvidenceProvenance.SYNTHETIC_FIXTURE),
    )
    assert envelope.collection_method == "offline_synthetic_fixture"
    assert envelope.facts["import"]["provenance"] == "synthetic_fixture"


def test_user_supplied_capture_provenance() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    envelope = import_offline_file(source, _metadata())
    assert envelope.collection_method == "offline_user_supplied_capture"
    assert envelope.facts["import"]["provenance"] == "user_supplied_capture"


# ---------------------------------------------------------------------------
# Cisco IOS import — source immutability and secret redaction
# ---------------------------------------------------------------------------


def test_cisco_import_redacts_community_and_does_not_mutate_source() -> None:
    """Community strings must not appear in output; source must not be modified."""
    source = NETWORK / "import_cisco" / "running-config-with-community.txt"
    operational = NETWORK / "import_cisco" / "show-output.txt"

    source_hash_before = hashlib.sha256(source.read_bytes()).hexdigest()
    operational_hash_before = hashlib.sha256(operational.read_bytes()).hexdigest()

    imported = import_offline_file(source, _metadata(), operational_path=operational)
    serialized = imported.model_dump_json()

    assert imported.collection_method == "offline_user_supplied_capture"
    assert imported.facts["import"]["provenance"] == "user_supplied_capture"
    assert imported.facts["snmp"]["default_community_present"] is True
    assert "public" not in serialized
    # Community strings are never emitted directly
    assert '"community": "public"' not in serialized
    # Source files not mutated
    assert source_hash_before == hashlib.sha256(source.read_bytes()).hexdigest()
    assert operational_hash_before == hashlib.sha256(operational.read_bytes()).hexdigest()


def test_cisco_import_acl_bindings_are_structured() -> None:
    """ACL bindings from Cisco config must be structured (not raw text)."""
    source = NETWORK / "import_cisco" / "running-config-with-community.txt"
    imported = import_offline_file(source, _metadata())
    bindings = imported.facts["acl_bindings"]
    assert isinstance(bindings, list)
    assert len(bindings) > 0
    binding = bindings[0]
    assert "interface" in binding
    assert "acl_id" in binding
    assert "direction" in binding


def test_cisco_import_never_prints_raw_configuration() -> None:
    """Raw configuration must not appear in the JSON output."""
    source = NETWORK / "import_cisco" / "running-config-with-community.txt"
    raw_text = source.read_text(encoding="utf-8")
    imported = import_offline_file(source, _metadata())
    serialized = imported.model_dump_json()
    # The hostname is fine to appear but the full raw config block must not
    assert "snmp-server community" not in serialized
    # Raw IOS config text (first few chars of the version line)
    assert raw_text not in serialized


# ---------------------------------------------------------------------------
# Capture timestamp provenance
# ---------------------------------------------------------------------------


def test_unknown_timestamp_uses_explicit_import_time_and_preserves_uncertainty() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    imported_at = datetime(2026, 10, 30, 1, tzinfo=UTC)
    result = import_offline_file(source, _metadata(capture_timestamp=None), imported_at=imported_at)
    assert result.facts["import"]["capture_timestamp_known"] is False
    assert result.facts["import"]["source_capture_timestamp"] is None
    assert result.facts["import"]["imported_at"] == imported_at.isoformat()
    assert result.collected_at == imported_at
    assert result.errors[0].code == "CAPTURE_TIMESTAMP_UNKNOWN"
    assert result.evidence_refs[0].timestamp == result.collected_at


def test_known_timestamp_is_preserved_verbatim() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    ts = datetime(2026, 3, 15, 12, 0, tzinfo=UTC)
    result = import_offline_file(source, _metadata(capture_timestamp=ts))
    assert result.collected_at == ts
    assert result.facts["import"]["capture_timestamp_known"] is True
    assert not result.errors  # no timestamp warning


# ---------------------------------------------------------------------------
# Partial/incomplete capture → no false PASSes
# ---------------------------------------------------------------------------


def test_partial_capture_downgrades_pass_results_to_not_assessed() -> None:
    """A partial capture must not produce PASS for absence-of-bad-setting claims."""
    source = NETWORK / "import_cisco" / "running-config.txt"
    envelope = import_offline_file(source, _metadata(completeness="partial"))
    results = evaluate_network_controls(envelope, NetworkControlPolicy(session_timeout_seconds=300))
    telnet = next(r for r in results if r.check_id == "DEV-M20-001")
    assert telnet.status == AssessmentStatus.NOT_ASSESSED
    assert telnet.error_code == "INCOMPLETE_CAPTURE"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_import_is_deterministic_for_same_file_and_metadata() -> None:
    """Importing the same file twice must produce identical results."""
    source = NETWORK / "import_cisco" / "running-config.txt"
    metadata = _metadata()
    imported_at = datetime(2026, 10, 30, 1, tzinfo=UTC)
    first = import_offline_file(source, metadata, imported_at=imported_at).model_dump(mode="json")
    second = import_offline_file(source, metadata, imported_at=imported_at).model_dump(mode="json")
    assert first == second


# ---------------------------------------------------------------------------
# Platform/source_type mismatch and size limits
# ---------------------------------------------------------------------------


def test_platform_source_type_mismatch_is_rejected() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    with pytest.raises(FixtureInputError, match="Platform"):
        import_offline_file(source, _metadata(platform="sophos_firewall"))


def test_invalid_size_limit_is_rejected() -> None:
    source = NETWORK / "import_cisco" / "running-config.txt"
    with pytest.raises(FixtureInputError) as exc:
        import_offline_file(source, _metadata(), max_bytes=0)
    assert exc.value.code == "INVALID_SIZE_LIMIT"


def test_oversized_source_is_rejected() -> None:
    """A file exceeding max_bytes must raise FILE_TOO_LARGE."""
    source = NETWORK / "import_cisco" / "running-config.txt"
    with pytest.raises(FixtureInputError) as exc:
        import_offline_file(source, _metadata(), max_bytes=1)
    assert exc.value.code == "FILE_TOO_LARGE"


def test_malformed_source_is_rejected() -> None:
    """A non-IOS text file must be rejected with UNSUPPORTED_IOS_VERSION."""
    source = NETWORK / "import_cisco" / "not-ios.txt"
    with pytest.raises(FixtureInputError) as exc:
        import_offline_file(source, _metadata())
    assert exc.value.code == "UNSUPPORTED_IOS_VERSION"


# ---------------------------------------------------------------------------
# All supported parser source types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source_type", "platform", "capture"),
    [
        (
            "sophos_firewall_api_xml",
            "sophos_firewall",
            FIXTURES / "remaining" / "sophos_firewall" / "secure" / "source.xml",
        ),
        (
            "palo_alto_panos_xml",
            "palo_alto_panos",
            FIXTURES / "remaining" / "palo_alto_panos" / "secure" / "source.xml",
        ),
        (
            "windows_json_capture",
            "windows_11_enterprise",
            FIXTURES / "windows" / "windows11_enterprise_secure" / "capture.json",
        ),
        ("linux_json_capture", "rhel_9", FIXTURES / "linux" / "rhel9_secure" / "capture.json"),
        (
            "firewall_capture_json",
            "fortinet_fortios",
            FIXTURES / "firewalls" / "fortios" / "secure" / "capture.json",
        ),
    ],
)
def test_existing_parser_source_types_import_offline(source_type, platform, capture) -> None:
    """Each supported source type must produce a valid FactsEnvelope."""
    envelope = import_offline_file(
        capture,
        _metadata(source_type=source_type, platform=platform),
    )
    assert envelope.platform == platform
    assert envelope.facts["import"]["source_type"] == source_type
    assert envelope.collection_method == "offline_user_supplied_capture"
    assert "current_state_proof" in envelope.unsupported_capabilities
    if source_type == "windows_json_capture":
        assert "os" in envelope.facts
        assert "windows_capture" not in envelope.facts
    if source_type == "linux_json_capture":
        assert "os_identity" in envelope.facts
        assert "linux_capture" not in envelope.facts


# ---------------------------------------------------------------------------
# Secret redaction in Windows capture
# ---------------------------------------------------------------------------


def test_windows_import_excludes_secret_fields() -> None:
    """Secret-like keys injected into a Windows capture must not appear in output."""
    capture_path = FIXTURES / "windows" / "windows11_enterprise_secure" / "capture.json"
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    # Inject a secret-like value into the capture
    capture.setdefault("sources", {}).setdefault("account_policy", {}).setdefault("data", {})[
        "password"
    ] = "never-print-this"

    # Write modified capture to a fixed network fixture file
    secret_fixture = NETWORK / "import_cisco" / "_windows_secret_test.json"
    secret_fixture.write_text(json.dumps(capture), encoding="utf-8")

    envelope = import_offline_file(
        secret_fixture,
        _metadata(source_type="windows_json_capture", platform="windows_11_enterprise"),
    )
    payload = envelope.model_dump_json()
    assert "never-print-this" not in payload
    # Clean up
    secret_fixture.unlink(missing_ok=True)
