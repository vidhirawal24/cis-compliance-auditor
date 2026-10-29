from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from cisguard_device.models import FactsEnvelope


def envelope(**overrides: object) -> FactsEnvelope:
    values: dict[str, object] = {
        "org_id": UUID("11111111-1111-4111-8111-111111111111"),
        "asset_id": UUID("22222222-2222-4222-8222-222222222222"),
        "platform": "synthetic_fixture",
        "vendor": "SYNTHETIC_ONLY",
        "model": "test",
        "os_or_firmware_version": "unknown",
        "collector_version": "0.1.0",
        "collection_method": "synthetic_fixture",
        "collected_at": datetime(2026, 10, 29, tzinfo=UTC),
        "facts": {"setting": None},
    }
    values.update(overrides)
    return FactsEnvelope.model_validate(values)


def test_valid_envelope_json_round_trip() -> None:
    original = envelope()
    restored = FactsEnvelope.model_validate_json(original.model_dump_json())
    assert restored == original


def test_invalid_uuid_rejected() -> None:
    with pytest.raises(ValidationError):
        envelope(org_id="not-a-uuid")


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        envelope(collected_at=datetime(2026, 10, 29))


def test_unknown_fact_remains_unknown() -> None:
    serialized = envelope().model_dump(mode="json")
    assert "setting" in serialized["facts"]
    assert serialized["facts"]["setting"] is None
