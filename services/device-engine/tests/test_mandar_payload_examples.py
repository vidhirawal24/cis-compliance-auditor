"""Validate handoff examples that correspond to implemented local schemas."""

import json
from pathlib import Path

from cisguard_device.models import FactsEnvelope, UnsupportedOperationResult

SAMPLES = Path(__file__).parents[3] / "docs" / "device" / "sample-payloads"


def test_all_handoff_samples_are_json() -> None:
    for path in sorted(SAMPLES.glob("*.json")):
        assert isinstance(json.loads(path.read_text(encoding="utf-8")), dict), path.name


def test_implemented_schema_examples_validate() -> None:
    FactsEnvelope.model_validate_json((SAMPLES / "collection-response.json").read_text())
    UnsupportedOperationResult.model_validate_json((SAMPLES / "structured-error.json").read_text())
