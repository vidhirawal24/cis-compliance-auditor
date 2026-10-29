import shutil
import subprocess
from pathlib import Path

import pytest

from cisguard_device.errors import DeviceEngineError, FixtureInputError
from cisguard_device.models import AssessmentStatus
from cisguard_device.openscap import (
    ingest_xccdf_results,
    inspect_scap_content,
    run_local_openscap,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "openscap"
RESULTS = FIXTURES / "synthetic-results.xml"
CONTENT = FIXTURES / "synthetic-ubuntu2204-content.xml"


def test_xccdf_preserves_all_result_states_and_provisional_mapping() -> None:
    result = ingest_xccdf_results(RESULTS, synthetic=True)
    states = {item.result for item in result.rule_results}
    assert states == {
        "pass",
        "fail",
        "notchecked",
        "notselected",
        "unknown",
        "error",
        "informational",
        "notapplicable",
        "fixed",
    }
    mapping = {item.result: item.shared_status_provisional for item in result.rule_results}
    assert mapping["pass"] == AssessmentStatus.PASS
    assert mapping["fail"] == AssessmentStatus.FAIL
    assert mapping["notapplicable"] == AssessmentStatus.NOT_APPLICABLE
    assert mapping["informational"] == AssessmentStatus.MANUAL_REVIEW
    assert mapping["unknown"] == AssessmentStatus.NOT_ASSESSED
    assert mapping["fixed"] == AssessmentStatus.NOT_ASSESSED


def test_xccdf_exact_hash_and_profile_metadata() -> None:
    result = ingest_xccdf_results(RESULTS, synthetic=True)
    assert result.synthetic is True
    assert result.profile_id == "synthetic_profile"
    assert result.benchmark_id == "synthetic_benchmark_not_official"
    assert len(result.evidence_refs[0].sha256) == 64


def test_dtd_entity_and_malformed_xml_are_rejected(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.xml"
    unsafe.write_text(
        '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', encoding="utf-8"
    )
    with pytest.raises(FixtureInputError) as captured:
        ingest_xccdf_results(unsafe)
    assert captured.value.code == "UNSAFE_XML"
    malformed = tmp_path / "malformed.xml"
    malformed.write_text("<x>", encoding="utf-8")
    with pytest.raises(FixtureInputError) as captured:
        ingest_xccdf_results(malformed)
    assert captured.value.code == "MALFORMED_XML"


def test_content_profile_and_platform_inspection() -> None:
    info = inspect_scap_content(CONTENT)
    assert info["profiles"] == ["synthetic_profile"]
    assert info["platform_references"] == ["cpe:/o:canonical:ubuntu_linux:22.04"]


def test_missing_profile_and_mismatched_platform(tmp_path: Path) -> None:
    with pytest.raises(DeviceEngineError) as profile:
        run_local_openscap(
            content_path=CONTENT,
            profile_id="missing",
            output_path=tmp_path / "out.xml",
            expected_platform="ubuntu_22_04_lts",
            oscap_path="oscap",
        )
    assert profile.value.code == "SCAP_PROFILE_NOT_FOUND"
    with pytest.raises(DeviceEngineError) as platform:
        run_local_openscap(
            content_path=CONTENT,
            profile_id="synthetic_profile",
            output_path=tmp_path / "out.xml",
            expected_platform="ubuntu_20_04_lts",
            oscap_path="oscap",
        )
    assert platform.value.code == "SCAP_COMPATIBILITY_UNVERIFIED"


def test_oscap_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(DeviceEngineError) as captured:
        run_local_openscap(
            content_path=CONTENT,
            profile_id="synthetic_profile",
            output_path=tmp_path / "out.xml",
            expected_platform="ubuntu_22_04_lts",
        )
    assert captured.value.code == "OSCAP_NOT_AVAILABLE"


@pytest.mark.parametrize(
    ("exit_status", "status"), [(0, "COMPLETED"), (2, "COMPLETED_NONCOMPLIANT")]
)
def test_oscap_success_and_noncompliant_exit_status(
    exit_status: int, status: str, tmp_path: Path
) -> None:
    output = tmp_path / "result.xml"

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=b"OpenSCAP 1.synthetic", stderr=b""
            )
        output.write_bytes(RESULTS.read_bytes())
        return subprocess.CompletedProcess(command, exit_status, stdout=b"", stderr=b"")

    result = run_local_openscap(
        content_path=CONTENT,
        profile_id="synthetic_profile",
        output_path=output,
        expected_platform="ubuntu_22_04_lts",
        runner=runner,
        oscap_path="oscap",
    )
    assert result.status == status
    assert result.exit_status == exit_status
    assert result.tool_version == "OpenSCAP 1.synthetic"


def test_oscap_timeout_and_execution_failure(tmp_path: Path) -> None:
    output = tmp_path / "result.xml"

    def timeout(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(command, 1)

    with pytest.raises(DeviceEngineError) as captured:
        run_local_openscap(
            content_path=CONTENT,
            profile_id="synthetic_profile",
            output_path=output,
            expected_platform="ubuntu_22_04_lts",
            runner=timeout,
            oscap_path="oscap",
        )
    assert captured.value.code == "OSCAP_TIMEOUT"

    def failed(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"sensitive")

    with pytest.raises(DeviceEngineError) as captured:
        run_local_openscap(
            content_path=CONTENT,
            profile_id="synthetic_profile",
            output_path=output,
            expected_platform="ubuntu_22_04_lts",
            runner=failed,
            oscap_path="oscap",
        )
    assert captured.value.code == "OSCAP_EXECUTION_FAILED"
    assert captured.value.details == {"exit_status": 1, "stderr_redacted": True}
