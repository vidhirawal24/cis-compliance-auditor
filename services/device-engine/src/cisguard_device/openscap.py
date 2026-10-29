"""Safe XCCDF result ingestion and explicit local OpenSCAP assessment."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .errors import DeviceEngineError, FixtureInputError
from .models import AssessmentStatus, EvidenceReference

DEFAULT_MAX_XML_BYTES = 8_388_608
XCCDF_STATES = {
    "pass",
    "fail",
    "error",
    "unknown",
    "notapplicable",
    "notchecked",
    "notselected",
    "informational",
    "fixed",
}


class XccdfRuleResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    result: str
    shared_status_provisional: AssessmentStatus
    time: str | None = None


class XccdfResultDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    synthetic: bool
    benchmark_id: str | None
    benchmark_version: str | None
    profile_id: str | None
    test_result_id: str | None
    start_time: str | None
    end_time: str | None
    rule_results: list[XccdfRuleResult]
    evidence_refs: list[EvidenceReference]


class OpenScapRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    status: Literal["COMPLETED", "COMPLETED_NONCOMPLIANT"]
    exit_status: int
    tool_version: str | None
    content_sha256: str
    profile_id: str
    platform: str
    result: XccdfResultDocument


def ingest_xccdf_results(
    path: Path,
    *,
    artifact_location: str | None = None,
    synthetic: bool = False,
    max_bytes: int = DEFAULT_MAX_XML_BYTES,
) -> XccdfResultDocument:
    content = _read_safe_xml(path, max_bytes=max_bytes)
    root = _parse_xml(content)
    benchmark = root if _local(root.tag) == "Benchmark" else _first(root, "Benchmark")
    test_result = _first(root, "TestResult")
    benchmark_id = benchmark.get("id") if benchmark is not None else None
    benchmark_version = None
    if benchmark is not None:
        version_element = _first(benchmark, "version")
        benchmark_version = _text(version_element)
    rule_results: list[XccdfRuleResult] = []
    if test_result is not None:
        for element in test_result.iter():
            if _local(element.tag) != "rule-result":
                continue
            result_element = _first(element, "result")
            raw_result = (_text(result_element) or "unknown").lower()
            if raw_result not in XCCDF_STATES:
                raw_result = "unknown"
            rule_results.append(
                XccdfRuleResult(
                    rule_id=element.get("idref") or "unknown-rule",
                    result=raw_result,
                    shared_status_provisional=_shared_status(raw_result),
                    time=element.get("time"),
                )
            )
    profile_id = None
    if test_result is not None:
        profile = _first(test_result, "profile")
        profile_id = profile.get("idref") if profile is not None else None
    return XccdfResultDocument(
        synthetic=synthetic,
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
        profile_id=profile_id,
        test_result_id=test_result.get("id") if test_result is not None else None,
        start_time=test_result.get("start-time") if test_result is not None else None,
        end_time=test_result.get("end-time") if test_result is not None else None,
        rule_results=rule_results,
        evidence_refs=[
            EvidenceReference(
                sha256=hashlib.sha256(content).hexdigest(),
                source_identity="offline:xccdf-results-xml",
                artifact_location=artifact_location or path.as_posix(),
                timestamp=_result_timestamp(test_result),
            )
        ],
    )


def inspect_scap_content(path: Path, *, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> dict[str, Any]:
    content = _read_safe_xml(path, max_bytes=max_bytes)
    root = _parse_xml(content)
    profiles = sorted(
        {
            element.get("id")
            for element in root.iter()
            if _local(element.tag) == "Profile" and element.get("id")
        }
    )
    platforms = sorted(
        {
            element.get("idref")
            for element in root.iter()
            if _local(element.tag) == "platform" and element.get("idref")
        }
    )
    return {
        "profiles": profiles,
        "platform_references": platforms,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def run_local_openscap(
    *,
    content_path: Path,
    profile_id: str,
    output_path: Path,
    expected_platform: str,
    timeout_seconds: int = 900,
    max_output_bytes: int = DEFAULT_MAX_XML_BYTES,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    oscap_path: str | None = None,
) -> OpenScapRunResult:
    if expected_platform not in {"ubuntu_20_04_lts", "ubuntu_22_04_lts", "rhel_8", "rhel_9"}:
        raise DeviceEngineError("UNSUPPORTED_PLATFORM", "OpenSCAP platform is unsupported.")
    info = inspect_scap_content(content_path)
    if profile_id not in info["profiles"]:
        raise DeviceEngineError(
            "SCAP_PROFILE_NOT_FOUND", "Requested profile is absent from content."
        )
    if not _platform_compatible(expected_platform, info["platform_references"]):
        raise DeviceEngineError(
            "SCAP_COMPATIBILITY_UNVERIFIED",
            "Content does not provide matching platform compatibility evidence.",
            details={"platform": expected_platform},
        )
    executable = oscap_path or shutil.which("oscap")
    if executable is None:
        raise DeviceEngineError("OSCAP_NOT_AVAILABLE", "OpenSCAP oscap executable is unavailable.")
    if not output_path.parent.is_dir():
        raise DeviceEngineError(
            "OUTPUT_DIRECTORY_NOT_FOUND", "Selected output directory does not exist."
        )
    command = [
        executable,
        "xccdf",
        "eval",
        "--profile",
        profile_id,
        "--results",
        str(output_path),
        str(content_path),
    ]
    try:
        completed = runner(
            command, shell=False, capture_output=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceEngineError("OSCAP_TIMEOUT", "OpenSCAP assessment timed out.") from exc
    if completed.returncode not in {0, 2}:
        raise DeviceEngineError(
            "OSCAP_EXECUTION_FAILED",
            "OpenSCAP assessment failed to execute.",
            details={"exit_status": completed.returncode, "stderr_redacted": True},
        )
    if not output_path.is_file() or output_path.stat().st_size > max_output_bytes:
        raise DeviceEngineError(
            "OSCAP_RESULT_MISSING", "OpenSCAP result file is missing or oversized."
        )
    version = _oscap_version(executable, runner)
    result = ingest_xccdf_results(output_path, artifact_location=output_path.as_posix())
    return OpenScapRunResult(
        status="COMPLETED" if completed.returncode == 0 else "COMPLETED_NONCOMPLIANT",
        exit_status=completed.returncode,
        tool_version=version,
        content_sha256=info["sha256"],
        profile_id=profile_id,
        platform=expected_platform,
        result=result,
    )


def _read_safe_xml(path: Path, *, max_bytes: int) -> bytes:
    try:
        if path.stat().st_size > max_bytes:
            raise FixtureInputError("XML_TOO_LARGE", "XML input exceeds its configured limit.")
        content = path.read_bytes()
    except FileNotFoundError as exc:
        raise FixtureInputError("XML_NOT_FOUND", "XML input file does not exist.") from exc
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise FixtureInputError("UNSAFE_XML", "DTD and entity declarations are rejected.")
    return content


def _parse_xml(content: bytes) -> ET.Element:
    try:
        parser = ET.XMLParser()
        return ET.fromstring(content, parser=parser)
    except ET.ParseError as exc:
        raise FixtureInputError("MALFORMED_XML", "XML input is malformed.") from exc


def _shared_status(result: str) -> AssessmentStatus:
    return {
        "pass": AssessmentStatus.PASS,
        "fail": AssessmentStatus.FAIL,
        "notapplicable": AssessmentStatus.NOT_APPLICABLE,
        "error": AssessmentStatus.ERROR,
        "informational": AssessmentStatus.MANUAL_REVIEW,
    }.get(result, AssessmentStatus.NOT_ASSESSED)


def _platform_compatible(platform: str, references: list[str]) -> bool:
    tokens = {
        "ubuntu_20_04_lts": ("ubuntu", "20.04"),
        "ubuntu_22_04_lts": ("ubuntu", "22.04"),
        "rhel_8": ("redhat", "8"),
        "rhel_9": ("redhat", "9"),
    }[platform]
    return any(all(token in reference.lower() for token in tokens) for reference in references)


def _oscap_version(
    executable: str, runner: Callable[..., subprocess.CompletedProcess[bytes]]
) -> str | None:
    try:
        result = runner(
            [executable, "--version"], shell=False, capture_output=True, timeout=15, check=False
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or b"").decode("utf-8", errors="replace").strip()[:200] or None


def _first(element: ET.Element, local_name: str) -> ET.Element | None:
    for candidate in element.iter():
        if _local(candidate.tag) == local_name:
            return candidate
    return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text.strip() or None


def _result_timestamp(test_result: ET.Element | None):
    from datetime import UTC, datetime

    if test_result is not None:
        value = test_result.get("end-time") or test_result.get("start-time")
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed):
                    return parsed
            except ValueError:
                pass
    return datetime(1970, 1, 1, tzinfo=UTC)
