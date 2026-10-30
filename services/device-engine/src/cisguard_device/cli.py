"""Machine-readable standalone CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from pydantic import ValidationError

from .errors import DeviceEngineError
from .firewalls import collect_firewall_fixture, probe_firewall_fixture
from .fixtures import collect_fixture, probe_fixture
from .linux import (
    EnvironmentSSHSecretProvider,
    collect_linux_fixture,
    collect_linux_local,
    collect_linux_ssh,
    probe_linux_fixture,
)
from .models import EvidenceReference, FactsEnvelope
from .network_predicates import NetworkControlPolicy
from .offline_import import (
    EvidenceProvenance,
    OfflineImportMetadata,
    import_offline_file,
)
from .openscap import ingest_xccdf_results, run_local_openscap
from .operations import candidates, evaluate_device, execute, simulate, verify
from .remaining_devices import collect_remaining_fixture, probe_remaining_fixture
from .remediation import list_remediation_templates
from .simulation import SimulationInput
from .verification import compare_normalized_facts, drift_events
from .windows import (
    EnvironmentWinRMSecretProvider,
    collect_windows_fixture,
    collect_windows_local,
    collect_windows_winrm,
    probe_windows_fixture,
)

DEVICE_FAMILIES = (
    "windows_11_enterprise",
    "windows_11_standalone",
    "windows_server_2019",
    "ubuntu_20_04_lts",
    "ubuntu_22_04_lts",
    "rhel_8",
    "rhel_9",
    "fortinet_fortios",
    "cisco_asa",
    "cisco_ftd",
    "check_point",
    "sophos_firewall",
    "palo_alto_panos",
    "cisco_router",
    "cisco_managed_switch",
)
_CLI_REQUEST_NAMESPACE = UUID("dd35838c-47df-46ce-875c-2822d815dc75")


def _write_json(payload: Any) -> None:
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def capabilities() -> int:
    _write_json(
        {
            "schema_version": "1.0.0",
            "device_families": [
                {
                    "platform": platform,
                    "implementation_status": (
                        "PHASE2_PARTIAL"
                        if platform
                        in {
                            "windows_11_enterprise",
                            "windows_11_standalone",
                            "windows_server_2019",
                        }
                        else "PHASE3_PARTIAL"
                        if platform
                        in {
                            "ubuntu_20_04_lts",
                            "ubuntu_22_04_lts",
                            "rhel_8",
                            "rhel_9",
                        }
                        else "PHASE4_PARTIAL"
                        if platform in {"fortinet_fortios", "cisco_asa", "cisco_ftd", "check_point"}
                        else "PHASE5_PARTIAL"
                        if platform in {"sophos_firewall", "palo_alto_panos"}
                        else "PHASE6_PARTIAL"
                        if platform in {"cisco_router", "cisco_managed_switch"}
                        else "NOT_IMPLEMENTED"
                    ),
                    "fixture_tests": True,
                    "live_lab_tests": False,
                }
                for platform in DEVICE_FAMILIES
            ],
            "fixture_adapters": [
                {
                    "platform": "cisco_ios_fixture",
                    "implementation_status": "FIXTURE_ONLY_PARTIAL",
                    "fixture_tests": True,
                    "live_lab_tests": False,
                    "vendor_support_claim": False,
                }
            ],
            "windows_transports": {
                "offline_capture": "FIXTURE_TESTED",
                "local_powershell": "IMPLEMENTED_SMOKE_BLOCKED_BY_PRIVILEGES",
                "winrm": "IMPLEMENTED_MOCK_TESTED_NO_AUTHORIZED_LAB",
            },
            "linux_transports": {
                "offline_capture": "FIXTURE_TESTED",
                "local_python": "IMPLEMENTED_NOT_RUN_WINDOWS_HOST",
                "ssh": "IMPLEMENTED_MOCK_TESTED_NO_AUTHORIZED_LAB",
            },
            "openscap": {
                "xccdf_ingestion": "FIXTURE_TESTED",
                "local_assessment": "IMPLEMENTED_MOCK_TESTED_OSCAP_UNAVAILABLE",
                "ubuntu_20_04_content": "UNAVAILABLE_NOT_SUBSTITUTED",
            },
            "firewall_transports": {
                "offline_capture": "FIXTURE_TESTED",
                "cisco_asa_ssh": "IMPLEMENTED_MOCK_TESTED_NO_AUTHORIZED_LAB",
                "fortios_api": "BLOCKED_UNVERIFIED_ENDPOINT_CONTRACT",
                "fmc_api": "BLOCKED_UNVERIFIED_ENDPOINT_CONTRACT",
                "checkpoint_api": "BLOCKED_UNVERIFIED_ENDPOINT_CONTRACT",
            },
        }
    )
    return 0


def synthetic_envelope() -> FactsEnvelope:
    fixture = b"synthetic phase-0 serialization fixture; no device collection"
    collected_at = datetime(2026, 10, 29, 0, 0, tzinfo=UTC)
    return FactsEnvelope(
        org_id=UUID("11111111-1111-4111-8111-111111111111"),
        asset_id=UUID("22222222-2222-4222-8222-222222222222"),
        platform="synthetic_fixture",
        vendor="SYNTHETIC_ONLY",
        model="phase0-envelope-fixture",
        os_or_firmware_version="unknown",
        collector_version="0.1.0",
        collection_method="synthetic_fixture_serialization_only",
        collected_at=collected_at,
        facts={"management": {"telnet_enabled": None}},
        evidence_refs=[
            EvidenceReference(
                sha256=hashlib.sha256(fixture).hexdigest(),
                source_identity="embedded:phase0-self-test-fixture",
                artifact_location="fixture://embedded/phase0-self-test",
                timestamp=collected_at,
            )
        ],
        supported_capabilities=[],
        unsupported_capabilities=["live_collection", "compliance_evaluation"],
        errors=[],
    )


def self_test() -> int:
    _write_json(synthetic_envelope().model_dump(mode="json"))
    return 0


def _unsupported_result(command: str) -> int:
    handlers = {
        "candidates": candidates,
        "execute": execute,
        "verify": verify,
    }
    result = handlers[command]({})
    _write_json(result.model_dump(mode="json"))
    print(result.error.message, file=sys.stderr)
    return 3


def _simulate_command(args: argparse.Namespace) -> int:
    payload = json.loads(_read_cli_json(Path(args.input), args.max_bytes))
    supplied_backend = payload.get("backend")
    if supplied_backend is not None and supplied_backend != args.backend:
        raise DeviceEngineError(
            "BACKEND_MISMATCH", "Input backend must match the explicit --backend choice."
        )
    payload["backend"] = args.backend
    result = simulate(SimulationInput.model_validate(payload))
    _write_json(result.model_dump(mode="json"))
    return 0


def _compare_command(args: argparse.Namespace) -> int:
    before = FactsEnvelope.model_validate_json(_read_cli_json(Path(args.before), args.max_bytes))
    after = FactsEnvelope.model_validate_json(_read_cli_json(Path(args.after), args.max_bytes))
    _write_json(
        {
            "mode": "OFFLINE_COMPARISON_NOT_POST_FIX_VERIFICATION",
            "differences": [
                item.model_dump(mode="json") for item in compare_normalized_facts(before, after)
            ],
            "drift_events": [item.model_dump(mode="json") for item in drift_events(before, after)],
        }
    )
    return 0


def _offline_import_command(args: argparse.Namespace) -> int:
    try:
        capture_timestamp = (
            datetime.fromisoformat(args.capture_timestamp) if args.capture_timestamp else None
        )
    except ValueError as exc:
        raise DeviceEngineError(
            "INVALID_CAPTURE_TIMESTAMP", "Capture timestamp must be ISO-8601 with a UTC offset."
        ) from exc
    metadata = OfflineImportMetadata(
        source_type=args.source_type,
        platform=args.platform,
        org_id=args.org_id,
        asset_id=args.asset_id,
        capture_timestamp=capture_timestamp,
        provenance=EvidenceProvenance(args.provenance),
        completeness=args.completeness,
    )
    envelope = import_offline_file(
        Path(args.input),
        metadata,
        max_bytes=args.max_bytes,
        operational_path=Path(args.operational) if args.operational else None,
    )
    _write_json(envelope.model_dump(mode="json"))
    return 0


def _evaluate_device_command(args: argparse.Namespace) -> int:
    try:
        fixture_arg = getattr(args, "fixture", None)
        envelope_arg = getattr(args, "envelope", None)
        if fixture_arg:
            envelope = collect_remaining_fixture(Path(fixture_arg), max_bytes=args.max_bytes)
        elif envelope_arg:
            envelope_bytes = _read_cli_json(Path(envelope_arg), args.max_bytes)
            envelope = FactsEnvelope.model_validate_json(envelope_bytes)
        else:
            raise DeviceEngineError(
                "INPUT_REQUIRED", "Either --envelope or --fixture must be supplied."
            )

        policy_json_arg = getattr(args, "policy_json", None)
        policy_arg = getattr(args, "policy", None)
        if policy_json_arg:
            policy = NetworkControlPolicy.model_validate_json(policy_json_arg)
        elif policy_arg:
            policy_bytes = _read_cli_json(Path(policy_arg), args.max_bytes)
            policy = NetworkControlPolicy.model_validate_json(policy_bytes)
        else:
            raise DeviceEngineError(
                "POLICY_REQUIRED", "Either --policy or --policy-json must be supplied."
            )
    except ValidationError:
        raise
    results = evaluate_device(envelope, policy)
    _write_json(
        {"assessment_status": "COMPLETED", "results": [r.model_dump(mode="json") for r in results]}
    )
    return 0


def _read_cli_json(path: Path, max_bytes: int) -> bytes:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise DeviceEngineError(
                "FILE_TOO_LARGE", f"JSON input exceeds the {max_bytes}-byte limit."
            )
        content = path.read_bytes()
    except OSError as exc:
        raise DeviceEngineError("FILE_READ_ERROR", f"Cannot read '{path.name}'.") from exc
    if len(content) > max_bytes:
        raise DeviceEngineError("FILE_TOO_LARGE", f"JSON input exceeds the {max_bytes}-byte limit.")
    return content[3:] if content.startswith(b"\xef\xbb\xbf") else content


def _fixture_command(args: argparse.Namespace) -> int:
    manifest_path = Path(args.fixture)
    if args.command == "probe":
        _write_json(probe_fixture(manifest_path, platform=args.platform))
    else:
        envelope = collect_fixture(
            manifest_path,
            platform=args.platform,
            max_bytes=args.max_bytes,
        )
        _write_json(envelope.model_dump(mode="json"))
    return 0


def _windows_command(args: argparse.Namespace) -> int:
    if args.command == "windows-probe":
        _write_json(probe_windows_fixture(Path(args.fixture)))
        return 0
    if args.transport == "offline":
        if not args.fixture:
            raise DeviceEngineError(
                "FIXTURE_REQUIRED", "Offline Windows collection requires --fixture."
            )
        envelope = collect_windows_fixture(Path(args.fixture))
    else:
        if args.org_id is None or args.asset_id is None:
            raise DeviceEngineError(
                "IDENTIFIERS_REQUIRED",
                "Local and WinRM collection require --org-id and --asset-id.",
            )
        if args.transport == "local":
            envelope = collect_windows_local(
                org_id=args.org_id,
                asset_id=args.asset_id,
                model=args.model,
                timeout_seconds=args.timeout,
                collection_only_diagnostic=args.collection_only_diagnostic,
            )
        else:
            if not args.target:
                raise DeviceEngineError(
                    "WINRM_TARGET_REQUIRED", "WinRM collection requires --target."
                )
            envelope = collect_windows_winrm(
                target=args.target,
                secret_provider=EnvironmentWinRMSecretProvider(),
                org_id=args.org_id,
                asset_id=args.asset_id,
                model=args.model,
                timeout_seconds=args.timeout,
            )
    _write_json(envelope.model_dump(mode="json"))
    return 0


def _linux_command(args: argparse.Namespace) -> int:
    if args.command == "linux-probe":
        _write_json(probe_linux_fixture(Path(args.fixture)))
        return 0
    if args.transport == "offline":
        if not args.fixture:
            raise DeviceEngineError(
                "FIXTURE_REQUIRED", "Offline Linux collection requires --fixture."
            )
        envelope = collect_linux_fixture(Path(args.fixture))
    else:
        if args.org_id is None or args.asset_id is None:
            raise DeviceEngineError(
                "IDENTIFIERS_REQUIRED", "Local and SSH collection require --org-id and --asset-id."
            )
        if args.transport == "local":
            envelope = collect_linux_local(
                org_id=args.org_id,
                asset_id=args.asset_id,
                model=args.model,
                timeout_seconds=args.timeout,
            )
        else:
            if not args.target or not args.known_hosts:
                raise DeviceEngineError(
                    "SSH_PARAMETERS_REQUIRED", "SSH requires --target and --known-hosts."
                )
            envelope = collect_linux_ssh(
                target=args.target,
                port=args.port,
                known_hosts=Path(args.known_hosts),
                secret_provider=EnvironmentSSHSecretProvider(),
                org_id=args.org_id,
                asset_id=args.asset_id,
                model=args.model,
                timeout_seconds=args.timeout,
            )
    _write_json(envelope.model_dump(mode="json"))
    return 0


def _scap_command(args: argparse.Namespace) -> int:
    if args.command == "scap-ingest":
        result = ingest_xccdf_results(Path(args.input), synthetic=args.synthetic)
    else:
        result = run_local_openscap(
            content_path=Path(args.content),
            profile_id=args.profile,
            output_path=Path(args.output),
            expected_platform=args.platform,
            timeout_seconds=args.timeout,
        )
    _write_json(result.model_dump(mode="json"))
    return 0


def _firewall_command(args: argparse.Namespace) -> int:
    manifest = Path(args.fixture)
    if args.command == "firewall-probe":
        _write_json(probe_firewall_fixture(manifest))
    else:
        if args.transport != "offline":
            raise DeviceEngineError(
                "LIVE_FIREWALL_TRANSPORT_UNAVAILABLE",
                "CLI live firewall collection is unavailable; ASA SSH is an SDK boundary.",
            )
        envelope = collect_firewall_fixture(manifest, max_bytes=args.max_bytes)
        _write_json(envelope.model_dump(mode="json"))
    return 0


def _remaining_command(args: argparse.Namespace) -> int:
    manifest = Path(args.fixture)
    if args.command == "device-probe":
        _write_json(probe_remaining_fixture(manifest))
    else:
        if args.transport != "offline":
            raise DeviceEngineError(
                "LIVE_DEVICE_TRANSPORT_UNAVAILABLE",
                "Phase 5 live transport is unsupported; no fixture was substituted.",
            )
        envelope = collect_remaining_fixture(manifest, max_bytes=args.max_bytes)
        _write_json(envelope.model_dump(mode="json"))
    return 0


def _remediation_catalog_command() -> int:
    _write_json(
        {
            "status": "PREPARATION_ONLY",
            "templates": [item.model_dump(mode="json") for item in list_remediation_templates()],
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cisguard-device")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("capabilities", help="List required families and honest support state")
    subparsers.add_parser("self-test", help="Serialize a synthetic FactsEnvelope fixture")
    for command in ("probe", "collect"):
        fixture_parser = subparsers.add_parser(
            command, help=f"{command.title()} an explicit offline synthetic fixture"
        )
        fixture_parser.add_argument(
            "--fixture", required=True, help="Path to fixture manifest JSON"
        )
        fixture_parser.add_argument("--platform", help="Explicit platform; mismatch is rejected")
        if command == "collect":
            fixture_parser.add_argument(
                "--max-bytes", type=int, help="Override the default 1 MiB fixture input limit"
            )
    for command in ("candidates", "execute", "verify"):
        subparsers.add_parser(command, help="Typed boundary; unavailable in Phase 1")
    simulate_parser = subparsers.add_parser(
        "simulate", help="Evaluate explicit offline simulation JSON with a chosen backend"
    )
    simulate_parser.add_argument("--input", required=True, help="Simulation input JSON")
    simulate_parser.add_argument("--backend", required=True, choices=("custom", "batfish"))
    simulate_parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    compare_parser = subparsers.add_parser(
        "offline-compare", help="Compare two explicit offline envelopes"
    )
    compare_parser.add_argument("--before", required=True)
    compare_parser.add_argument("--after", required=True)
    compare_parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    offline_import = subparsers.add_parser(
        "offline-import",
        aliases=["network-import"],
        help="Import an explicitly identified offline device capture",
    )
    offline_import.add_argument("--input", "--file", dest="input", required=True)
    offline_import.add_argument("--source-type", required=True)
    offline_import.add_argument("--platform", required=True)
    offline_import.add_argument("--org-id", required=True, type=UUID)
    offline_import.add_argument("--asset-id", required=True, type=UUID)
    offline_import.add_argument("--capture-timestamp")
    offline_import.add_argument(
        "--provenance",
        choices=tuple(item.value for item in EvidenceProvenance),
        default=EvidenceProvenance.USER_SUPPLIED_CAPTURE.value,
    )
    offline_import.add_argument(
        "--completeness", choices=("complete", "partial", "unknown"), required=True
    )
    offline_import.add_argument("--operational", "--operational-file", dest="operational")
    offline_import.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    evaluate_parser = subparsers.add_parser(
        "evaluate_device",
        aliases=["network-evaluate"],
        help="Evaluate supported predicates using explicit policy JSON",
    )
    evaluate_parser.add_argument("--envelope")
    evaluate_parser.add_argument("--fixture")
    evaluate_parser.add_argument("--platform")
    evaluate_parser.add_argument("--policy")
    evaluate_parser.add_argument("--policy-json")
    evaluate_parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    windows_probe = subparsers.add_parser(
        "windows-probe", help="Probe an explicit offline synthetic Windows capture"
    )
    windows_probe.add_argument("--fixture", required=True, help="Path to Windows fixture manifest")
    windows_collect = subparsers.add_parser(
        "windows-collect", help="Explicit offline, local, or authorized WinRM Windows collection"
    )
    windows_collect.add_argument(
        "--transport", required=True, choices=("offline", "local", "winrm")
    )
    windows_collect.add_argument("--fixture", help="Windows fixture manifest for offline transport")
    windows_collect.add_argument("--target", help="Authorized HTTPS WinRM endpoint")
    windows_collect.add_argument("--org-id", type=UUID)
    windows_collect.add_argument("--asset-id", type=UUID)
    windows_collect.add_argument("--model", default="windows-host")
    windows_collect.add_argument("--timeout", type=int, default=120)
    windows_collect.add_argument(
        "--collection-only-diagnostic",
        action="store_true",
        help="Allow Windows 11 Home facts only; benchmark applicability remains unsupported.",
    )
    linux_probe = subparsers.add_parser(
        "linux-probe", help="Probe an explicit offline synthetic Linux capture"
    )
    linux_probe.add_argument("--fixture", required=True)
    linux_collect = subparsers.add_parser(
        "linux-collect", help="Explicit offline, local, or authorized SSH Linux collection"
    )
    linux_collect.add_argument("--transport", required=True, choices=("offline", "local", "ssh"))
    linux_collect.add_argument("--fixture")
    linux_collect.add_argument("--target")
    linux_collect.add_argument("--port", type=int, default=22)
    linux_collect.add_argument("--known-hosts")
    linux_collect.add_argument("--org-id", type=UUID)
    linux_collect.add_argument("--asset-id", type=UUID)
    linux_collect.add_argument("--model", default="linux-host")
    linux_collect.add_argument("--timeout", type=int, default=120)
    scap_ingest = subparsers.add_parser("scap-ingest", help="Safely ingest XCCDF result XML")
    scap_ingest.add_argument("--input", required=True)
    scap_ingest.add_argument("--synthetic", action="store_true")
    scap_run = subparsers.add_parser("scap-run", help="Explicit local OpenSCAP assessment")
    scap_run.add_argument("--content", required=True)
    scap_run.add_argument("--profile", required=True)
    scap_run.add_argument("--output", required=True)
    scap_run.add_argument(
        "--platform",
        required=True,
        choices=("ubuntu_20_04_lts", "ubuntu_22_04_lts", "rhel_8", "rhel_9"),
    )
    scap_run.add_argument("--timeout", type=int, default=900)
    firewall_probe = subparsers.add_parser(
        "firewall-probe", help="Probe a synthetic firewall capture"
    )
    firewall_probe.add_argument("--fixture", required=True)
    firewall_collect = subparsers.add_parser(
        "firewall-collect", help="Explicit firewall replay or authorized live collection"
    )
    firewall_collect.add_argument("--transport", required=True, choices=("offline", "live"))
    firewall_collect.add_argument("--fixture", required=True)
    firewall_collect.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    device_probe = subparsers.add_parser("device-probe", help="Probe a Phase-5 fixture")
    device_probe.add_argument("--fixture", required=True)
    device_collect = subparsers.add_parser("device-collect", help="Replay a Phase-5 fixture")
    device_collect.add_argument("--transport", required=True, choices=("offline", "live"))
    device_collect.add_argument("--fixture", required=True)
    device_collect.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    subparsers.add_parser("remediation-catalog", help="List fixture-tested no-write templates")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            return capabilities()
        if args.command == "self-test":
            return self_test()
        if args.command in {"offline-import", "network-import"}:
            return _offline_import_command(args)
        if args.command in {"evaluate_device", "network-evaluate"}:
            return _evaluate_device_command(args)
        if args.command in {"probe", "collect"}:
            return _fixture_command(args)
        if args.command in {"windows-probe", "windows-collect"}:
            return _windows_command(args)
        if args.command in {"linux-probe", "linux-collect"}:
            return _linux_command(args)
        if args.command in {"scap-ingest", "scap-run"}:
            return _scap_command(args)
        if args.command in {"firewall-probe", "firewall-collect"}:
            return _firewall_command(args)
        if args.command in {"device-probe", "device-collect"}:
            return _remaining_command(args)
        if args.command == "remediation-catalog":
            return _remediation_catalog_command()
        if args.command == "simulate":
            return _simulate_command(args)
        if args.command == "offline-compare":
            return _compare_command(args)
        if args.command in {"candidates", "execute", "verify"}:
            return _unsupported_result(args.command)
    except DeviceEngineError as exc:
        request_id = uuid5(_CLI_REQUEST_NAMESPACE, f"{args.command}:{exc.code}")
        _write_json(
            {
                "schema_version": "1.0.0",
                "status": "ERROR",
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "request_id": str(request_id),
                    "details": exc.details,
                    "retryable": exc.retryable,
                },
            }
        )
        print(f"cisguard-device: {exc.code}: {exc.message}", file=sys.stderr)
        return 2
    except ValidationError as exc:
        request_id = uuid5(_CLI_REQUEST_NAMESPACE, f"{args.command}:VALIDATION_ERROR")
        _write_json(
            {
                "schema_version": "1.0.0",
                "status": "ERROR",
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Input metadata or policy failed validation.",
                    "request_id": str(request_id),
                    "details": {"error_count": exc.error_count()},
                    "retryable": False,
                },
            }
        )
        print("cisguard-device: VALIDATION_ERROR", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - last-resort CLI boundary
        print(f"cisguard-device: unexpected error: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 2
