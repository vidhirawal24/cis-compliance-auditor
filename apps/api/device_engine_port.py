"""Mandar-owned typed boundary. No imports from Vidhi's device implementation."""
from typing import Protocol

from models import (CollectionCommand, CollectionResult, CollectorError,
                    ExecutionCommand, ExecutionResult, VerificationCommand, Verification,
                    SimulationCommand, Simulation)


class DeviceEnginePort(Protocol):
    async def collect(self, command: CollectionCommand) -> CollectionResult: ...
    async def execute(self, command: ExecutionCommand) -> ExecutionResult: ...
    async def verify(self, command: VerificationCommand) -> Verification: ...
    async def simulate(self, command: SimulationCommand) -> Simulation: ...


def validate_collection_result(command: CollectionCommand, result: CollectionResult) -> CollectionResult:
    """Reject even well-shaped worker replies that do not match the dispatch."""
    for field in ("org_id", "job_id", "scan_id", "asset_id"):
        if getattr(command, field) != getattr(result, field):
            raise ValueError(f"Worker result {field} does not match dispatched command")
    return result


class MockDeviceEngine:
    """Development double: no I/O and no fabricated evidence or success."""

    async def collect(self, command: CollectionCommand) -> CollectionResult:
        return CollectionResult(
            schema_version="1.0.0",
            org_id=command.org_id, job_id=command.job_id, scan_id=command.scan_id,
            asset_id=command.asset_id, status="UNSUPPORTED", evidence=None,
            errors=[CollectorError(code="UNSUPPORTED", message="Development port has no collector",
                                   retryable=False)],
        )

    async def execute(self, command: ExecutionCommand) -> ExecutionResult:
        raise NotImplementedError("Development port cannot execute device changes")

    async def verify(self, command: VerificationCommand) -> Verification:
        raise NotImplementedError("Development port cannot verify live devices")

    async def simulate(self, command: SimulationCommand) -> Simulation:
        raise NotImplementedError("Development port has no supported simulation model")
