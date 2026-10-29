from datetime import UTC, datetime, timedelta
from uuid import UUID

from cisguard_device.models import EvidenceReference, FactsEnvelope
from cisguard_device.verification import (
    TrustedOutcomes,
    VerificationRequest,
    VerificationStatus,
    compare_normalized_facts,
    drift_events,
    phase9_verifier_adapter,
    verify_post_fix,
)


def _env(*, when, facts, method="synthetic_fixture", errors=None):
    errors = errors or []
    return FactsEnvelope(
        org_id=UUID("11111111-1111-4111-8111-111111111111"),
        asset_id=UUID("22222222-2222-4222-8222-222222222222"),
        platform="cisco_router",
        vendor="Cisco",
        model="m",
        os_or_firmware_version="17",
        collector_version="t",
        collection_method=method,
        collected_at=when,
        facts=facts,
        evidence_refs=[
            EvidenceReference(
                sha256="a" * 64,
                source_identity="x",
                artifact_location="fixture://x",
                timestamp=when,
            )
        ],
        errors=errors,
    )


class Provider:
    def __init__(self, env):
        self.env = env

    def collect(self, request):
        return self.env


class Outcomes:
    def __init__(self, request, fresh, controls, services):
        self.value = TrustedOutcomes(
            org_id=request.org_id,
            asset_id=request.asset_id,
            change_id=request.change_id,
            evidence_hashes=[ref.sha256 for ref in fresh.evidence_refs],
            control_outcomes=controls,
            service_outcomes=services,
            observed_at=fresh.collected_at,
            vantage="synthetic-worker",
            provenance="synthetic_fixture",
        )

    def evaluate(self, request, fresh):
        return self.value


def test_independent_verification_separates_control_and_service():
    now = datetime.now(UTC)
    base = _env(when=now - timedelta(minutes=1), facts={"x": True})
    req = VerificationRequest(
        org_id=str(base.org_id),
        asset_id=str(base.asset_id),
        change_id="c",
        candidate_hash="a" * 64,
        template_id="t",
        template_version="1",
        policy_version="p",
        baseline=base,
        required_check_ids=["M"],
        service_contract_ids=["S"],
    )
    fresh = _env(when=now, facts={"x": False})
    result = verify_post_fix(
        req,
        Provider(fresh),
        outcome_provider=Outcomes(
            req, fresh, {"M": VerificationStatus.PASS}, {"S": VerificationStatus.PASS}
        ),
    )
    assert (
        result.status == VerificationStatus.PASS and result.fresh_provenance == "synthetic_fixture"
    )
    assert (
        verify_post_fix(
            req,
            Provider(fresh),
            outcome_provider=Outcomes(
                req, fresh, {"M": VerificationStatus.FAIL}, {"S": VerificationStatus.PASS}
            ),
        ).config_control_status
        == VerificationStatus.FAIL
    )
    assert (
        verify_post_fix(
            req,
            Provider(fresh),
            outcome_provider=Outcomes(req, fresh, {"M": VerificationStatus.PASS}, {}),
        ).service_contract_status
        == VerificationStatus.UNKNOWN
    )


def test_raw_pass_cannot_establish_trusted_success():
    now = datetime.now(UTC)
    base = _env(when=now - timedelta(minutes=1), facts={})
    request = VerificationRequest(
        org_id=str(base.org_id),
        asset_id=str(base.asset_id),
        change_id="c",
        candidate_hash="a" * 64,
        template_id="t",
        template_version="1",
        policy_version="p",
        baseline=base,
        required_check_ids=["M"],
        service_contract_ids=["S"],
    )
    fresh = _env(when=now, facts={})
    assert (
        verify_post_fix(
            request, Provider(fresh), {"M": VerificationStatus.PASS}, {"S": VerificationStatus.PASS}
        ).status
        == VerificationStatus.UNKNOWN
    )


def test_synthetic_pass_never_authorizes_phase9_gate():
    now = datetime.now(UTC)
    base = _env(when=now - timedelta(minutes=1), facts={})
    request = VerificationRequest(
        org_id=str(base.org_id),
        asset_id=str(base.asset_id),
        change_id="c",
        candidate_hash="a" * 64,
        template_id="t",
        template_version="1",
        policy_version="p",
        baseline=base,
        required_check_ids=["M"],
        service_contract_ids=["S"],
    )
    fresh = _env(when=now, facts={})
    result = verify_post_fix(
        request,
        Provider(fresh),
        outcome_provider=Outcomes(
            request, fresh, {"M": VerificationStatus.PASS}, {"S": VerificationStatus.PASS}
        ),
    )
    assert result.status == VerificationStatus.PASS
    assert phase9_verifier_adapter(result).allowed is False


def test_drift_is_deterministic_and_partial_missing_is_not_removed():
    now = datetime.now(UTC)
    base = _env(
        when=now - timedelta(minutes=1), facts={"acl": ["deny", "permit"], "password": "secret"}
    )
    current = _env(when=now, facts={"acl": ["permit", "deny"], "password": "new secret"})
    diff = compare_normalized_facts(base, current)
    assert [item.path for item in diff] == sorted(item.path for item in diff)
    assert next(item for item in diff if item.path == "facts.password").after == "[REDACTED]"
    assert drift_events(base, current)[0].provenance == "synthetic_fixture"
