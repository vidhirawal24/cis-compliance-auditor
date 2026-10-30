"""Phase 0 contract tests; feature tags identify intent, not completed product tests."""
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate
from pydantic import ValidationError

import models as m
from build_examples import fixture_values, outputs
from device_engine_port import MockDeviceEngine, validate_collection_result
from generate import generate_outputs
from route_catalog import ROUTES

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "packages/contracts/v1"
REGISTER = json.loads((ROOT / "docs/core/feature-register.json").read_text(encoding="utf-8"))
FIXTURES = fixture_values()


def test_M01_M38_E01_E30_I01_I20_exact_scope():
    expected = {f"{p}{n:02}" for p,limit in [("M",38),("E",30),("I",20)] for n in range(1,limit+1)}
    assert len(REGISTER) == 88
    assert {r["id"] for r in REGISTER} == expected


@pytest.mark.parametrize("row", REGISTER, ids=lambda r:r["id"])
def test_feature_register(row):
    assert row["requirement"] and row["acceptance_evidence"] and 6 <= row["prd_page"] <= 9
    assert row["accountable"] in row["responsible"]
    assert set(row["responsible"] + row["consulted"] + row["informed"]) == {"Mandar","Apoorva","Vidhi"}
    assert row["status"] == "UNTESTED" and row["evidence"] == []
    assert row["acceptance_test_id"] == "AC-" + row["id"]


def test_E30_openapi_and_generated_files():
    for filename, content in generate_outputs().items():
        assert (CONTRACT / filename).read_text(encoding="utf-8") == content, filename
    document = yaml.safe_load((CONTRACT / "openapi.yaml").read_text(encoding="utf-8"))
    validate(document)
    assert document["servers"] == [{"url":"/api/v1"}]
    assert document["security"] == [{"SupabaseBearer":[]}]
    operation_ids = []
    allowed_permissions = {p for permissions in json.loads((CONTRACT / "permissions.json").read_text())["roles"].values() for p in permissions}
    feature_ids = {r["id"] for r in REGISTER}
    for path, methods in document["paths"].items():
        for method, op in methods.items():
            operation_ids.append(op["operationId"])
            assert op["x-permission"] in allowed_permissions
            assert set(op["x-feature-ids"]) <= feature_ids
            assert any(p["name"] == "X-Org-ID" and p["required"] for p in op["parameters"])
            if method != "get":
                assert any(p["name"] == "Idempotency-Key" and p["required"] for p in op["parameters"])
            assert "security" not in op or op["security"]
            assert {"401","403","404","409","422","429","503"} <= set(op["responses"])
            if "requestBody" in op:
                ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                assert not ref.endswith("Command"), "Public endpoints cannot accept internal worker commands"
    assert len(operation_ids) == len(set(operation_ids)) == len(ROUTES)


@pytest.mark.parametrize("schema_path", sorted((CONTRACT / "json-schemas").glob("*.json")), ids=lambda p:p.stem)
def test_M17_E30_valid_json_schema(schema_path):
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("name", list(FIXTURES), ids=list(FIXTURES))
def test_E30_synthetic_examples_validate_in_both_consumers(name):
    payload = json.loads((CONTRACT / "examples" / (name+".json")).read_text())
    schema = json.loads((CONTRACT / "json-schemas" / (name+".schema.json")).read_text())
    Draft202012Validator(schema,format_checker=FormatChecker()).validate(payload)
    assert getattr(m,name).model_validate_json(json.dumps(payload)).model_dump(mode="json") == payload
    assert outputs()[name+".json"] == payload


@pytest.mark.parametrize("status", ["ERROR", "NOT_ASSESSED", "MANUAL_REVIEW", "NOT_APPLICABLE", "EXCEPTION"])
def test_M35_E14_non_assessed_never_boosts_score(status):
    data = {"pass_count":0,"fail_count":0,"not_applicable_count":0,"manual_review_count":0,"error_count":0,"not_assessed_count":0,
            "assessed_compliance_pct":None,"assessment_coverage_pct":None}
    field = {"ERROR":"error_count","NOT_ASSESSED":"not_assessed_count","MANUAL_REVIEW":"manual_review_count","NOT_APPLICABLE":"not_applicable_count"}.get(status)
    if field:
        data[field] = 1
        data["assessment_coverage_pct"] = None if status == "NOT_APPLICABLE" else 0
    valid = m.Score(**data)
    assert valid.assessed_compliance_pct is None
    with pytest.raises(ValidationError):
        m.Score(**{**data,"assessed_compliance_pct":100})


def test_M35_scores_reconcile_and_progress_is_bounded():
    with pytest.raises(ValidationError):
        m.Score(**{**FIXTURES["Score"],"assessed_compliance_pct":99})
    with pytest.raises(ValidationError):
        m.Scan(**{**FIXTURES["Scan"],"completed_assets":4})
    with pytest.raises(ValidationError):
        m.Score(**{**FIXTURES["Score"],"pass_count":-1})


@pytest.mark.parametrize("status", ["PASS","FAIL"])
def test_M36_I20_assessed_finding_requires_evidence(status):
    data = deepcopy(FIXTURES["Finding"])
    data.update(status=status, evidence_refs=[])
    with pytest.raises(ValidationError):
        m.Finding(**data)


def test_E14_exception_is_not_a_status():
    with pytest.raises(ValidationError):
        m.Finding(**{**FIXTURES["Finding"],"status":"EXCEPTION"})
    assert len(m.AssessmentStatus) == 6


def test_M12_M14_evidence_requires_matching_provenance():
    data = deepcopy(FIXTURES["NormalizedEvidence"])
    data["evidence_refs"] = []
    with pytest.raises(ValidationError):
        m.NormalizedEvidence(**data)
    data = deepcopy(FIXTURES["NormalizedEvidence"])
    data["unsupported_capabilities"] = data["supported_capabilities"]
    with pytest.raises(ValidationError):
        m.NormalizedEvidence(**data)


@pytest.mark.parametrize("field,value", [("asset_id","not-uuid"),("schema_version","2.0.0"),("read_only",False),("command","configure terminal"),("password","synthetic-secret")])
def test_E17_E18_E30_reject_unsafe_or_invalid_job(field,value):
    with pytest.raises(ValidationError):
        m.CollectionCommand(**{**FIXTURES["CollectionCommand"],field:value})


@pytest.mark.parametrize("timestamp", ["2026-10-29T00:00:00+05:30","2026-10-29T00:00:00","2026-02-31T00:00:00Z"])
def test_E19_utc_real_calendar_timestamp(timestamp):
    with pytest.raises(ValidationError):
        m.CollectionCommand(**{**FIXTURES["CollectionCommand"],"deadline_at":timestamp})


@pytest.mark.parametrize("field", ["org_id","job_id","scan_id","asset_id"])
def test_E09_E15_worker_correlation(field):
    command = m.CollectionCommand(**FIXTURES["CollectionCommand"])
    result = m.CollectionResult(**{**FIXTURES["CollectionResult"],field:"ffffffff-ffff-4fff-8fff-ffffffffffff"})
    with pytest.raises(ValueError):
        validate_collection_result(command,result)


def test_M12_E15_cross_tenant_collected_evidence_rejected():
    evidence = deepcopy(FIXTURES["NormalizedEvidence"])
    evidence["org_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    with pytest.raises(ValidationError):
        m.CollectionResult(**{**FIXTURES["CollectionResult"],"status":"COLLECTED","errors":[],"evidence":evidence})


def test_E23_I14_self_approval_rejected():
    data = deepcopy(FIXTURES["ExecutionCommand"])
    data["approver_id"] = data["operator_id"]
    with pytest.raises(ValidationError):
        m.ExecutionCommand(**data)


def test_E23_I14_plan_author_cannot_approve():
    data = deepcopy(FIXTURES["ExecutionCommand"])
    data["plan_author_id"] = data["approver_id"]
    with pytest.raises(ValidationError):
        m.ExecutionCommand(**data)


@pytest.mark.parametrize("name", ["CollectionCommand","CollectionResult","ExecutionCommand","VerificationCommand","SimulationCommand"])
def test_E30_worker_version_is_explicit(name):
    data = deepcopy(FIXTURES[name])
    del data["schema_version"]
    with pytest.raises(ValidationError):
        getattr(m,name)(**data)


def test_I06_unsat_has_no_actions_and_explains_constraints():
    with pytest.raises(ValidationError):
        m.Plan(**{**FIXTURES["Plan"],"actions":FIXTURES["ExecutionCommand"]["actions"]})
    with pytest.raises(ValidationError):
        m.Plan(**{**FIXTURES["Plan"],"violated_constraints":[]})


def test_I16_unknown_checks_cannot_be_verified():
    data = deepcopy(FIXTURES["Verification"])
    data["status"] = "VERIFIED"
    with pytest.raises(ValidationError):
        m.Verification(**data)
    data.update(control_statuses=["PASS"], evidence_refs=FIXTURES["NormalizedEvidence"]["evidence_refs"])
    with pytest.raises(ValidationError):
        m.Verification(**data)
    data["service_checks"][0].update(status="PASS",evidence_refs=data["evidence_refs"])
    assert m.Verification(**data).status == "VERIFIED"
    with pytest.raises(ValidationError):
        m.ExecutionResult(**{**FIXTURES["ExecutionResult"],"state":"VERIFIED"})


def test_E18_mock_does_not_fake_success_or_mutate():
    port = MockDeviceEngine()
    command = m.CollectionCommand(**FIXTURES["CollectionCommand"])
    result = asyncio.run(port.collect(command))
    assert result.status == "UNSUPPORTED" and result.evidence is None and result.errors
    validate_collection_result(command,result)
    for method, model, fixture in [(port.execute,m.ExecutionCommand,"ExecutionCommand"),
                                   (port.verify,m.VerificationCommand,"VerificationCommand"),
                                   (port.simulate,m.SimulationCommand,"SimulationCommand")]:
        with pytest.raises(NotImplementedError):
            asyncio.run(method(model(**FIXTURES[fixture])))


def test_E15_E16_role_separation():
    permissions = json.loads((CONTRACT / "permissions.json").read_text())
    roles = permissions["roles"]
    assert set(roles) == {r.value for r in m.Role}
    assert "change.execute" not in roles["approver"]
    assert "change.approve" not in roles["operator"]
    assert "audit.read" not in roles["executive"]
    assert "change.execute" not in roles["owner"]
    assert {"operator","approver","owner","security_admin"} <= set(permissions["mfa_roles"])


def test_E30_frozen_snapshot_digest():
    record = json.loads((CONTRACT / "freeze.json").read_text())
    digest = hashlib.sha256()
    for relative in record["files"]:
        digest.update(relative.encode()+b"\0"+(CONTRACT/relative).read_bytes()+b"\0")
    assert record["sha256"] == digest.hexdigest()
    assert record["status"] == "PROPOSED"
    assert all(review["status"] == "PENDING" for review in record["reviews"].values())
