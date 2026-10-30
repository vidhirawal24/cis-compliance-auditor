"""Synthetic contract fixtures only. Never use as device/compliance evidence."""
import json
from pathlib import Path
from uuid import UUID

import models as m

HERE = Path(__file__).resolve().parent


def fixture_values():
    uid = lambda n: str(UUID(int=n))
    now = "2026-10-29T00:00:00Z"
    scope = {"schema_version": "1.0.0", "org_id": uid(1)}
    ref = {"evidence_id": uid(4), "sha256": "0" * 64, "source_identity": "synthetic-fixture/management-v1",
           "encrypted_artifact_location": f"private://audit-evidence/{uid(1)}/{uid(4)}", "collected_at": now}
    fact = {"path": "management.telnet_enabled", "value": True, "evidence_ids": [uid(4)], "observed_at": now}
    error = {"code": "UNSUPPORTED", "message": "Synthetic offline fixture; no device implementation", "retryable": False}
    command = {**scope, "job_id":uid(2), "scan_id":uid(3), "asset_id":uid(5), "request_id":uid(6),
               "authorization_scope_id":uid(7), "credential_reference_id":None, "expected_platform":"synthetic_lab",
               "expected_device_version":"fixture-only", "requested_capabilities":["management_telnet"],
               "read_only":True, "deadline_at":"2026-10-29T00:05:00Z", "idempotency_key":uid(8)}
    evidence = {**scope, "asset_id":uid(5), "platform":"synthetic_lab", "vendor":"Synthetic", "model":"fixture-only",
                "os_or_firmware_version":"fixture-only", "collector_version":"fixture-1", "collection_method":"offline_fixture",
                "collected_at":now, "facts":{"management":[fact]}, "evidence_refs":[ref],
                "supported_capabilities":["management_telnet"], "unsupported_capabilities":[], "errors":[]}
    score = {"pass_count":3, "fail_count":1, "not_applicable_count":1, "manual_review_count":1,
             "error_count":1, "not_assessed_count":2, "assessed_compliance_pct":75.0, "assessment_coverage_pct":50.0}
    action = {"action_id":uid(9), "asset_id":uid(5), "template_id":uid(10), "template_version":"fixture-1",
              "expected_device_version":"fixture-only", "baseline_sha256":"0"*64,
              "validated_parameters_ref":uid(11), "depends_on":[], "recovery":"ROLLBACK"}
    values = {
        "CollectionCommand": command,
        "CollectionResult": {**scope, "job_id":uid(2), "scan_id":uid(3), "asset_id":uid(5), "status":"UNSUPPORTED", "evidence":None,"errors":[error]},
        "NormalizedEvidence": evidence,
        "Scan": {**scope, **score, "scan_id":uid(3), "status":"RUNNING", "requested_assets":3, "completed_assets":1, "created_at":now},
        "Score": score,
        "Finding": {**scope, "finding_id":uid(12), "scan_id":uid(3), "asset_id":uid(5), "device_version":"fixture-only",
                    "control_id":"synthetic-management-001", "policy_pack_id":uid(13), "policy_version":"fixture-1", "benchmark_release":"organizational-fixture",
                    "profile":"synthetic", "applicability":"APPLICABLE", "status":"FAIL", "severity":"HIGH", "expected":False,
                    "observed":True, "rule_inputs":[fact], "evidence_refs":[ref], "evaluator_version":"fixture-1", "evaluated_at":now,
                    "remediation_template_id":None, "limitations":["Synthetic offline wire example; not a real audit"]},
        "Plan": {**scope, "plan_id":uid(14), "plan_sha256":"1"*64, "outcome":"UNSAT", "actions":[],
                 "violated_constraints":["Synthetic: no vetted candidate preserves mandatory service"], "safety_contract_ids":[uid(15)], "created_by":uid(16), "created_at":now},
        "Simulation": {**scope, "simulation_id":uid(17), "plan_id":uid(14), "plan_sha256":"1"*64, "verdict":"UNSUPPORTED",
                       "checked_contract_ids":[], "unsupported_capabilities":["synthetic_semantics"], "evidence_ids":[],
                       "limitations":["Synthetic fixture: no model executed"], "model_version":"fixture-only", "simulated_at":now},
        "SimulationCommand": {**scope, "job_id":uid(2), "request_id":uid(6), "plan_id":uid(14), "plan_sha256":"1"*64,
                              "baseline_evidence_ids":[uid(4)], "safety_contract_ids":[uid(15)], "deadline_at":now},
        "ExecutionCommand": {**scope, "job_id":uid(2), "request_id":uid(6), "change_id":uid(18), "plan_id":uid(14), "plan_sha256":"1"*64,
                             "approval_id":uid(19), "operator_id":uid(16), "approver_id":uid(20), "plan_author_id":uid(16), "authorization_grant_id":uid(21),
                             "precheck_id":uid(22), "backup_evidence_ids":[uid(4)], "safety_contract_ids":[uid(15)],
                             "actions":[action], "expires_at":now, "idempotency_key":uid(8)},
        "ExecutionResult": {**scope,"job_id":uid(2),"change_id":uid(18),"state":"FAILED","evidence_refs":[],"errors":[error],"completed_action_ids":[]},
        "VerificationCommand": {**scope,"job_id":uid(2),"change_id":uid(18),"scan_id":uid(3),"asset_ids":[uid(5)],
                                "control_ids":["synthetic-management-001"],"safety_contract_ids":[uid(15)],"deadline_at":now},
        "Verification": {**scope, "verification_id":uid(23),"change_id":uid(18),"post_scan_id":uid(24),"control_statuses":["NOT_ASSESSED"],
                         "service_checks":[{"safety_contract_id":uid(15),"status":"NOT_ASSESSED","evidence_refs":[]}],
                         "status":"NOT_FULLY_VERIFIED","verified_at":now,"evidence_refs":[]},
        "APIError": {"code":"FORBIDDEN","message":"Operation not permitted in selected organization","request_id":uid(6),"retryable":False},
    }
    return values


def outputs():
    return {f"{name}.json": getattr(m, name).model_validate(data).model_dump(mode="json") for name,data in fixture_values().items()}


if __name__ == "__main__":
    (HERE / "examples").mkdir(exist_ok=True)
    for filename, content in outputs().items():
        (HERE / "examples" / filename).write_text(json.dumps(content,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("Wrote synthetic wire examples (no live results)")
