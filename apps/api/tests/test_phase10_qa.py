"""Independent release regressions: real assertions, no success-only placeholders."""
import io
import json
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from hypothesis import given, settings, strategies as st
from pypdf import PdfReader

from cisguard_api.device_port import DevicePortError, collect_device_facts, get_asset_capabilities
from cisguard_api.policy_engine import calculate_scan_score
from cisguard_api.plan_optimizer import VettedCandidate, PlanConstraints, optimize_plan, compute_plan_sha256
from cisguard_api.change_routes import advance_change, create_simulation
from cisguard_api.security import Identity
from cisguard_api.settings import get_settings


@given(st.lists(st.sampled_from(['PASS','FAIL','ERROR','NOT_ASSESSED','NOT_APPLICABLE','MANUAL_REVIEW']),max_size=200))
@settings(max_examples=100,deadline=None)
def test_M35_score_property(statuses):
    score=calculate_scan_score(statuses)
    assessed=statuses.count('PASS')+statuses.count('FAIL')
    eligible=len(statuses)-statuses.count('NOT_APPLICABLE')
    assert score.assessed_compliance_pct == (round(100*statuses.count('PASS')/assessed,4) if assessed else None)
    assert score.assessment_coverage_pct == (round(100*assessed/eligible,4) if eligible else None)
    assert calculate_scan_score(list(reversed(statuses)))==score


def test_E18_I20_runtime_cannot_fabricate_device_evidence(monkeypatch):
    monkeypatch.setattr(get_settings(),'environment','development')
    monkeypatch.setattr(get_settings(),'enable_synthetic_fixtures',True)
    asset=SimpleNamespace(id=uuid4(),org_id=uuid4(),target='10.0.0.1',family='linux',tags=[])
    with pytest.raises(DevicePortError,match='not connected'):
        collect_device_facts(asset)
    capabilities=get_asset_capabilities(asset.id,'linux','Ubuntu','Canonical')
    assert capabilities.supported==[] and capabilities.compatibility_status=='UNTESTED'


def candidate(**updates):
    fields=dict(template_id=uuid4(),template_version='test-only',asset_id=uuid4(),targets_control_ids=['test-1'],
                platform_family='linux',expected_device_version='fixture',baseline_sha256='a'*64,
                validated_parameters_ref=uuid4(),recovery='ROLLBACK',change_cost=1,blast_radius=1)
    return VettedCandidate(**(fields|updates))


def test_I06_I10_optimizer_stable_ids_and_dependency_constraints():
    constraints=PlanConstraints([uuid4()],[uuid4()],100)
    c=candidate()
    first=optimize_plan([c],{'test-1'},constraints)
    second=optimize_plan([c],{'test-1'},constraints)
    assert first.outcome=='FEASIBLE'
    assert compute_plan_sha256(first.selected_actions,constraints.safety_contract_ids)==compute_plan_sha256(second.selected_actions,constraints.safety_contract_ids)
    missing=candidate(depends_on_template_ids=[uuid4()])
    assert optimize_plan([missing],{'test-1'},constraints).outcome=='UNSAT'
    a,b=uuid4(),uuid4()
    cycle=[candidate(template_id=a,depends_on_template_ids=[b]),candidate(template_id=b,depends_on_template_ids=[a])]
    assert optimize_plan(cycle,{'test-1'},constraints).outcome=='UNSAT'


@pytest.mark.parametrize('state,target',[('APPROVED','EXECUTING'),('VERIFYING','VERIFIED'),('EXECUTING','ROLLED_BACK')])
def test_E23_I14_browser_cannot_assert_worker_success(state,target):
    who=Identity(uuid4(),'aal2',9999999999,None)
    db=MagicMock(); db.scalar.return_value=SimpleNamespace(state=state)
    with patch('cisguard_api.change_routes.identity',return_value=who),patch('cisguard_api.change_routes.member'),patch('cisguard_api.change_routes.tenant_session') as session:
        session.return_value.__enter__.return_value=db
        with pytest.raises(HTTPException) as failure:
            advance_change(uuid4(),{'target_state':target},MagicMock(),uuid4())
        assert failure.value.status_code==403
        assert db.scalar.return_value.state==state


def test_I11_missing_simulator_is_never_safe():
    who=Identity(uuid4(),'aal2',9999999999,None)
    plan=SimpleNamespace(plan_sha256='a'*64,outcome='FEASIBLE')
    db=MagicMock(); db.scalar.return_value=plan; db.scalars.return_value.all.return_value=[]
    with patch('cisguard_api.change_routes.identity',return_value=who),patch('cisguard_api.change_routes.member'),patch('cisguard_api.change_routes.audit'),patch('cisguard_api.change_routes.tenant_session') as session:
        session.return_value.__enter__.return_value=db
        response=create_simulation({'plan_id':str(uuid4()),'plan_sha256':'a'*64},SimpleNamespace(state=SimpleNamespace(request_id=str(uuid4()))),uuid4())
    assert response['data']['verdict']=='UNSUPPORTED'
    assert response['data']['checked_contract_ids']==[]


def test_E30_no_duplicate_http_operations():
    from cisguard_api.main import app
    pairs=[(route.path,method) for route in app.routes for method in getattr(route,'methods',[]) if route.path.startswith('/api/v1')]
    assert len(pairs)==len(set(pairs))


def test_M38_pdf_contains_real_rendered_counts():
    # Existing format tests only checked PDF magic bytes. Read the actual rendered text here.
    from test_phase5_reports import sample_report_data
    from cisguard_api.report_service import export_pdf,export_html,export_json,export_csv
    import csv
    payload=sample_report_data.__wrapped__()
    pdf=export_pdf(payload,export_html(payload))
    content=' '.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
    assert str(payload['score']['assessed_compliance_pct']) in content
    assert str(payload['score']['assessment_coverage_pct']) in content
    rows=list(csv.DictReader(io.StringIO(export_csv(payload))))
    data=json.loads(export_json(payload))
    for status in ['PASS','FAIL','NOT_APPLICABLE','MANUAL_REVIEW','ERROR','NOT_ASSESSED']:
        assert sum(row['status']==status for row in rows)==sum(row['status']==status for row in data['findings'])
    for finding in payload['findings']:
        assert finding['control_id'] in content
