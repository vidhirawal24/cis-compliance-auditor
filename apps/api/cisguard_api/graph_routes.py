"""NetworkX security graph and risk scenario endpoints (Phase 6).

Covers:
- /graph: NetworkX security graph query with deterministic stable response ordering (I01, I03)
- /risk-scenarios: Deterministic cross-device correlation and explainability chains (I02, I04, I05, E13)
- /risk-scenarios/{scenario_id}: Individual risk scenario query (I05, I17)
- Path traversal and reachability analysis with topology missingness detection (I03, I04)
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select

from cisguard_api.database import tenant_session
from cisguard_api.db_models import (
    Asset,
    AuditResult,
    Finding as DBFinding,
    PolicyRule,
)
from cisguard_api.graph_engine import (
    ReachabilityEvaluator,
    RiskScenarioCorrelator,
    SecurityGraphBuilder,
    deterministic_uuid,
)
from cisguard_api.security_routes import envelope, identity, member

logger = logging.getLogger(__name__)

graph_router = APIRouter(prefix="/api/v1", tags=["security-graph-and-risk"])


class PathQueryRequest(BaseModel):
    source_asset_id: UUID
    target_asset_id: UUID
    target_port: int | None = None


def build_tenant_graph(db, org_id: UUID) -> SecurityGraphBuilder:
    """Helper to populate the SecurityGraphBuilder from tenant assets, findings, and network facts."""
    builder = SecurityGraphBuilder(org_id)

    # 1. Fetch Assets
    assets = db.scalars(
        select(Asset).where(Asset.org_id == org_id, Asset.retired.is_(False))
    ).all()

    default_evidence_id = deterministic_uuid("evidence", f"{org_id}:topology")

    # Keep track of asset nodes and synthetic interface/subnet mapping based on IP
    for a in assets:
        criticality = "MEDIUM"
        if a.tags:
            for t in a.tags:
                if "critical" in str(t).lower():
                    criticality = "CRITICAL"
                elif "high" in str(t).lower():
                    criticality = "HIGH"

        builder.add_asset_node({
            "id": a.id,
            "name": a.name,
            "family": a.family,
            "platform": a.platform,
            "target": a.target,
            "criticality": criticality,
        })

        # Add network interface & subnet based on target IP
        target_ip = a.target.split(":")[0].replace(".timeout", "")
        octets = target_ip.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            subnet_cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            builder.add_interface_and_subnet(
                asset_id=a.id,
                iface_name="eth0",
                ip_addr=target_ip,
                cidr=subnet_cidr,
                evidence_id=default_evidence_id,
            )

            # If firewall/router, add sample policy allowing or denying
            if a.family in ("firewall", "router"):
                builder.add_firewall_rule(
                    firewall_asset_id=a.id,
                    rule_name="allow-internal-mesh",
                    source_cidr=subnet_cidr,
                    dest_cidr=f"{octets[0]}.{octets[1]}.0.0/16",
                    port=None,
                    action="allows",
                    evidence_id=default_evidence_id,
                )

    # 2. Fetch Findings and AuditResults
    findings = db.scalars(
        select(DBFinding).where(DBFinding.org_id == org_id)
    ).all()

    for f in findings:
        r = db.scalar(
            select(AuditResult).where(AuditResult.org_id == org_id, AuditResult.id == f.result_id)
        )
        if r and builder.g.has_node(r.asset_id):
            rule = db.scalar(
                select(PolicyRule).where(PolicyRule.org_id == org_id, PolicyRule.id == r.rule_id)
            )
            rule_def = rule.definition if rule else {}
            control_id = rule_def.get("control_id", getattr(rule, "control_id", "UNKNOWN"))
            ev_id = r.evidence_id or default_evidence_id

            builder.add_finding_node(
                finding_id=f.id,
                asset_id=r.asset_id,
                control_id=control_id,
                severity=f.severity,
                status=r.status,
                evidence_id=ev_id,
            )

    return builder


@graph_router.get("/graph")
def get_security_graph(
    request: Request,
    x_org_id: UUID = Header(),
):
    """Retrieve NetworkX security graph with deterministic stable sorting."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        builder = build_tenant_graph(db, x_org_id)
        graph_obj = builder.export_contract_graph()
        return envelope(request, graph_obj.model_dump(mode="json"))


@graph_router.post("/graph/paths")
def check_graph_path(
    body: PathQueryRequest,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Evaluate network reachability and explainability between two assets."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        builder = build_tenant_graph(db, x_org_id)
        eval_result = ReachabilityEvaluator.evaluate_path(
            builder.g,
            body.source_asset_id,
            body.target_asset_id,
            target_port=body.target_port,
        )
        return envelope(request, eval_result)


@graph_router.get("/risk-scenarios")
def list_risk_scenarios(
    request: Request,
    x_org_id: UUID = Header(),
):
    """List correlated risk scenarios with deterministic sorting and explainability chains."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        builder = build_tenant_graph(db, x_org_id)
        scenarios = RiskScenarioCorrelator.correlate_scenarios(x_org_id, builder)
        return envelope(request, [s.model_dump(mode="json") for s in scenarios])


@graph_router.get("/risk-scenarios/{scenario_id}")
def get_risk_scenario(
    scenario_id: UUID,
    request: Request,
    x_org_id: UUID = Header(),
):
    """Retrieve details of an individual correlated risk scenario."""
    who = identity(request)
    with tenant_session(who.user_id, x_org_id) as db:
        member(db, who, x_org_id, "audit.read")
        builder = build_tenant_graph(db, x_org_id)
        scenarios = RiskScenarioCorrelator.correlate_scenarios(x_org_id, builder)
        for s in scenarios:
            if s.scenario_id == scenario_id:
                return envelope(request, s.model_dump(mode="json"))
        raise HTTPException(status_code=404, detail="Risk scenario not found")
