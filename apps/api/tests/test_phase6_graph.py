"""Phase 6 unit and integration tests: Cross-layer security graph, reachability, and risk scenario correlation.

Covers:
- NetworkX security graph builder with typed nodes and edges (E13, I01, I03)
- Reachability traversal and topology missingness detection (I03, I04)
- False correlation prevention (scenarios rejected when network paths are blocked or unverifiable) (I04, I05)
- Lateral movement, perimeter exposure, and shared subnet blast radius scenarios (I02, I05, I17)
- Determinism and reproducible output ordering (unchanged input yields identical output) (E20)
"""

import json
from uuid import UUID, uuid4

import pytest

from cisguard_api.graph_engine import (
    ReachabilityEvaluator,
    RiskScenarioCorrelator,
    SecurityGraphBuilder,
    deterministic_uuid,
)
from cisguard_contracts.v1.models import Graph, RiskScenario


@pytest.fixture
def mock_topology():
    """Build a deterministic test topology:

    - Perimeter Firewall (fw-edge) with public interface and internal interfaces
    - DMZ Subnet (10.0.1.0/24) hosting Web Server (web-prod-01)
    - Internal Secure Subnet (10.0.2.0/24) hosting Database Server (db-prod-01)
    - Firewall rules:
        Rule 1: ALLOW 0.0.0.0/0 -> 10.0.1.0/24 (HTTP/HTTPS public ingress)
        Rule 2: ALLOW 10.0.1.0/24 -> 10.0.2.0/24 port 5432 (Database access from DMZ)
        Rule 3: DENY 10.0.1.0/24 -> 10.0.3.0/24 (Blocked subnet)
    """
    org_id = uuid4()
    builder = SecurityGraphBuilder(org_id)
    ev_id = uuid4()

    # Assets
    fw_id = uuid4()
    web_id = uuid4()
    db_id = uuid4()
    isolated_id = uuid4()

    builder.add_asset_node({
        "id": fw_id,
        "name": "fw-edge",
        "family": "firewall",
        "platform": "FortiGate 7.0",
        "target": "192.168.1.1",
        "criticality": "CRITICAL",
    })

    builder.add_asset_node({
        "id": web_id,
        "name": "web-prod-01",
        "family": "linux",
        "platform": "Ubuntu 22.04",
        "target": "10.0.1.10",
        "criticality": "HIGH",
    })

    builder.add_asset_node({
        "id": db_id,
        "name": "db-prod-01",
        "family": "linux",
        "platform": "Ubuntu 22.04",
        "target": "10.0.2.20",
        "criticality": "CRITICAL",
    })

    builder.add_asset_node({
        "id": isolated_id,
        "name": "isolated-test",
        "family": "linux",
        "platform": "Ubuntu 22.04",
        "target": "10.0.3.30",
        "criticality": "LOW",
    })

    # Interfaces & Subnets
    builder.add_interface_and_subnet(web_id, "eth0", "10.0.1.10", "10.0.1.0/24", ev_id)
    builder.add_interface_and_subnet(db_id, "eth0", "10.0.2.20", "10.0.2.0/24", ev_id)
    builder.add_interface_and_subnet(isolated_id, "eth0", "10.0.3.30", "10.0.3.0/24", ev_id)

    # Firewall Rules
    # Perimeter Ingress: 0.0.0.0/0 -> 10.0.1.0/24
    builder.add_firewall_rule(fw_id, "allow-public-web", "0.0.0.0/0", "10.0.1.0/24", 443, "allows", ev_id)

    # DMZ to Internal Database: 10.0.1.0/24 -> 10.0.2.0/24 port 5432
    builder.add_firewall_rule(fw_id, "allow-web-to-db", "10.0.1.0/24", "10.0.2.0/24", 5432, "allows", ev_id)

    # DMZ to Isolated: Explicit DENY
    builder.add_firewall_rule(fw_id, "deny-web-to-isolated", "10.0.1.0/24", "10.0.3.0/24", None, "denies", ev_id)

    # Compliance Findings
    # Web server has failing SSH PermitRootLogin (CRITICAL) and unpatched web service
    f1_id = uuid4()
    builder.add_finding_node(f1_id, web_id, "5.2.1", "CRITICAL", "FAIL", ev_id)

    # DB server has failing unencrypted data at rest (HIGH)
    f2_id = uuid4()
    builder.add_finding_node(f2_id, db_id, "3.4.1", "HIGH", "FAIL", ev_id)

    # Isolated node has failing finding
    f3_id = uuid4()
    builder.add_finding_node(f3_id, isolated_id, "1.1.1", "HIGH", "FAIL", ev_id)

    return {
        "org_id": org_id,
        "builder": builder,
        "fw_id": fw_id,
        "web_id": web_id,
        "db_id": db_id,
        "isolated_id": isolated_id,
        "f1_id": f1_id,
        "f2_id": f2_id,
        "f3_id": f3_id,
        "ev_id": ev_id,
    }


# ============================================================================
# Reachability Traversal Tests (I03, I04)
# ============================================================================

def test_reachability_allowed_path(mock_topology):
    """Verifiable network path from web server to DB server on allowed port 5432."""
    g = mock_topology["builder"].g
    web_id = mock_topology["web_id"]
    db_id = mock_topology["db_id"]

    res = ReachabilityEvaluator.evaluate_path(g, web_id, db_id, target_port=5432)
    assert res["reachable"] is True
    assert res["incomplete_evidence"] is False
    assert res["path_type"] == "inter_subnet_allowed"
    assert res["hops"] >= 1


def test_reachability_blocked_by_firewall_rule(mock_topology):
    """Traffic from web server to isolated node is explicitly blocked by firewall rule."""
    g = mock_topology["builder"].g
    web_id = mock_topology["web_id"]
    isolated_id = mock_topology["isolated_id"]

    res = ReachabilityEvaluator.evaluate_path(g, web_id, isolated_id)
    assert res["reachable"] is False
    assert res["incomplete_evidence"] is False
    assert "No verifiable route or firewall rule permits traffic" in res["reason"]


def test_reachability_missing_topology_evidence(mock_topology):
    """When an asset has no interface or routing evidence, flags incomplete evidence."""
    g = mock_topology["builder"].g
    web_id = mock_topology["web_id"]
    ghost_asset_id = uuid4()

    g.add_node(ghost_asset_id, kind="asset", label="ghost-node", target="192.168.99.99")

    res = ReachabilityEvaluator.evaluate_path(g, web_id, ghost_asset_id)
    assert res["reachable"] is False
    assert res["incomplete_evidence"] is True
    assert res["topology_missingness"] == "interface_or_routing_missing"


# ============================================================================
# False Correlation Negative Tests (I04, I05)
# ============================================================================

def test_false_correlation_prevention(mock_topology):
    """MANDATORY REQUIREMENT:

    Risk scenarios MUST NOT correlate findings between devices if the network path
    between them is denied or unverifiable.
    """
    org_id = mock_topology["org_id"]
    builder = mock_topology["builder"]
    web_id = mock_topology["web_id"]
    db_id = mock_topology["db_id"]
    isolated_id = mock_topology["isolated_id"]
    f1_id = mock_topology["f1_id"]
    f3_id = mock_topology["f3_id"]

    scenarios = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)

    # 1. POSITIVE CASE: Web (compromised) -> DB (high-crit target) has allowed path.
    # Therefore, a lateral movement scenario connecting web and db MUST be present!
    web_to_db_scenarios = [
        s for s in scenarios
        if f1_id in s.source_finding_ids and mock_topology["f2_id"] in s.source_finding_ids
    ]
    assert len(web_to_db_scenarios) == 1
    assert "Verifiable lateral movement path detected" in web_to_db_scenarios[0].explanation

    # 2. NEGATIVE CASE: Web -> Isolated has a DENY rule.
    # Therefore, a scenario correlating Web finding f1 and Isolated finding f3 MUST NOT EXIST!
    false_correlation = [
        s for s in scenarios
        if f1_id in s.source_finding_ids and f3_id in s.source_finding_ids
    ]
    assert len(false_correlation) == 0, "False correlation detected! Denied path must never correlate."


# ============================================================================
# Perimeter Ingress Exposure Scenario (I02, I05)
# ============================================================================

def test_perimeter_ingress_scenario(mock_topology):
    """Verifies correlation of public 0.0.0.0/0 ingress to an asset with failing controls."""
    org_id = mock_topology["org_id"]
    builder = mock_topology["builder"]
    f1_id = mock_topology["f1_id"]

    scenarios = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)
    perimeter_scenarios = [s for s in scenarios if "Perimeter ingress exposure" in s.explanation]

    assert len(perimeter_scenarios) == 1
    p_scen = perimeter_scenarios[0]
    assert f1_id in p_scen.source_finding_ids
    assert p_scen.score >= 80.0
    assert "0.0.0.0/0" in p_scen.explanation


# ============================================================================
# Shared Subnet Blast Radius Scenario (I02, I17)
# ============================================================================

def test_shared_subnet_blast_radius():
    """Verifies grouping of multiple assets sharing a failing control on the same subnet."""
    org_id = uuid4()
    builder = SecurityGraphBuilder(org_id)
    ev_id = uuid4()

    # Three web nodes on the same 10.0.1.0/24 subnet
    node1_id = uuid4()
    node2_id = uuid4()
    node3_id = uuid4()

    for nid, name, ip in [(node1_id, "node1", "10.0.1.11"), (node2_id, "node2", "10.0.1.12"), (node3_id, "node3", "10.0.1.13")]:
        builder.add_asset_node({"id": nid, "name": name, "target": ip, "family": "linux"})
        builder.add_interface_and_subnet(nid, "eth0", ip, "10.0.1.0/24", ev_id)
        # All three have failing control 5.2.1 (SSH Root Login)
        builder.add_finding_node(uuid4(), nid, "5.2.1", "HIGH", "FAIL", ev_id)

    scenarios = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)
    blast_scenarios = [s for s in scenarios if "Shared subnet blast radius" in s.explanation]

    assert len(blast_scenarios) == 1
    assert "10.0.1.0/24" in blast_scenarios[0].explanation
    assert len(blast_scenarios[0].source_finding_ids) >= 2


# ============================================================================
# Determinism Test: Unchanged Input Yields Byte-For-Byte Identical Output
# ============================================================================

def test_graph_and_scenario_determinism(mock_topology):
    """MANDATORY REQUIREMENT:

    Unchanged input produces byte-for-byte identical output and stable ordering.
    """
    org_id = mock_topology["org_id"]
    builder = mock_topology["builder"]

    # Export graph twice
    graph1 = builder.export_contract_graph()
    graph2 = builder.export_contract_graph()

    json1 = graph1.model_dump_json()
    json2 = graph2.model_dump_json()
    assert json1 == json2, "Graph export must be 100% deterministic"

    # Correlate scenarios twice
    scenarios1 = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)
    scenarios2 = RiskScenarioCorrelator.correlate_scenarios(org_id, builder)

    scen_json1 = json.dumps([s.model_dump(mode="json") for s in scenarios1], sort_keys=True)
    scen_json2 = json.dumps([s.model_dump(mode="json") for s in scenarios2], sort_keys=True)
    assert scen_json1 == scen_json2, "Risk scenarios must be 100% deterministic"

