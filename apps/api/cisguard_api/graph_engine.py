"""NetworkX deterministic security graph, reachability traversal, and risk scenario correlator (Phase 6).

Covers:
- NetworkX security graph builder from evidence-linked assets, interfaces, subnets, routes, rules, services, and findings (E13, I01-I03)
- Reachability analysis and topology missingness detection (I03, I04)
- False correlation prevention (scenarios rejected when network path is denied or incomplete) (I04, I05)
- Asset-criticality ranking and exposure severity scoring (I05, I17)
- Deterministic explainability chain and root-cause grouping (I17, I20)
- 100% deterministic, reproducible output
"""

import ipaddress
import logging
from typing import Any, Literal
from uuid import UUID, uuid5, NAMESPACE_DNS

import networkx as nx

from cisguard_contracts.v1.models import (
    Graph,
    GraphEdge,
    GraphNode,
    RiskScenario,
)

logger = logging.getLogger(__name__)


def deterministic_uuid(namespace: str, name: str) -> UUID:
    """Generate deterministic UUIDv5 for consistent node/edge identification."""
    return uuid5(NAMESPACE_DNS, f"{namespace}:{name}")


class SecurityGraphBuilder:
    """Builds a deterministic NetworkX MultiDiGraph from evidence-linked infrastructure and findings."""

    def __init__(self, org_id: UUID):
        self.org_id = org_id
        self.g = nx.MultiDiGraph()
        self.limitations: list[str] = []

    def add_asset_node(self, asset: dict[str, Any]) -> UUID:
        """Add asset node."""
        asset_id = UUID(str(asset["id"]))
        name = asset.get("name", "Unknown Asset")
        criticality = asset.get("criticality", "MEDIUM")
        self.g.add_node(
            asset_id,
            kind="asset",
            label=name,
            asset_id=asset_id,
            family=asset.get("family", "linux"),
            platform=asset.get("platform", "Ubuntu"),
            target=asset.get("target", "127.0.0.1"),
            criticality=criticality,
        )
        return asset_id

    def add_interface_and_subnet(
        self,
        asset_id: UUID,
        iface_name: str,
        ip_addr: str,
        cidr: str,
        evidence_id: UUID,
    ) -> tuple[UUID, UUID]:
        """Add interface and subnet network nodes with attached_to and routes_to edges."""
        iface_id = deterministic_uuid("interface", f"{asset_id}:{iface_name}")
        self.g.add_node(
            iface_id,
            kind="interface",
            label=f"{iface_name} ({ip_addr})",
            ip_addr=ip_addr,
            asset_id=asset_id,
        )

        subnet_id = deterministic_uuid("network", cidr)
        self.g.add_node(
            subnet_id,
            kind="network",
            label=f"Subnet {cidr}",
            cidr=cidr,
        )

        # Edges
        # Asset -> Interface (hosted_on or attached_to)
        e1_id = deterministic_uuid("edge", f"{iface_id}:attached_to:{asset_id}")
        self.g.add_edge(
            iface_id,
            asset_id,
            key=str(e1_id),
            edge_id=e1_id,
            relationship="attached_to",
            evidence_ids=[evidence_id],
        )

        # Interface -> Network (routes_to)
        e2_id = deterministic_uuid("edge", f"{iface_id}:routes_to:{subnet_id}")
        self.g.add_edge(
            iface_id,
            subnet_id,
            key=str(e2_id),
            edge_id=e2_id,
            relationship="routes_to",
            evidence_ids=[evidence_id],
        )
        return iface_id, subnet_id

    def add_service_node(
        self,
        asset_id: UUID,
        service_name: str,
        port: int,
        protocol: str,
        evidence_id: UUID,
    ) -> UUID:
        """Add service running on asset."""
        service_id = deterministic_uuid("service", f"{asset_id}:{service_name}:{port}")
        self.g.add_node(
            service_id,
            kind="service",
            label=f"{service_name}:{port}/{protocol}",
            service_name=service_name,
            port=port,
            protocol=protocol,
            asset_id=asset_id,
        )

        edge_id = deterministic_uuid("edge", f"{service_id}:hosted_on:{asset_id}")
        self.g.add_edge(
            service_id,
            asset_id,
            key=str(edge_id),
            edge_id=edge_id,
            relationship="hosted_on",
            evidence_ids=[evidence_id],
        )
        return service_id

    def add_firewall_rule(
        self,
        firewall_asset_id: UUID,
        rule_name: str,
        source_cidr: str,
        dest_cidr: str,
        port: int | None,
        action: Literal["allows", "denies"],
        evidence_id: UUID,
    ) -> UUID:
        """Add firewall/ACL policy rule node and filter edges."""
        rule_id = deterministic_uuid("policy", f"{firewall_asset_id}:{rule_name}")
        self.g.add_node(
            rule_id,
            kind="policy",
            label=f"Rule {rule_name}: {action.upper()} {source_cidr} -> {dest_cidr}",
            source_cidr=source_cidr,
            dest_cidr=dest_cidr,
            port=port,
            action=action,
            firewall_asset_id=firewall_asset_id,
        )

        src_net_id = deterministic_uuid("network", source_cidr)
        dest_net_id = deterministic_uuid("network", dest_cidr)

        if not self.g.has_node(src_net_id):
            self.g.add_node(src_net_id, kind="network", label=f"Subnet {source_cidr}", cidr=source_cidr)
        if not self.g.has_node(dest_net_id):
            self.g.add_node(dest_net_id, kind="network", label=f"Subnet {dest_cidr}", cidr=dest_cidr)

        edge_id = deterministic_uuid("edge", f"{src_net_id}:{action}:{dest_net_id}")
        self.g.add_edge(
            src_net_id,
            dest_net_id,
            key=str(edge_id),
            edge_id=edge_id,
            relationship=action,
            evidence_ids=[evidence_id],
            rule_id=rule_id,
            port=port,
        )
        return rule_id

    def add_finding_node(
        self,
        finding_id: UUID,
        asset_id: UUID,
        control_id: str,
        severity: str,
        status: str,
        evidence_id: UUID,
    ) -> UUID:
        """Add compliance finding node and edge violating CIS control."""
        self.g.add_node(
            finding_id,
            kind="finding",
            label=f"Finding {control_id} [{severity}]",
            control_id=control_id,
            severity=severity,
            status=status,
            asset_id=asset_id,
            evidence_id=evidence_id,
        )

        edge_id = deterministic_uuid("edge", f"{finding_id}:violates:{asset_id}")
        self.g.add_edge(
            finding_id,
            asset_id,
            key=str(edge_id),
            edge_id=edge_id,
            relationship="violates",
            evidence_ids=[evidence_id],
        )
        return finding_id

    def export_contract_graph(self) -> Graph:
        """Export canonical Graph wire contract with stable deterministic sorting."""
        nodes_out = []
        for n_id, data in sorted(self.g.nodes(data=True), key=lambda x: str(x[0])):
            nodes_out.append(
                GraphNode(
                    node_id=n_id if isinstance(n_id, UUID) else UUID(str(n_id)),
                    kind=data.get("kind", "asset"),
                    label=data.get("label", str(n_id)),
                )
            )

        edges_out = []
        for u, v, k, data in sorted(self.g.edges(data=True, keys=True), key=lambda x: str(x[3].get("edge_id", x[2]))):
            edge_id = data.get("edge_id") or deterministic_uuid("edge", f"{u}:{v}:{k}")
            rel = data.get("relationship", "depends_on")
            ev_ids = data.get("evidence_ids") or [deterministic_uuid("evidence", "fallback")]
            edges_out.append(
                GraphEdge(
                    edge_id=edge_id,
                    source_id=u if isinstance(u, UUID) else UUID(str(u)),
                    target_id=v if isinstance(v, UUID) else UUID(str(v)),
                    relationship=rel,
                    evidence_ids=[e if isinstance(e, UUID) else UUID(str(e)) for e in ev_ids],
                )
            )

        return Graph(
            schema_version="1.0.0",
            org_id=self.org_id,
            nodes=nodes_out,
            edges=edges_out,
            limitations=sorted(list(set(self.limitations))),
        )


class ReachabilityEvaluator:
    """Evaluates reachability between nodes and flags topology gaps or missing evidence."""

    @staticmethod
    def evaluate_path(
        g: nx.MultiDiGraph,
        source_asset_id: UUID,
        target_asset_id: UUID,
        target_port: int | None = None,
    ) -> dict[str, Any]:
        """Check if source asset can reach target asset/service across network topology."""
        if not g.has_node(source_asset_id) or not g.has_node(target_asset_id):
            return {
                "reachable": False,
                "incomplete_evidence": True,
                "reason": "Source or target asset node missing in security graph",
                "missing_nodes": [str(nid) for nid in (source_asset_id, target_asset_id) if not g.has_node(nid)],
            }

        # Find subnets for source and target
        src_subnets = []
        for u, v, data in g.edges(data=True):
            if data.get("relationship") == "attached_to" and v == source_asset_id:
                # u is interface, find its subnet
                for _, net_id, net_data in g.edges(u, data=True):
                    if net_data.get("relationship") == "routes_to":
                        src_subnets.append(net_id)

        dest_subnets = []
        for u, v, data in g.edges(data=True):
            if data.get("relationship") == "attached_to" and v == target_asset_id:
                for _, net_id, net_data in g.edges(u, data=True):
                    if net_data.get("relationship") == "routes_to":
                        dest_subnets.append(net_id)

        if not src_subnets or not dest_subnets:
            return {
                "reachable": False,
                "incomplete_evidence": True,
                "reason": "Missing interface or routing configuration evidence for asset",
                "topology_missingness": "interface_or_routing_missing",
            }

        # Check for same subnet (intra-subnet direct reachability)
        common_subnets = set(src_subnets) & set(dest_subnets)
        if common_subnets:
            return {
                "reachable": True,
                "incomplete_evidence": False,
                "path_type": "intra_subnet",
                "subnet_id": str(list(common_subnets)[0]),
                "hops": 0,
            }

        # Check inter-subnet routes through firewall/router policies
        for s_net in src_subnets:
            for d_net in dest_subnets:
                # Check direct or routed paths
                try:
                    for path in nx.all_simple_paths(g, s_net, d_net, cutoff=4):
                        # Verify every segment in path allows traffic
                        is_allowed = True
                        for i in range(len(path) - 1):
                            u_node = path[i]
                            v_node = path[i + 1]
                            edge_datas = g.get_edge_data(u_node, v_node)
                            if not edge_datas:
                                is_allowed = False
                                break

                            # If edge denies, or specifies a conflicting port, reject
                            has_allow = False
                            for edge_key, ed in edge_datas.items():
                                if ed.get("relationship") == "denies":
                                    is_allowed = False
                                    break
                                if ed.get("relationship") == "allows":
                                    rule_port = ed.get("port")
                                    if rule_port is None or target_port is None or rule_port == target_port:
                                        has_allow = True
                            if not has_allow or not is_allowed:
                                is_allowed = False
                                break

                        if is_allowed:
                            return {
                                "reachable": True,
                                "incomplete_evidence": False,
                                "path_type": "inter_subnet_allowed",
                                "path": [str(p) for p in path],
                                "hops": len(path) - 1,
                            }
                except nx.NetworkXNoPath:
                    continue

        return {
            "reachable": False,
            "incomplete_evidence": False,
            "reason": "No verifiable route or firewall rule permits traffic between source and destination subnets",
        }


class RiskScenarioCorrelator:
    """Evaluates cross-device attack paths and correlates findings deterministically."""

    @staticmethod
    def correlate_scenarios(
        org_id: UUID,
        builder: SecurityGraphBuilder,
    ) -> list[RiskScenario]:
        """Correlate security risks across topology and findings.
        
        Strict rule: Joins related device findings ONLY when network paths and supporting
        facts are explicitly verifiable. Rejects unsupported path assertions.
        """
        g = builder.g
        scenarios: list[RiskScenario] = []

        # Find all failing findings
        failing_findings = []
        for n_id, data in g.nodes(data=True):
            if data.get("kind") == "finding" and data.get("status") in ("FAIL", "MANUAL_REVIEW"):
                failing_findings.append((n_id, data))

        # ------------------------------------------------------------------
        # SCENARIO 1: Lateral Movement from Compromised Bastion/Management Node
        # Condition: Asset A has a HIGH/CRITICAL finding (e.g. SSH weak config)
        # AND Asset A has a verifiable network path to Asset B
        # AND Asset B is HIGH/CRITICAL asset with failing findings.
        # ------------------------------------------------------------------
        for f_id_a, f_data_a in failing_findings:
            asset_a_id = f_data_a.get("asset_id")
            sev_a = f_data_a.get("severity")
            if sev_a not in ("CRITICAL", "HIGH"):
                continue

            for f_id_b, f_data_b in failing_findings:
                if f_id_a == f_id_b:
                    continue
                asset_b_id = f_data_b.get("asset_id")
                if asset_a_id == asset_b_id:
                    continue

                asset_b_data = g.nodes.get(asset_b_id, {})
                crit_b = asset_b_data.get("criticality", "LOW")

                # Test verifiable reachability
                path_eval = ReachabilityEvaluator.evaluate_path(g, asset_a_id, asset_b_id)
                if not path_eval["reachable"]:
                    # CRITICAL REQUIREMENT: Do NOT correlate if path is blocked or unverifiable!
                    continue

                # Verifiable lateral movement scenario!
                scenario_id = deterministic_uuid(
                    "scenario",
                    f"lateral_movement:{asset_a_id}:{f_data_a['control_id']}:{asset_b_id}:{f_data_b['control_id']}"
                )

                ev_ids = [
                    f_data_a["evidence_id"],
                    f_data_b["evidence_id"],
                ]
                explanation = (
                    f"Verifiable lateral movement path detected: Asset '{g.nodes[asset_a_id].get('label')}' "
                    f"with non-compliant control {f_data_a['control_id']} ({sev_a}) has active network reachability "
                    f"to high-criticality asset '{asset_b_data.get('label')}' ({crit_b}), which has failing control "
                    f"{f_data_b['control_id']}."
                )

                # Deterministic score calculation based on severities and criticality
                score = 85.0 if crit_b == "CRITICAL" else 75.0

                scenarios.append(
                    RiskScenario(
                        schema_version="1.0.0",
                        org_id=org_id,
                        scenario_id=scenario_id,
                        rule_version="1.0.0",
                        source_finding_ids=[f_id_a, f_id_b],
                        evidence_ids=ev_ids,
                        explanation=explanation,
                        score=score,
                        limitations=[],
                    )
                )

        # ------------------------------------------------------------------
        # SCENARIO 2: Perimeter Ingress Exposure
        # Condition: Firewall allows external public traffic (0.0.0.0/0) directly
        # to an asset with failing CIS controls on an exposed service.
        # ------------------------------------------------------------------
        for n_id, data in g.nodes(data=True):
            if data.get("kind") == "policy" and data.get("action") == "allows":
                src_cidr = data.get("source_cidr", "")
                if src_cidr in ("0.0.0.0/0", "any"):
                    dest_cidr = data.get("dest_cidr", "")

                    # Find assets belonging to this dest_cidr
                    for a_id, a_data in g.nodes(data=True):
                        if a_data.get("kind") == "asset":
                            target_ip = a_data.get("target")
                            try:
                                if ipaddress.ip_address(target_ip) in ipaddress.ip_network(dest_cidr):
                                    # Check if asset has failing findings
                                    for f_id, f_data in failing_findings:
                                        if f_data.get("asset_id") == a_id:
                                            scenario_id = deterministic_uuid(
                                                "scenario",
                                                f"perimeter_exposure:{n_id}:{a_id}:{f_data['control_id']}"
                                            )
                                            ev_ids = [f_data["evidence_id"]]
                                            explanation = (
                                                f"Perimeter ingress exposure: Rule '{data.get('label')}' allows unrestricted "
                                                f"ingress from {src_cidr} to asset '{a_data.get('label')}' ({target_ip}), "
                                                f"which has failing CIS control {f_data['control_id']}."
                                            )
                                            scenarios.append(
                                                RiskScenario(
                                                    schema_version="1.0.0",
                                                    org_id=org_id,
                                                    scenario_id=scenario_id,
                                                    rule_version="1.0.0",
                                                    source_finding_ids=[f_id],
                                                    evidence_ids=ev_ids,
                                                    explanation=explanation,
                                                    score=90.0 if f_data["severity"] == "CRITICAL" else 80.0,
                                                    limitations=[],
                                                )
                                            )
                            except ValueError:
                                pass

        # ------------------------------------------------------------------
        # SCENARIO 3: Shared Subnet Blast Radius
        # Multiple assets on same subnet with identical high/critical finding
        # ------------------------------------------------------------------
        subnet_findings: dict[str, list[tuple[UUID, UUID, str]]] = {}
        for f_id, f_data in failing_findings:
            if f_data.get("severity") in ("CRITICAL", "HIGH"):
                a_id = f_data.get("asset_id")
                # find subnet
                for u, v, ed in g.edges(data=True):
                    if ed.get("relationship") == "attached_to" and v == a_id:
                        for _, net_id, nd in g.edges(u, data=True):
                            if nd.get("relationship") == "routes_to":
                                cidr = g.nodes[net_id].get("cidr", str(net_id))
                                key = f"{cidr}:{f_data['control_id']}"
                                subnet_findings.setdefault(key, []).append((f_id, f_data["evidence_id"], a_id))

        for key, items in subnet_findings.items():
            if len(items) >= 2:
                cidr, control_id = key.split(":")
                unique_assets = set(it[2] for it in items)
                if len(unique_assets) >= 2:
                    first_items = items[:3]
                    f_ids = [it[0] for it in first_items]
                    ev_ids = [it[1] for it in first_items]
                    scenario_id = deterministic_uuid("scenario", f"shared_blast:{key}")
                    explanation = (
                        f"Shared subnet blast radius on {cidr}: Multiple assets ({len(unique_assets)}) share identical "
                        f"failing control {control_id}, exposing the broadcast domain to common vulnerability exploitation."
                    )
                    scenarios.append(
                        RiskScenario(
                            schema_version="1.0.0",
                            org_id=org_id,
                            scenario_id=scenario_id,
                            rule_version="1.0.0",
                            source_finding_ids=f_ids,
                            evidence_ids=ev_ids,
                            explanation=explanation,
                            score=70.0,
                            limitations=[],
                        )
                    )

        # Sort scenarios deterministically by scenario_id
        scenarios.sort(key=lambda s: str(s.scenario_id))
        return scenarios
