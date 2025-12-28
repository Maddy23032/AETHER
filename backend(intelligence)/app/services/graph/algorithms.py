"""
Novel Graph Algorithms for Security-Aware Sitemap Analysis

This module implements three key algorithms for the Dynamic Graph Sitemap:
1. Security-Aware PageRank (SA-PageRank) - Ranks nodes by security importance
2. Vulnerability Propagation Model - Computes risk spread across infrastructure
3. Functional Zone Clustering - Groups related nodes by security function

These algorithms form the core novelty contribution for research paper.
"""

import networkx as nx
import numpy as np
from typing import Dict, List, Tuple, Set, Optional, Any
from dataclasses import dataclass
from enum import Enum
import math


class NodeType(str, Enum):
    """Types of nodes in the security graph"""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT_SERVICE = "port_service"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    VULNERABILITY = "vulnerability"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    API_ENDPOINT = "api_endpoint"
    THIRD_PARTY_SERVICE = "third_party_service"
    AUTHENTICATION_POINT = "authentication_point"
    FILE_RESOURCE = "file_resource"
    MOBILE_ENDPOINT = "mobile_endpoint"


class EdgeType(str, Enum):
    """Types of edges (relationships) in the security graph"""
    RESOLVES_TO = "resolves_to"
    HAS_SUBDOMAIN = "has_subdomain"
    HOSTS_SERVICE = "hosts_service"
    SERVES_ENDPOINT = "serves_endpoint"
    ACCEPTS_PARAMETER = "accepts_parameter"
    HAS_VULNERABILITY = "has_vulnerability"
    USES_TECHNOLOGY = "uses_technology"
    AUTHENTICATES_VIA = "authenticates_via"
    CALLS_API = "calls_api"
    INTEGRATES_WITH = "integrates_with"
    LEADS_TO = "leads_to"
    PROTECTED_BY = "protected_by"
    EXPOSES_DATA = "exposes_data"
    INFERRED = "inferred"


@dataclass
class NodeRiskScore:
    """Risk score for a node with component breakdown"""
    node_id: str
    total_score: float
    intrinsic_risk: float  # Based on node type and direct vulnerabilities
    propagated_risk: float  # Risk from connected vulnerable nodes
    exposure_factor: float  # How exposed/connected this node is
    criticality_factor: float  # Business/security criticality


@dataclass 
class AttackPath:
    """Represents a potential attack path through the graph"""
    path_id: str
    nodes: List[str]
    edges: List[str]
    total_risk: float
    entry_point: str
    target: str
    exploitability_score: float
    impact_score: float
    cvss_chain: List[float]


@dataclass
class FunctionalZone:
    """A cluster of related nodes forming a functional zone"""
    zone_id: str
    zone_name: str
    zone_type: str  # 'authentication', 'api', 'infrastructure', 'data', etc.
    nodes: List[str]
    aggregate_risk: float
    boundary_nodes: List[str]  # Nodes at zone boundaries
    internal_connectivity: float


class SecurityAwarePageRank:
    """
    Security-Aware PageRank (SA-PageRank)
    
    A novel extension of the PageRank algorithm that incorporates:
    - Node type importance weights
    - Vulnerability severity scores  
    - Edge type criticality factors
    - Authentication/authorization boundaries
    
    Formula: SA-PR(v) = (1-d) + d * Σ(SA-PR(u) * W(u,v) * S(u))
    Where:
        - d = damping factor (0.85)
        - W(u,v) = edge weight based on relationship type
        - S(u) = security factor combining vulnerability scores
    """
    
    # Node type importance weights (higher = more critical in security context)
    NODE_TYPE_WEIGHTS = {
        NodeType.DOMAIN: 0.9,
        NodeType.SUBDOMAIN: 0.7,
        NodeType.IP_ADDRESS: 0.8,
        NodeType.PORT_SERVICE: 0.75,
        NodeType.ENDPOINT: 0.6,
        NodeType.PARAMETER: 0.5,
        NodeType.VULNERABILITY: 1.0,  # Vulnerabilities are highest priority
        NodeType.TECHNOLOGY: 0.4,
        NodeType.CERTIFICATE: 0.6,
        NodeType.API_ENDPOINT: 0.7,
        NodeType.THIRD_PARTY_SERVICE: 0.65,
        NodeType.AUTHENTICATION_POINT: 0.85,
        NodeType.FILE_RESOURCE: 0.5,
        NodeType.MOBILE_ENDPOINT: 0.7,
    }
    
    # Edge type weights (higher = more significant relationship for security)
    EDGE_TYPE_WEIGHTS = {
        EdgeType.RESOLVES_TO: 0.8,
        EdgeType.HAS_SUBDOMAIN: 0.6,
        EdgeType.HOSTS_SERVICE: 0.9,
        EdgeType.SERVES_ENDPOINT: 0.7,
        EdgeType.ACCEPTS_PARAMETER: 0.8,
        EdgeType.HAS_VULNERABILITY: 1.0,
        EdgeType.USES_TECHNOLOGY: 0.5,
        EdgeType.AUTHENTICATES_VIA: 0.95,
        EdgeType.CALLS_API: 0.75,
        EdgeType.INTEGRATES_WITH: 0.6,
        EdgeType.LEADS_TO: 0.85,
        EdgeType.PROTECTED_BY: 0.7,
        EdgeType.EXPOSES_DATA: 0.9,
        EdgeType.INFERRED: 0.3,
    }
    
    def __init__(self, damping_factor: float = 0.85, max_iterations: int = 100, 
                 tolerance: float = 1e-6):
        self.damping_factor = damping_factor
        self.max_iterations = max_iterations
        self.tolerance = tolerance
    
    def compute(self, graph: nx.DiGraph) -> Dict[str, float]:
        """
        Compute Security-Aware PageRank for all nodes.
        
        Args:
            graph: NetworkX DiGraph with node and edge attributes
            
        Returns:
            Dictionary mapping node IDs to their SA-PageRank scores
        """
        if len(graph) == 0:
            return {}
        
        nodes = list(graph.nodes())
        n = len(nodes)
        node_index = {node: i for i, node in enumerate(nodes)}
        
        # Initialize scores uniformly
        scores = np.ones(n) / n
        
        # Pre-compute security factors for each node
        security_factors = self._compute_security_factors(graph, nodes)
        
        # Pre-compute weighted adjacency
        adj_matrix = self._build_weighted_adjacency(graph, nodes, node_index)
        
        # Power iteration with security awareness
        for iteration in range(self.max_iterations):
            new_scores = np.zeros(n)
            
            for i, node in enumerate(nodes):
                # Base score (teleportation)
                new_scores[i] = (1 - self.damping_factor) / n
                
                # Contribution from predecessors
                for pred in graph.predecessors(node):
                    pred_idx = node_index[pred]
                    out_degree = graph.out_degree(pred)
                    if out_degree > 0:
                        # Weight by security factor and edge weight
                        edge_weight = adj_matrix[pred_idx, i]
                        security_factor = security_factors[pred]
                        contribution = scores[pred_idx] * edge_weight * security_factor / out_degree
                        new_scores[i] += self.damping_factor * contribution
            
            # Normalize
            new_scores = new_scores / new_scores.sum() if new_scores.sum() > 0 else new_scores
            
            # Check convergence
            if np.abs(new_scores - scores).sum() < self.tolerance:
                break
            
            scores = new_scores
        
        return {node: float(scores[i]) for i, node in enumerate(nodes)}
    
    def _compute_security_factors(self, graph: nx.DiGraph, nodes: List[str]) -> Dict[str, float]:
        """Compute security factor for each node based on type and vulnerabilities."""
        factors = {}
        
        for node in nodes:
            node_data = graph.nodes[node]
            node_type = node_data.get('node_type', NodeType.ENDPOINT)
            
            # Base weight from node type
            if isinstance(node_type, str):
                try:
                    node_type = NodeType(node_type)
                except ValueError:
                    node_type = NodeType.ENDPOINT
            
            base_weight = self.NODE_TYPE_WEIGHTS.get(node_type, 0.5)
            
            # Vulnerability adjustment
            vuln_count = node_data.get('vulnerability_count', 0)
            max_severity = node_data.get('max_severity', 0)
            vuln_factor = 1.0 + (vuln_count * 0.1) + (max_severity / 10.0)
            
            # Exposure factor (based on connectivity)
            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)
            exposure = math.log1p(in_degree + out_degree) / 5.0
            
            factors[node] = min(base_weight * vuln_factor * (1 + exposure), 2.0)
        
        return factors
    
    def _build_weighted_adjacency(self, graph: nx.DiGraph, nodes: List[str], 
                                   node_index: Dict[str, int]) -> np.ndarray:
        """Build weighted adjacency matrix based on edge types."""
        n = len(nodes)
        adj = np.zeros((n, n))
        
        for u, v, data in graph.edges(data=True):
            edge_type = data.get('edge_type', EdgeType.INFERRED)
            
            if isinstance(edge_type, str):
                try:
                    edge_type = EdgeType(edge_type)
                except ValueError:
                    edge_type = EdgeType.INFERRED
            
            weight = self.EDGE_TYPE_WEIGHTS.get(edge_type, 0.5)
            adj[node_index[u], node_index[v]] = weight
        
        return adj


class VulnerabilityPropagation:
    """
    Vulnerability Propagation Model
    
    Computes how vulnerability risk propagates through the infrastructure graph.
    Uses a modified heat diffusion model where:
    - Vulnerable nodes act as heat sources
    - Risk "flows" through edges based on relationship type
    - Nodes accumulate propagated risk over time steps
    
    This enables identifying nodes that aren't directly vulnerable but are
    at high risk due to their proximity to vulnerable components.
    """
    
    # How much risk is retained at each propagation step
    RETENTION_FACTOR = 0.7
    
    # Edge types that propagate risk more easily
    HIGH_PROPAGATION_EDGES = {
        EdgeType.AUTHENTICATES_VIA,
        EdgeType.LEADS_TO,
        EdgeType.EXPOSES_DATA,
        EdgeType.HAS_VULNERABILITY,
        EdgeType.HOSTS_SERVICE,
    }
    
    def __init__(self, propagation_steps: int = 5, min_risk_threshold: float = 0.01):
        self.propagation_steps = propagation_steps
        self.min_risk_threshold = min_risk_threshold
    
    def compute(self, graph: nx.DiGraph) -> Dict[str, NodeRiskScore]:
        """
        Compute propagated risk scores for all nodes.
        
        Args:
            graph: NetworkX DiGraph with vulnerability information
            
        Returns:
            Dictionary mapping node IDs to NodeRiskScore objects
        """
        if len(graph) == 0:
            return {}
        
        nodes = list(graph.nodes())
        
        # Initialize intrinsic risk based on direct vulnerabilities
        intrinsic_risk = self._compute_intrinsic_risk(graph, nodes)
        
        # Propagate risk through the graph
        propagated_risk = self._propagate_risk(graph, nodes, intrinsic_risk)
        
        # Compute exposure factors
        exposure_factors = self._compute_exposure_factors(graph, nodes)
        
        # Compute criticality factors
        criticality_factors = self._compute_criticality_factors(graph, nodes)
        
        # Combine into final risk scores
        risk_scores = {}
        for node in nodes:
            intrinsic = intrinsic_risk.get(node, 0.0)
            propagated = propagated_risk.get(node, 0.0)
            exposure = exposure_factors.get(node, 1.0)
            criticality = criticality_factors.get(node, 1.0)
            
            # Total risk combines all factors
            total = (intrinsic * 0.4 + propagated * 0.3) * exposure * criticality
            
            risk_scores[node] = NodeRiskScore(
                node_id=node,
                total_score=min(total, 10.0),  # Cap at 10
                intrinsic_risk=intrinsic,
                propagated_risk=propagated,
                exposure_factor=exposure,
                criticality_factor=criticality
            )
        
        return risk_scores
    
    def _compute_intrinsic_risk(self, graph: nx.DiGraph, nodes: List[str]) -> Dict[str, float]:
        """Compute intrinsic risk based on direct vulnerabilities."""
        risk = {}
        
        for node in nodes:
            node_data = graph.nodes[node]
            
            # Base risk from vulnerability count and severity
            vuln_count = node_data.get('vulnerability_count', 0)
            max_severity = node_data.get('max_severity', 0)
            cvss_scores = node_data.get('cvss_scores', [])
            
            if cvss_scores:
                avg_cvss = sum(cvss_scores) / len(cvss_scores)
            else:
                avg_cvss = max_severity
            
            # Risk formula: weighted combination
            base_risk = (vuln_count * 0.5) + (max_severity * 0.3) + (avg_cvss * 0.2)
            
            # Node type modifier
            node_type = node_data.get('node_type', 'endpoint')
            type_modifier = {
                'authentication_point': 1.5,
                'api_endpoint': 1.3,
                'domain': 1.2,
                'ip_address': 1.1,
                'endpoint': 1.0,
                'parameter': 0.8,
                'technology': 0.7,
            }.get(node_type, 1.0)
            
            risk[node] = base_risk * type_modifier
        
        return risk
    
    def _propagate_risk(self, graph: nx.DiGraph, nodes: List[str], 
                        initial_risk: Dict[str, float]) -> Dict[str, float]:
        """Propagate risk through the graph using heat diffusion."""
        current_risk = initial_risk.copy()
        propagated = {node: 0.0 for node in nodes}
        
        for step in range(self.propagation_steps):
            new_propagated = propagated.copy()
            
            for node in nodes:
                # Get risk from neighbors
                incoming_risk = 0.0
                
                for pred in graph.predecessors(node):
                    edge_data = graph.edges[pred, node]
                    edge_type = edge_data.get('edge_type', 'inferred')
                    
                    # Higher propagation for critical edge types
                    if edge_type in [e.value for e in self.HIGH_PROPAGATION_EDGES]:
                        propagation_weight = 0.8
                    else:
                        propagation_weight = 0.4
                    
                    source_risk = current_risk.get(pred, 0) + propagated.get(pred, 0)
                    incoming_risk += source_risk * propagation_weight * self.RETENTION_FACTOR
                
                # Also consider outgoing edges (bidirectional propagation)
                for succ in graph.successors(node):
                    edge_data = graph.edges[node, succ]
                    edge_type = edge_data.get('edge_type', 'inferred')
                    
                    # Lower propagation in reverse direction
                    propagation_weight = 0.2
                    source_risk = current_risk.get(succ, 0) + propagated.get(succ, 0)
                    incoming_risk += source_risk * propagation_weight * self.RETENTION_FACTOR * 0.5
                
                new_propagated[node] = max(propagated[node], incoming_risk)
            
            propagated = new_propagated
        
        return propagated
    
    def _compute_exposure_factors(self, graph: nx.DiGraph, nodes: List[str]) -> Dict[str, float]:
        """Compute how exposed each node is based on connectivity."""
        factors = {}
        max_degree = max((graph.degree(n) for n in nodes), default=1)
        # Prevent division by zero when max_degree is 0
        log_max_degree = math.log1p(max_degree) if max_degree > 0 else 1.0
        
        for node in nodes:
            degree = graph.degree(node)
            # Logarithmic scaling to prevent extreme values
            factors[node] = 1.0 + math.log1p(degree) / log_max_degree
        
        return factors
    
    def _compute_criticality_factors(self, graph: nx.DiGraph, nodes: List[str]) -> Dict[str, float]:
        """Compute business/security criticality based on node properties."""
        factors = {}
        
        for node in nodes:
            node_data = graph.nodes[node]
            
            # Check for critical indicators
            is_auth = node_data.get('node_type') == 'authentication_point'
            is_api = node_data.get('node_type') == 'api_endpoint'
            has_sensitive_data = node_data.get('handles_sensitive_data', False)
            is_external = node_data.get('is_external', False)
            
            factor = 1.0
            if is_auth:
                factor *= 1.5
            if is_api:
                factor *= 1.3
            if has_sensitive_data:
                factor *= 1.4
            if is_external:
                factor *= 1.2
            
            factors[node] = factor
        
        return factors
    
    def find_attack_paths(self, graph: nx.DiGraph, risk_scores: Dict[str, NodeRiskScore],
                          max_paths: int = 10) -> List[AttackPath]:
        """
        Find potential attack paths from entry points to high-value targets.
        
        Uses risk scores to identify the most dangerous paths through the infrastructure.
        """
        paths = []
        
        # Identify entry points (external-facing nodes)
        entry_points = [
            n for n in graph.nodes() 
            if graph.nodes[n].get('is_external', False) or 
               graph.nodes[n].get('node_type') in ['domain', 'subdomain', 'ip_address']
        ]
        
        # Identify high-value targets
        targets = [
            n for n in graph.nodes()
            if graph.nodes[n].get('node_type') in ['authentication_point', 'api_endpoint'] or
               graph.nodes[n].get('handles_sensitive_data', False) or
               risk_scores.get(n, NodeRiskScore(n, 0, 0, 0, 0, 0)).intrinsic_risk > 5.0
        ]
        
        # Find paths from entry points to targets
        path_id = 0
        for entry in entry_points[:5]:  # Limit entry points
            for target in targets[:5]:  # Limit targets
                if entry == target:
                    continue
                    
                try:
                    # Find shortest path
                    if nx.has_path(graph, entry, target):
                        path_nodes = nx.shortest_path(graph, entry, target)
                        
                        # Calculate path risk
                        path_risk = sum(
                            risk_scores.get(n, NodeRiskScore(n, 0, 0, 0, 0, 0)).total_score 
                            for n in path_nodes
                        )
                        
                        # Get CVSS scores along path
                        cvss_chain = []
                        for n in path_nodes:
                            node_data = graph.nodes[n]
                            cvss = node_data.get('max_severity', 0)
                            if cvss > 0:
                                cvss_chain.append(cvss)
                        
                        # Calculate exploitability (based on vulnerability chain)
                        exploitability = sum(cvss_chain) / len(path_nodes) if path_nodes else 0
                        
                        # Calculate impact (based on target criticality)
                        target_risk = risk_scores.get(target, NodeRiskScore(target, 0, 0, 0, 0, 1.0))
                        impact = target_risk.criticality_factor * target_risk.intrinsic_risk
                        
                        path = AttackPath(
                            path_id=f"path_{path_id}",
                            nodes=path_nodes,
                            edges=[],  # Would need to track edge IDs
                            total_risk=path_risk,
                            entry_point=entry,
                            target=target,
                            exploitability_score=exploitability,
                            impact_score=impact,
                            cvss_chain=cvss_chain
                        )
                        paths.append(path)
                        path_id += 1
                        
                except nx.NetworkXNoPath:
                    continue
        
        # Sort by total risk and return top paths
        paths.sort(key=lambda p: p.total_risk, reverse=True)
        return paths[:max_paths]


class FunctionalZoneClustering:
    """
    Functional Zone Clustering
    
    Groups nodes into functional security zones based on:
    - Node types and their relationships
    - Authentication boundaries
    - Network topology
    - Shared vulnerabilities
    
    This helps identify security perimeters and potential lateral movement zones.
    """
    
    ZONE_TYPES = [
        'perimeter',      # External-facing infrastructure
        'authentication', # Auth-related components
        'api',            # API layer
        'application',    # Application logic
        'data',           # Data storage and processing
        'infrastructure', # Core infrastructure
        'third_party',    # Third-party integrations
        'mobile',         # Mobile-specific components
    ]
    
    def __init__(self, min_zone_size: int = 2, modularity_threshold: float = 0.3):
        self.min_zone_size = min_zone_size
        self.modularity_threshold = modularity_threshold
    
    def compute(self, graph: nx.DiGraph) -> List[FunctionalZone]:
        """
        Compute functional zones for the graph.
        
        Args:
            graph: NetworkX DiGraph with node attributes
            
        Returns:
            List of FunctionalZone objects
        """
        if len(graph) == 0:
            return []
        
        # Convert to undirected for community detection
        undirected = graph.to_undirected()
        
        # Use Louvain community detection if available, otherwise use label propagation
        try:
            from networkx.algorithms.community import louvain_communities
            communities = list(louvain_communities(undirected))
        except ImportError:
            from networkx.algorithms.community import label_propagation_communities
            communities = list(label_propagation_communities(undirected))
        
        zones = []
        for i, community in enumerate(communities):
            if len(community) < self.min_zone_size:
                continue
            
            community_nodes = list(community)
            
            # Determine zone type based on node composition
            zone_type = self._determine_zone_type(graph, community_nodes)
            
            # Calculate aggregate risk
            aggregate_risk = self._calculate_aggregate_risk(graph, community_nodes)
            
            # Find boundary nodes (connected to nodes outside the zone)
            boundary_nodes = self._find_boundary_nodes(graph, community_nodes, set(community_nodes))
            
            # Calculate internal connectivity
            internal_connectivity = self._calculate_internal_connectivity(
                graph, community_nodes, set(community_nodes)
            )
            
            zone = FunctionalZone(
                zone_id=f"zone_{i}",
                zone_name=f"{zone_type.title()} Zone {i+1}",
                zone_type=zone_type,
                nodes=community_nodes,
                aggregate_risk=aggregate_risk,
                boundary_nodes=boundary_nodes,
                internal_connectivity=internal_connectivity
            )
            zones.append(zone)
        
        return zones
    
    def _determine_zone_type(self, graph: nx.DiGraph, nodes: List[str]) -> str:
        """Determine the functional type of a zone based on its nodes."""
        type_counts = {}
        
        for node in nodes:
            node_type = graph.nodes[node].get('node_type', 'endpoint')
            
            # Map node types to zone types
            if node_type in ['domain', 'subdomain', 'ip_address']:
                zone_type = 'perimeter'
            elif node_type == 'authentication_point':
                zone_type = 'authentication'
            elif node_type in ['api_endpoint', 'endpoint']:
                zone_type = 'api'
            elif node_type == 'third_party_service':
                zone_type = 'third_party'
            elif node_type == 'mobile_endpoint':
                zone_type = 'mobile'
            elif node_type in ['port_service', 'technology']:
                zone_type = 'infrastructure'
            else:
                zone_type = 'application'
            
            type_counts[zone_type] = type_counts.get(zone_type, 0) + 1
        
        # Return the most common zone type
        if type_counts:
            return max(type_counts, key=type_counts.get)
        return 'application'
    
    def _calculate_aggregate_risk(self, graph: nx.DiGraph, nodes: List[str]) -> float:
        """Calculate aggregate risk for a zone."""
        total_risk = 0.0
        
        for node in nodes:
            node_data = graph.nodes[node]
            vuln_count = node_data.get('vulnerability_count', 0)
            max_severity = node_data.get('max_severity', 0)
            total_risk += vuln_count * 0.5 + max_severity * 0.5
        
        return total_risk / len(nodes) if nodes else 0.0
    
    def _find_boundary_nodes(self, graph: nx.DiGraph, nodes: List[str], 
                              node_set: Set[str]) -> List[str]:
        """Find nodes that connect to nodes outside the zone."""
        boundary = []
        
        for node in nodes:
            # Check if any neighbor is outside the zone
            all_neighbors = set(graph.predecessors(node)) | set(graph.successors(node))
            external_neighbors = all_neighbors - node_set
            
            if external_neighbors:
                boundary.append(node)
        
        return boundary
    
    def _calculate_internal_connectivity(self, graph: nx.DiGraph, nodes: List[str],
                                          node_set: Set[str]) -> float:
        """Calculate how well-connected nodes are within the zone."""
        if len(nodes) < 2:
            return 1.0
        
        internal_edges = 0
        total_possible = len(nodes) * (len(nodes) - 1)  # Directed graph
        
        for node in nodes:
            for neighbor in graph.successors(node):
                if neighbor in node_set:
                    internal_edges += 1
        
        return internal_edges / total_possible if total_possible > 0 else 0.0
