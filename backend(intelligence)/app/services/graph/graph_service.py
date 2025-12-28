"""
Graph Service - Core service for Dynamic Graph Sitemap

This service manages the security infrastructure graph, providing:
- Graph construction from scan data
- Layout computation (force, hierarchical, radial)
- Node/edge management with real-time updates
- Integration with security analysis algorithms
- Export capabilities (JSON, GEXF, Cytoscape format)

The graph service acts as the central hub for all graph-related operations.
"""

import networkx as nx
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import math
import logging

from .algorithms import (
    SecurityAwarePageRank,
    VulnerabilityPropagation,
    FunctionalZoneClustering,
    NodeType,
    EdgeType,
    NodeRiskScore,
    AttackPath,
    FunctionalZone
)

logger = logging.getLogger(__name__)


class LayoutType(str, Enum):
    """Available graph layout algorithms"""
    FORCE = "force"
    HIERARCHICAL = "hierarchical"
    RADIAL = "radial"
    CLUSTER = "cluster"
    TIMELINE = "timeline"


@dataclass
class GraphNode:
    """Represents a node in the security graph"""
    id: str
    label: str
    node_type: str
    properties: Dict[str, Any]
    position_x: float = 0.0
    position_y: float = 0.0
    risk_score: float = 0.0
    vulnerability_count: int = 0
    max_severity: float = 0.0
    is_external: bool = False
    source_scan_id: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


@dataclass
class GraphEdge:
    """Represents an edge in the security graph"""
    id: str
    source_id: str
    target_id: str
    edge_type: str
    weight: float = 1.0
    properties: Dict[str, Any] = None
    is_bidirectional: bool = False
    is_inferred: bool = False
    source_scan_id: Optional[str] = None
    created_at: str = ""


@dataclass
class GraphStats:
    """Statistics about the current graph state"""
    total_nodes: int
    total_edges: int
    node_type_distribution: Dict[str, int]
    edge_type_distribution: Dict[str, int]
    avg_degree: float
    density: float
    connected_components: int
    high_risk_nodes: int
    vulnerability_hotspots: List[str]


class GraphService:
    """
    Core service for managing the security infrastructure graph.
    
    Provides:
    - Graph construction and manipulation
    - Multiple layout algorithms
    - Security analysis integration
    - Real-time updates
    - Export/Import functionality
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.session_id: Optional[str] = None
        self.created_at: Optional[datetime] = None
        
        # Algorithm instances
        self.pagerank = SecurityAwarePageRank()
        self.risk_propagation = VulnerabilityPropagation()
        self.zone_clustering = FunctionalZoneClustering()
        
        # Cache for computed values
        self._pagerank_cache: Dict[str, float] = {}
        self._risk_cache: Dict[str, NodeRiskScore] = {}
        self._zones_cache: List[FunctionalZone] = []
        self._attack_paths_cache: List[AttackPath] = []
        self._cache_valid = False
    
    def create_session(self, target_domain: str, scan_ids: List[str] = None) -> str:
        """Create a new graph session."""
        self.session_id = str(uuid.uuid4())
        self.created_at = datetime.utcnow()
        self.graph.clear()
        self.nodes.clear()
        self.edges.clear()
        self._invalidate_cache()
        
        # Store session metadata
        self.graph.graph['session_id'] = self.session_id
        self.graph.graph['target_domain'] = target_domain
        self.graph.graph['scan_ids'] = scan_ids or []
        self.graph.graph['created_at'] = self.created_at.isoformat()
        
        logger.info(f"Created new graph session: {self.session_id} for {target_domain}")
        return self.session_id
    
    def add_node(self, node_id: str, label: str, node_type: str,
                 properties: Dict[str, Any] = None, source_scan_id: str = None) -> GraphNode:
        """Add a node to the graph."""
        now = datetime.utcnow().isoformat()
        
        node = GraphNode(
            id=node_id,
            label=label,
            node_type=node_type,
            properties=properties or {},
            vulnerability_count=properties.get('vulnerability_count', 0) if properties else 0,
            max_severity=properties.get('max_severity', 0) if properties else 0,
            is_external=properties.get('is_external', False) if properties else False,
            source_scan_id=source_scan_id,
            created_at=now,
            updated_at=now
        )
        
        self.nodes[node_id] = node
        
        # Add to NetworkX graph - filter out keys we're already passing explicitly
        filtered_props = {k: v for k, v in (properties or {}).items() 
                         if k not in ('vulnerability_count', 'max_severity', 'is_external')}
        self.graph.add_node(
            node_id,
            label=label,
            node_type=node_type,
            vulnerability_count=node.vulnerability_count,
            max_severity=node.max_severity,
            is_external=node.is_external,
            **filtered_props
        )
        
        self._invalidate_cache()
        return node
    
    def add_edge(self, source_id: str, target_id: str, edge_type: str,
                 weight: float = 1.0, properties: Dict[str, Any] = None,
                 is_bidirectional: bool = False, is_inferred: bool = False,
                 source_scan_id: str = None) -> Optional[GraphEdge]:
        """Add an edge to the graph."""
        # Ensure nodes exist
        if source_id not in self.nodes or target_id not in self.nodes:
            logger.warning(f"Cannot add edge: nodes {source_id} or {target_id} don't exist")
            return None
        
        edge_id = f"{source_id}--{edge_type}--{target_id}"
        now = datetime.utcnow().isoformat()
        
        edge = GraphEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            properties=properties or {},
            is_bidirectional=is_bidirectional,
            is_inferred=is_inferred,
            source_scan_id=source_scan_id,
            created_at=now
        )
        
        self.edges[edge_id] = edge
        
        # Add to NetworkX graph
        self.graph.add_edge(
            source_id, target_id,
            edge_id=edge_id,
            edge_type=edge_type,
            weight=weight,
            is_inferred=is_inferred,
            **(properties or {})
        )
        
        # Add reverse edge if bidirectional
        if is_bidirectional:
            reverse_id = f"{target_id}--{edge_type}--{source_id}"
            self.graph.add_edge(
                target_id, source_id,
                edge_id=reverse_id,
                edge_type=edge_type,
                weight=weight,
                is_inferred=is_inferred,
                **(properties or {})
            )
        
        self._invalidate_cache()
        return edge
    
    def update_node(self, node_id: str, updates: Dict[str, Any]) -> Optional[GraphNode]:
        """Update node properties."""
        if node_id not in self.nodes:
            return None
        
        node = self.nodes[node_id]
        
        # Update fields
        for key, value in updates.items():
            if hasattr(node, key):
                setattr(node, key, value)
            node.properties[key] = value
        
        node.updated_at = datetime.utcnow().isoformat()
        
        # Update NetworkX graph
        for key, value in updates.items():
            self.graph.nodes[node_id][key] = value
        
        self._invalidate_cache()
        return node
    
    def remove_node(self, node_id: str) -> bool:
        """Remove a node and all its edges."""
        if node_id not in self.nodes:
            return False
        
        # Remove associated edges
        edges_to_remove = [
            eid for eid, edge in self.edges.items()
            if edge.source_id == node_id or edge.target_id == node_id
        ]
        for eid in edges_to_remove:
            del self.edges[eid]
        
        # Remove from NetworkX
        self.graph.remove_node(node_id)
        
        # Remove from our dict
        del self.nodes[node_id]
        
        self._invalidate_cache()
        return True
    
    def remove_edge(self, edge_id: str) -> bool:
        """Remove an edge."""
        if edge_id not in self.edges:
            return False
        
        edge = self.edges[edge_id]
        
        # Remove from NetworkX
        if self.graph.has_edge(edge.source_id, edge.target_id):
            self.graph.remove_edge(edge.source_id, edge.target_id)
        
        # Remove from our dict
        del self.edges[edge_id]
        
        self._invalidate_cache()
        return True
    
    # ==================== SCAN DATA INGESTION ====================
    
    def ingest_recon_scan(self, scan_data: Dict[str, Any]) -> int:
        """
        Ingest reconnaissance scan results into the graph.
        
        Returns number of nodes/edges created.
        """
        scan_id = scan_data.get('id', str(uuid.uuid4()))
        target = scan_data.get('target', 'unknown')
        results = scan_data.get('results', {})
        
        nodes_created = 0
        edges_created = 0
        
        # Add main domain node
        domain_id = f"domain:{target}"
        self.add_node(
            node_id=domain_id,
            label=target,
            node_type=NodeType.DOMAIN.value,
            properties={'target': target, 'is_external': True},
            source_scan_id=scan_id
        )
        nodes_created += 1
        
        # Process subdomains
        subdomains = results.get('subdomains', [])
        for subdomain in subdomains:
            if isinstance(subdomain, dict):
                sub_name = subdomain.get('subdomain', subdomain.get('name', ''))
            else:
                sub_name = str(subdomain)
            
            if sub_name:
                sub_id = f"subdomain:{sub_name}"
                self.add_node(
                    node_id=sub_id,
                    label=sub_name,
                    node_type=NodeType.SUBDOMAIN.value,
                    properties={'subdomain': sub_name, 'is_external': True},
                    source_scan_id=scan_id
                )
                nodes_created += 1
                
                self.add_edge(
                    source_id=domain_id,
                    target_id=sub_id,
                    edge_type=EdgeType.HAS_SUBDOMAIN.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process DNS records (IP addresses)
        dns_records = results.get('dns', [])
        for record in dns_records:
            if isinstance(record, dict):
                ip = record.get('ip', record.get('address', ''))
                record_type = record.get('type', 'A')
            else:
                ip = str(record)
                record_type = 'A'
            
            if ip:
                ip_id = f"ip:{ip}"
                if ip_id not in self.nodes:
                    self.add_node(
                        node_id=ip_id,
                        label=ip,
                        node_type=NodeType.IP_ADDRESS.value,
                        properties={'ip_address': ip, 'record_type': record_type},
                        source_scan_id=scan_id
                    )
                    nodes_created += 1
                
                self.add_edge(
                    source_id=domain_id,
                    target_id=ip_id,
                    edge_type=EdgeType.RESOLVES_TO.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process ports/services
        ports = results.get('ports', [])
        for port_info in ports:
            if isinstance(port_info, dict):
                port = port_info.get('port', port_info.get('number', 0))
                service = port_info.get('service', 'unknown')
                state = port_info.get('state', 'open')
            else:
                port = int(port_info) if str(port_info).isdigit() else 0
                service = 'unknown'
                state = 'open'
            
            if port:
                port_id = f"port:{target}:{port}"
                self.add_node(
                    node_id=port_id,
                    label=f"{port}/{service}",
                    node_type=NodeType.PORT_SERVICE.value,
                    properties={'port': port, 'service': service, 'state': state},
                    source_scan_id=scan_id
                )
                nodes_created += 1
                
                self.add_edge(
                    source_id=domain_id,
                    target_id=port_id,
                    edge_type=EdgeType.HOSTS_SERVICE.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process technologies
        technologies = results.get('technologies', [])
        for tech in technologies:
            if isinstance(tech, dict):
                tech_name = tech.get('name', tech.get('technology', ''))
                version = tech.get('version', '')
            else:
                tech_name = str(tech)
                version = ''
            
            if tech_name:
                tech_id = f"tech:{tech_name.lower().replace(' ', '_')}"
                if tech_id not in self.nodes:
                    self.add_node(
                        node_id=tech_id,
                        label=f"{tech_name} {version}".strip(),
                        node_type=NodeType.TECHNOLOGY.value,
                        properties={'technology': tech_name, 'version': version},
                        source_scan_id=scan_id
                    )
                    nodes_created += 1
                
                self.add_edge(
                    source_id=domain_id,
                    target_id=tech_id,
                    edge_type=EdgeType.USES_TECHNOLOGY.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process endpoints/URLs
        endpoints = results.get('endpoints', results.get('urls', []))
        for endpoint in endpoints[:50]:  # Limit to prevent graph explosion
            if isinstance(endpoint, dict):
                url = endpoint.get('url', endpoint.get('path', ''))
                method = endpoint.get('method', 'GET')
            else:
                url = str(endpoint)
                method = 'GET'
            
            if url:
                endpoint_id = f"endpoint:{hash(url) % 100000}"
                self.add_node(
                    node_id=endpoint_id,
                    label=url[:50] + '...' if len(url) > 50 else url,
                    node_type=NodeType.ENDPOINT.value,
                    properties={'url': url, 'method': method},
                    source_scan_id=scan_id
                )
                nodes_created += 1
                
                self.add_edge(
                    source_id=domain_id,
                    target_id=endpoint_id,
                    edge_type=EdgeType.SERVES_ENDPOINT.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln_name = vuln.get('name', vuln.get('title', 'Unknown Vulnerability'))
                severity = vuln.get('severity', vuln.get('cvss', 0))
                affected = vuln.get('affected', vuln.get('location', target))
            else:
                vuln_name = str(vuln)
                severity = 5.0
                affected = target
            
            vuln_id = f"vuln:{hash(vuln_name) % 100000}"
            self.add_node(
                node_id=vuln_id,
                label=vuln_name[:40],
                node_type=NodeType.VULNERABILITY.value,
                properties={
                    'vulnerability': vuln_name,
                    'severity': float(severity) if severity else 5.0,
                    'affected': affected
                },
                source_scan_id=scan_id
            )
            nodes_created += 1
            
            # Link to affected component
            self.add_edge(
                source_id=domain_id,
                target_id=vuln_id,
                edge_type=EdgeType.HAS_VULNERABILITY.value,
                source_scan_id=scan_id
            )
            edges_created += 1
        
        logger.info(f"Ingested recon scan: {nodes_created} nodes, {edges_created} edges")
        return nodes_created + edges_created
    
    def ingest_mobile_scan(self, scan_data: Dict[str, Any]) -> int:
        """Ingest mobile APK/IPA scan results into the graph."""
        scan_id = scan_data.get('id', str(uuid.uuid4()))
        app_name = scan_data.get('app_name', 'Unknown App')
        package_name = scan_data.get('package_name', '')
        
        nodes_created = 0
        edges_created = 0
        
        # Add main app node
        app_id = f"mobile_app:{package_name or app_name}"
        self.add_node(
            node_id=app_id,
            label=app_name,
            node_type="mobile_endpoint",
            properties={
                'app_name': app_name,
                'package_name': package_name,
                'version': scan_data.get('version', ''),
                'platform': scan_data.get('platform', 'android')
            },
            source_scan_id=scan_id
        )
        nodes_created += 1
        
        # Process permissions
        permissions = scan_data.get('permissions', [])
        for perm in permissions[:20]:
            if isinstance(perm, dict):
                perm_name = perm.get('name', perm.get('permission', ''))
                status = perm.get('status', 'granted')
            else:
                perm_name = str(perm)
                status = 'granted'
            
            if perm_name:
                perm_id = f"permission:{hash(perm_name) % 100000}"
                self.add_node(
                    node_id=perm_id,
                    label=perm_name.split('.')[-1],
                    node_type="parameter",
                    properties={'permission': perm_name, 'status': status},
                    source_scan_id=scan_id
                )
                nodes_created += 1
                
                self.add_edge(
                    source_id=app_id,
                    target_id=perm_id,
                    edge_type=EdgeType.ACCEPTS_PARAMETER.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        # Process security issues
        issues = scan_data.get('security_issues', [])
        for issue in issues:
            if isinstance(issue, dict):
                issue_title = issue.get('title', issue.get('name', 'Security Issue'))
                severity = issue.get('severity', 'medium')
            else:
                issue_title = str(issue)
                severity = 'medium'
            
            severity_score = {'critical': 9.0, 'high': 7.5, 'medium': 5.0, 'low': 2.5}.get(
                severity.lower() if isinstance(severity, str) else 'medium', 5.0
            )
            
            issue_id = f"mobile_vuln:{hash(issue_title) % 100000}"
            self.add_node(
                node_id=issue_id,
                label=issue_title[:40],
                node_type=NodeType.VULNERABILITY.value,
                properties={
                    'vulnerability': issue_title,
                    'severity': severity_score,
                    'severity_label': severity
                },
                source_scan_id=scan_id
            )
            nodes_created += 1
            
            self.add_edge(
                source_id=app_id,
                target_id=issue_id,
                edge_type=EdgeType.HAS_VULNERABILITY.value,
                source_scan_id=scan_id
            )
            edges_created += 1
        
        # Process network endpoints found
        urls = scan_data.get('urls', scan_data.get('network_calls', []))
        for url in urls[:30]:
            url_str = url if isinstance(url, str) else url.get('url', '')
            if url_str:
                api_id = f"mobile_api:{hash(url_str) % 100000}"
                self.add_node(
                    node_id=api_id,
                    label=url_str[:50],
                    node_type=NodeType.API_ENDPOINT.value,
                    properties={'url': url_str},
                    source_scan_id=scan_id
                )
                nodes_created += 1
                
                self.add_edge(
                    source_id=app_id,
                    target_id=api_id,
                    edge_type=EdgeType.CALLS_API.value,
                    source_scan_id=scan_id
                )
                edges_created += 1
        
        logger.info(f"Ingested mobile scan: {nodes_created} nodes, {edges_created} edges")
        return nodes_created + edges_created
    
    # ==================== LAYOUT COMPUTATION ====================
    
    def compute_layout(self, layout_type: LayoutType = LayoutType.FORCE) -> Dict[str, Tuple[float, float]]:
        """
        Compute node positions using the specified layout algorithm.
        
        Returns dictionary mapping node IDs to (x, y) coordinates.
        """
        if len(self.graph) == 0:
            return {}
        
        if layout_type == LayoutType.FORCE:
            positions = self._compute_force_layout()
        elif layout_type == LayoutType.HIERARCHICAL:
            positions = self._compute_hierarchical_layout()
        elif layout_type == LayoutType.RADIAL:
            positions = self._compute_radial_layout()
        elif layout_type == LayoutType.CLUSTER:
            positions = self._compute_cluster_layout()
        elif layout_type == LayoutType.TIMELINE:
            positions = self._compute_timeline_layout()
        else:
            positions = self._compute_force_layout()
        
        # Update node positions
        for node_id, (x, y) in positions.items():
            if node_id in self.nodes:
                self.nodes[node_id].position_x = x
                self.nodes[node_id].position_y = y
        
        return positions
    
    def _compute_force_layout(self) -> Dict[str, Tuple[float, float]]:
        """Force-directed layout using spring algorithm."""
        try:
            pos = nx.spring_layout(self.graph, k=2, iterations=50, scale=500)
            return {node: (float(x) * 1000, float(y) * 1000) for node, (x, y) in pos.items()}
        except Exception as e:
            logger.error(f"Force layout failed: {e}")
            return self._fallback_layout()
    
    def _compute_hierarchical_layout(self) -> Dict[str, Tuple[float, float]]:
        """Hierarchical layout with domains at top."""
        try:
            # Find root nodes (no incoming edges or domain type)
            roots = [n for n in self.graph.nodes() 
                    if self.graph.in_degree(n) == 0 or 
                    self.graph.nodes[n].get('node_type') == 'domain']
            
            if not roots:
                roots = list(self.graph.nodes())[:1]
            
            # BFS to assign levels
            levels: Dict[str, int] = {}
            for root in roots:
                self._assign_levels_bfs(root, levels, 0)
            
            # Position nodes by level
            positions = {}
            level_nodes: Dict[int, List[str]] = {}
            for node, level in levels.items():
                if level not in level_nodes:
                    level_nodes[level] = []
                level_nodes[level].append(node)
            
            y_spacing = 150
            for level, nodes in level_nodes.items():
                x_spacing = 1000 / (len(nodes) + 1)
                for i, node in enumerate(nodes):
                    positions[node] = ((i + 1) * x_spacing, level * y_spacing)
            
            return positions
        except Exception as e:
            logger.error(f"Hierarchical layout failed: {e}")
            return self._fallback_layout()
    
    def _assign_levels_bfs(self, root: str, levels: Dict[str, int], start_level: int):
        """Assign levels to nodes using BFS from root."""
        from collections import deque
        queue = deque([(root, start_level)])
        
        while queue:
            node, level = queue.popleft()
            if node in levels:
                continue
            levels[node] = level
            
            for successor in self.graph.successors(node):
                if successor not in levels:
                    queue.append((successor, level + 1))
    
    def _compute_radial_layout(self) -> Dict[str, Tuple[float, float]]:
        """Radial layout with high-risk nodes at center."""
        try:
            # Compute risk scores if not cached
            if not self._cache_valid:
                self._update_cache()
            
            # Sort by risk (highest in center)
            sorted_nodes = sorted(
                self.graph.nodes(),
                key=lambda n: self._risk_cache.get(n, NodeRiskScore(n, 0, 0, 0, 0, 0)).total_score,
                reverse=True
            )
            
            positions = {}
            center_x, center_y = 500, 500
            
            for i, node in enumerate(sorted_nodes):
                ring = i // 8  # 8 nodes per ring
                angle_offset = (i % 8) * (2 * math.pi / 8)
                radius = 50 + ring * 100
                
                x = center_x + radius * math.cos(angle_offset)
                y = center_y + radius * math.sin(angle_offset)
                positions[node] = (x, y)
            
            return positions
        except Exception as e:
            logger.error(f"Radial layout failed: {e}")
            return self._fallback_layout()
    
    def _compute_cluster_layout(self) -> Dict[str, Tuple[float, float]]:
        """Cluster layout grouping nodes by functional zones."""
        try:
            if not self._cache_valid:
                self._update_cache()
            
            zones = self._zones_cache
            positions = {}
            
            # Position each zone as a cluster
            zone_centers = []
            for i, zone in enumerate(zones):
                angle = i * (2 * math.pi / max(len(zones), 1))
                center_x = 500 + 300 * math.cos(angle)
                center_y = 500 + 300 * math.sin(angle)
                zone_centers.append((center_x, center_y))
                
                # Position nodes within zone
                for j, node in enumerate(zone.nodes):
                    inner_angle = j * (2 * math.pi / max(len(zone.nodes), 1))
                    radius = 50 + (j // 6) * 30
                    x = center_x + radius * math.cos(inner_angle)
                    y = center_y + radius * math.sin(inner_angle)
                    positions[node] = (x, y)
            
            # Handle orphan nodes
            orphans = [n for n in self.graph.nodes() if n not in positions]
            for i, node in enumerate(orphans):
                positions[node] = (100 + i * 50, 50)
            
            return positions
        except Exception as e:
            logger.error(f"Cluster layout failed: {e}")
            return self._fallback_layout()
    
    def _compute_timeline_layout(self) -> Dict[str, Tuple[float, float]]:
        """Timeline layout based on creation time."""
        try:
            # Sort nodes by creation time
            sorted_nodes = sorted(
                self.nodes.values(),
                key=lambda n: n.created_at
            )
            
            positions = {}
            y_by_type: Dict[str, float] = {}
            x = 50
            
            for node in sorted_nodes:
                if node.node_type not in y_by_type:
                    y_by_type[node.node_type] = len(y_by_type) * 100 + 50
                
                positions[node.id] = (x, y_by_type[node.node_type])
                x += 80
            
            return positions
        except Exception as e:
            logger.error(f"Timeline layout failed: {e}")
            return self._fallback_layout()
    
    def _fallback_layout(self) -> Dict[str, Tuple[float, float]]:
        """Simple grid layout as fallback."""
        positions = {}
        cols = max(int(math.sqrt(len(self.graph))), 1)
        
        for i, node in enumerate(self.graph.nodes()):
            x = (i % cols) * 100 + 50
            y = (i // cols) * 100 + 50
            positions[node] = (x, y)
        
        return positions
    
    # ==================== ANALYSIS ====================
    
    def _invalidate_cache(self):
        """Invalidate all computed caches."""
        self._cache_valid = False
        self._pagerank_cache = {}
        self._risk_cache = {}
        self._zones_cache = []
        self._attack_paths_cache = []
    
    def _update_cache(self):
        """Update all cached computations."""
        if self._cache_valid or len(self.graph) == 0:
            return
        
        # Compute PageRank
        self._pagerank_cache = self.pagerank.compute(self.graph)
        
        # Compute risk scores
        self._risk_cache = self.risk_propagation.compute(self.graph)
        
        # Compute zones
        self._zones_cache = self.zone_clustering.compute(self.graph)
        
        # Find attack paths
        self._attack_paths_cache = self.risk_propagation.find_attack_paths(
            self.graph, self._risk_cache
        )
        
        # Update node risk scores
        for node_id, risk in self._risk_cache.items():
            if node_id in self.nodes:
                self.nodes[node_id].risk_score = risk.total_score
        
        self._cache_valid = True
    
    def get_pagerank_scores(self) -> Dict[str, float]:
        """Get Security-Aware PageRank scores for all nodes."""
        if not self._cache_valid:
            self._update_cache()
        return self._pagerank_cache
    
    def get_risk_scores(self) -> Dict[str, NodeRiskScore]:
        """Get risk scores for all nodes."""
        if not self._cache_valid:
            self._update_cache()
        return self._risk_cache
    
    def get_functional_zones(self) -> List[FunctionalZone]:
        """Get functional zone clusters."""
        if not self._cache_valid:
            self._update_cache()
        return self._zones_cache
    
    def get_attack_paths(self) -> List[AttackPath]:
        """Get identified attack paths."""
        if not self._cache_valid:
            self._update_cache()
        return self._attack_paths_cache
    
    def get_stats(self) -> GraphStats:
        """Get graph statistics."""
        if len(self.graph) == 0:
            return GraphStats(
                total_nodes=0,
                total_edges=0,
                node_type_distribution={},
                edge_type_distribution={},
                avg_degree=0,
                density=0,
                connected_components=0,
                high_risk_nodes=0,
                vulnerability_hotspots=[]
            )
        
        # Node type distribution
        node_types = {}
        for node_id, node in self.nodes.items():
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        
        # Edge type distribution
        edge_types = {}
        for edge_id, edge in self.edges.items():
            edge_types[edge.edge_type] = edge_types.get(edge.edge_type, 0) + 1
        
        # Graph metrics
        avg_degree = sum(d for n, d in self.graph.degree()) / len(self.graph) if self.graph else 0
        density = nx.density(self.graph)
        
        # Connected components (convert to undirected)
        undirected = self.graph.to_undirected()
        components = nx.number_connected_components(undirected)
        
        # High risk nodes
        if not self._cache_valid:
            self._update_cache()
        
        high_risk = [
            nid for nid, risk in self._risk_cache.items()
            if risk.total_score > 5.0
        ]
        
        # Vulnerability hotspots
        hotspots = sorted(
            [(nid, risk.total_score) for nid, risk in self._risk_cache.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return GraphStats(
            total_nodes=len(self.nodes),
            total_edges=len(self.edges),
            node_type_distribution=node_types,
            edge_type_distribution=edge_types,
            avg_degree=avg_degree,
            density=density,
            connected_components=components,
            high_risk_nodes=len(high_risk),
            vulnerability_hotspots=[h[0] for h in hotspots]
        )
    
    # ==================== EXPORT ====================
    
    def to_cytoscape_json(self) -> Dict[str, Any]:
        """
        Export graph to Cytoscape.js compatible JSON format.
        
        This format is directly usable by the frontend visualization.
        """
        if not self._cache_valid:
            self._update_cache()
        
        # Compute layout if positions not set
        positions = self.compute_layout(LayoutType.FORCE)
        
        elements = []
        
        # Add nodes
        for node_id, node in self.nodes.items():
            risk = self._risk_cache.get(node_id, NodeRiskScore(node_id, 0, 0, 0, 0, 1))
            pagerank = self._pagerank_cache.get(node_id, 0)
            
            pos = positions.get(node_id, (0, 0))
            
            elements.append({
                "data": {
                    "id": node_id,
                    "label": node.label,
                    "nodeType": node.node_type,
                    "riskScore": risk.total_score,
                    "intrinsicRisk": risk.intrinsic_risk,
                    "propagatedRisk": risk.propagated_risk,
                    "pagerank": pagerank,
                    "vulnerabilityCount": node.vulnerability_count,
                    "maxSeverity": node.max_severity,
                    "isExternal": node.is_external,
                    **node.properties
                },
                "position": {
                    "x": pos[0],
                    "y": pos[1]
                },
                "classes": f"{node.node_type} {'high-risk' if risk.total_score > 7 else 'medium-risk' if risk.total_score > 4 else 'low-risk'}"
            })
        
        # Add edges
        for edge_id, edge in self.edges.items():
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "edgeType": edge.edge_type,
                    "weight": edge.weight,
                    "isInferred": edge.is_inferred,
                    **(edge.properties or {})
                },
                "classes": f"{edge.edge_type} {'inferred' if edge.is_inferred else ''}"
            })
        
        return {
            "elements": elements,
            "stats": asdict(self.get_stats()),
            "zones": [asdict(z) for z in self._zones_cache],
            "attackPaths": [asdict(p) for p in self._attack_paths_cache[:5]],
            "sessionId": self.session_id,
            "createdAt": self.created_at.isoformat() if self.created_at else None
        }
    
    def to_gexf(self) -> str:
        """Export graph to GEXF format for Gephi."""
        import io
        output = io.BytesIO()
        nx.write_gexf(self.graph, output)
        return output.getvalue().decode('utf-8')
    
    def to_json(self) -> str:
        """Export graph to JSON format."""
        return json.dumps(self.to_cytoscape_json(), indent=2)


# Global instance
_graph_service: Optional[GraphService] = None


def get_graph_service() -> GraphService:
    """Get or create the global graph service instance."""
    global _graph_service
    if _graph_service is None:
        _graph_service = GraphService()
    return _graph_service
