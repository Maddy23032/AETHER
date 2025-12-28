"""
Graph Router - API endpoints for Dynamic Graph Sitemap

Provides REST API for:
- Graph session management
- Node/edge CRUD operations
- Layout computation
- Security analysis (PageRank, risk scores, zones)
- Attack path analysis
- Export functionality
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging

from ..services.graph import GraphService, get_graph_service
from ..services.graph.graph_service import LayoutType
from ..services.graph.algorithms import NodeRiskScore, AttackPath, FunctionalZone

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["Graph Sitemap"])


# ==================== REQUEST/RESPONSE MODELS ====================

class CreateSessionRequest(BaseModel):
    target_domain: str = Field(..., description="Primary target domain for the graph")
    scan_ids: Optional[List[str]] = Field(None, description="Scan IDs to include in graph")


class CreateSessionResponse(BaseModel):
    session_id: str
    target_domain: str
    message: str


class AddNodeRequest(BaseModel):
    node_id: str = Field(..., description="Unique node identifier")
    label: str = Field(..., description="Display label for the node")
    node_type: str = Field(..., description="Type of node (domain, ip_address, endpoint, etc.)")
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional node properties")
    source_scan_id: Optional[str] = Field(None, description="ID of source scan")


class AddEdgeRequest(BaseModel):
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    edge_type: str = Field(..., description="Type of relationship")
    weight: float = Field(1.0, description="Edge weight")
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional edge properties")
    is_bidirectional: bool = Field(False, description="Whether edge goes both ways")
    is_inferred: bool = Field(False, description="Whether edge was inferred")
    source_scan_id: Optional[str] = Field(None, description="ID of source scan")


class UpdateNodeRequest(BaseModel):
    updates: Dict[str, Any] = Field(..., description="Properties to update")


class LayoutRequest(BaseModel):
    layout_type: str = Field("force", description="Layout algorithm: force, hierarchical, radial, cluster, timeline")


class IngestScanRequest(BaseModel):
    scan_type: str = Field(..., description="Type of scan: recon, enum, mobile")
    scan_data: Dict[str, Any] = Field(..., description="Full scan data object")


class NodeResponse(BaseModel):
    id: str
    label: str
    node_type: str
    risk_score: float
    vulnerability_count: int
    max_severity: float
    is_external: bool
    position_x: float
    position_y: float
    properties: Dict[str, Any]


class EdgeResponse(BaseModel):
    id: str
    source_id: str
    target_id: str
    edge_type: str
    weight: float
    is_inferred: bool


class RiskScoreResponse(BaseModel):
    node_id: str
    total_score: float
    intrinsic_risk: float
    propagated_risk: float
    exposure_factor: float
    criticality_factor: float


class AttackPathResponse(BaseModel):
    path_id: str
    nodes: List[str]
    total_risk: float
    entry_point: str
    target: str
    exploitability_score: float
    impact_score: float


class ZoneResponse(BaseModel):
    zone_id: str
    zone_name: str
    zone_type: str
    nodes: List[str]
    aggregate_risk: float
    boundary_nodes: List[str]
    internal_connectivity: float


class GraphStatsResponse(BaseModel):
    total_nodes: int
    total_edges: int
    node_type_distribution: Dict[str, int]
    edge_type_distribution: Dict[str, int]
    avg_degree: float
    density: float
    connected_components: int
    high_risk_nodes: int
    vulnerability_hotspots: List[str]


# ==================== SESSION ENDPOINTS ====================

@router.post("/session", response_model=CreateSessionResponse)
async def create_session(request: CreateSessionRequest):
    """
    Create a new graph session for a target domain.
    
    This initializes an empty graph that can be populated with scan data.
    """
    try:
        service = get_graph_service()
        session_id = service.create_session(
            target_domain=request.target_domain,
            scan_ids=request.scan_ids
        )
        
        return CreateSessionResponse(
            session_id=session_id,
            target_domain=request.target_domain,
            message="Graph session created successfully"
        )
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/session")
async def get_session_info():
    """Get current session information."""
    service = get_graph_service()
    
    if not service.session_id:
        raise HTTPException(status_code=404, detail="No active session")
    
    return {
        "session_id": service.session_id,
        "created_at": service.created_at.isoformat() if service.created_at else None,
        "target_domain": service.graph.graph.get('target_domain'),
        "node_count": len(service.nodes),
        "edge_count": len(service.edges)
    }


# ==================== NODE ENDPOINTS ====================

@router.get("/nodes", response_model=List[NodeResponse])
async def get_all_nodes():
    """Get all nodes in the graph."""
    service = get_graph_service()
    
    return [
        NodeResponse(
            id=node.id,
            label=node.label,
            node_type=node.node_type,
            risk_score=node.risk_score,
            vulnerability_count=node.vulnerability_count,
            max_severity=node.max_severity,
            is_external=node.is_external,
            position_x=node.position_x,
            position_y=node.position_y,
            properties=node.properties
        )
        for node in service.nodes.values()
    ]


@router.get("/nodes/{node_id}", response_model=NodeResponse)
async def get_node(node_id: str):
    """Get a specific node by ID."""
    service = get_graph_service()
    
    if node_id not in service.nodes:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    
    node = service.nodes[node_id]
    return NodeResponse(
        id=node.id,
        label=node.label,
        node_type=node.node_type,
        risk_score=node.risk_score,
        vulnerability_count=node.vulnerability_count,
        max_severity=node.max_severity,
        is_external=node.is_external,
        position_x=node.position_x,
        position_y=node.position_y,
        properties=node.properties
    )


@router.post("/nodes", response_model=NodeResponse)
async def add_node(request: AddNodeRequest):
    """Add a new node to the graph."""
    service = get_graph_service()
    
    if request.node_id in service.nodes:
        raise HTTPException(status_code=400, detail=f"Node {request.node_id} already exists")
    
    node = service.add_node(
        node_id=request.node_id,
        label=request.label,
        node_type=request.node_type,
        properties=request.properties,
        source_scan_id=request.source_scan_id
    )
    
    return NodeResponse(
        id=node.id,
        label=node.label,
        node_type=node.node_type,
        risk_score=node.risk_score,
        vulnerability_count=node.vulnerability_count,
        max_severity=node.max_severity,
        is_external=node.is_external,
        position_x=node.position_x,
        position_y=node.position_y,
        properties=node.properties
    )


@router.put("/nodes/{node_id}", response_model=NodeResponse)
async def update_node(node_id: str, request: UpdateNodeRequest):
    """Update an existing node."""
    service = get_graph_service()
    
    node = service.update_node(node_id, request.updates)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    
    return NodeResponse(
        id=node.id,
        label=node.label,
        node_type=node.node_type,
        risk_score=node.risk_score,
        vulnerability_count=node.vulnerability_count,
        max_severity=node.max_severity,
        is_external=node.is_external,
        position_x=node.position_x,
        position_y=node.position_y,
        properties=node.properties
    )


@router.delete("/nodes/{node_id}")
async def delete_node(node_id: str):
    """Delete a node and all its edges."""
    service = get_graph_service()
    
    if not service.remove_node(node_id):
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    
    return {"message": f"Node {node_id} deleted successfully"}


# ==================== EDGE ENDPOINTS ====================

@router.get("/edges", response_model=List[EdgeResponse])
async def get_all_edges():
    """Get all edges in the graph."""
    service = get_graph_service()
    
    return [
        EdgeResponse(
            id=edge.id,
            source_id=edge.source_id,
            target_id=edge.target_id,
            edge_type=edge.edge_type,
            weight=edge.weight,
            is_inferred=edge.is_inferred
        )
        for edge in service.edges.values()
    ]


@router.post("/edges", response_model=EdgeResponse)
async def add_edge(request: AddEdgeRequest):
    """Add a new edge to the graph."""
    service = get_graph_service()
    
    edge = service.add_edge(
        source_id=request.source_id,
        target_id=request.target_id,
        edge_type=request.edge_type,
        weight=request.weight,
        properties=request.properties,
        is_bidirectional=request.is_bidirectional,
        is_inferred=request.is_inferred,
        source_scan_id=request.source_scan_id
    )
    
    if not edge:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot add edge: source or target node doesn't exist"
        )
    
    return EdgeResponse(
        id=edge.id,
        source_id=edge.source_id,
        target_id=edge.target_id,
        edge_type=edge.edge_type,
        weight=edge.weight,
        is_inferred=edge.is_inferred
    )


@router.delete("/edges/{edge_id}")
async def delete_edge(edge_id: str):
    """Delete an edge."""
    service = get_graph_service()
    
    if not service.remove_edge(edge_id):
        raise HTTPException(status_code=404, detail=f"Edge {edge_id} not found")
    
    return {"message": f"Edge {edge_id} deleted successfully"}


# ==================== SCAN INGESTION ====================

@router.post("/ingest")
async def ingest_scan(request: IngestScanRequest):
    """
    Ingest a scan into the graph.
    
    Automatically creates nodes and edges based on scan type.
    """
    service = get_graph_service()
    
    # Create session if not exists
    if not service.session_id:
        target = request.scan_data.get('target', 
                 request.scan_data.get('app_name', 'unknown'))
        service.create_session(target)
    
    try:
        if request.scan_type in ['recon', 'enum', 'enumeration']:
            count = service.ingest_recon_scan(request.scan_data)
        elif request.scan_type == 'mobile':
            count = service.ingest_mobile_scan(request.scan_data)
        else:
            raise HTTPException(
                status_code=400, 
                detail=f"Unknown scan type: {request.scan_type}"
            )
        
        return {
            "message": f"Scan ingested successfully",
            "elements_created": count,
            "total_nodes": len(service.nodes),
            "total_edges": len(service.edges)
        }
    except Exception as e:
        logger.error(f"Failed to ingest scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ingest/batch")
async def ingest_batch(scans: List[IngestScanRequest]):
    """Ingest multiple scans at once."""
    service = get_graph_service()
    
    total_elements = 0
    for scan in scans:
        try:
            if scan.scan_type in ['recon', 'enum']:
                total_elements += service.ingest_recon_scan(scan.scan_data)
            elif scan.scan_type == 'mobile':
                total_elements += service.ingest_mobile_scan(scan.scan_data)
        except Exception as e:
            logger.warning(f"Failed to ingest scan: {e}")
    
    return {
        "message": f"Batch ingestion complete",
        "total_elements_created": total_elements,
        "total_nodes": len(service.nodes),
        "total_edges": len(service.edges)
    }


# ==================== LAYOUT ====================

@router.post("/layout")
async def compute_layout(request: LayoutRequest):
    """
    Compute node positions using the specified layout algorithm.
    
    Available layouts:
    - force: Force-directed spring layout
    - hierarchical: Tree-like layout with domains at top
    - radial: Circular layout with high-risk nodes at center
    - cluster: Groups nodes by functional zones
    - timeline: Arranges by creation time
    """
    service = get_graph_service()
    
    try:
        layout_type = LayoutType(request.layout_type)
    except ValueError:
        layout_type = LayoutType.FORCE
    
    positions = service.compute_layout(layout_type)
    
    return {
        "layout_type": request.layout_type,
        "positions": {
            node_id: {"x": pos[0], "y": pos[1]}
            for node_id, pos in positions.items()
        }
    }


# ==================== ANALYSIS ====================

@router.get("/analysis/pagerank")
async def get_pagerank_scores():
    """
    Get Security-Aware PageRank scores for all nodes.
    
    Higher scores indicate more security-critical nodes.
    """
    service = get_graph_service()
    scores = service.get_pagerank_scores()
    
    # Sort by score descending
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "algorithm": "Security-Aware PageRank",
        "scores": [
            {"node_id": node_id, "score": score}
            for node_id, score in sorted_scores
        ]
    }


@router.get("/analysis/risk", response_model=List[RiskScoreResponse])
async def get_risk_scores():
    """
    Get comprehensive risk scores for all nodes.
    
    Includes intrinsic risk, propagated risk, and exposure factors.
    """
    service = get_graph_service()
    risk_scores = service.get_risk_scores()
    
    # Sort by total score descending
    sorted_risks = sorted(
        risk_scores.values(), 
        key=lambda x: x.total_score, 
        reverse=True
    )
    
    return [
        RiskScoreResponse(
            node_id=r.node_id,
            total_score=r.total_score,
            intrinsic_risk=r.intrinsic_risk,
            propagated_risk=r.propagated_risk,
            exposure_factor=r.exposure_factor,
            criticality_factor=r.criticality_factor
        )
        for r in sorted_risks
    ]


@router.get("/analysis/zones", response_model=List[ZoneResponse])
async def get_functional_zones():
    """
    Get functional security zones.
    
    Nodes are clustered into zones like 'perimeter', 'authentication', 
    'api', 'data', etc.
    """
    service = get_graph_service()
    zones = service.get_functional_zones()
    
    return [
        ZoneResponse(
            zone_id=z.zone_id,
            zone_name=z.zone_name,
            zone_type=z.zone_type,
            nodes=z.nodes,
            aggregate_risk=z.aggregate_risk,
            boundary_nodes=z.boundary_nodes,
            internal_connectivity=z.internal_connectivity
        )
        for z in zones
    ]


@router.get("/analysis/attack-paths", response_model=List[AttackPathResponse])
async def get_attack_paths(max_paths: int = Query(10, ge=1, le=50)):
    """
    Get potential attack paths through the infrastructure.
    
    Identifies paths from entry points to high-value targets,
    ranked by total risk.
    """
    service = get_graph_service()
    paths = service.get_attack_paths()
    
    return [
        AttackPathResponse(
            path_id=p.path_id,
            nodes=p.nodes,
            total_risk=p.total_risk,
            entry_point=p.entry_point,
            target=p.target,
            exploitability_score=p.exploitability_score,
            impact_score=p.impact_score
        )
        for p in paths[:max_paths]
    ]


@router.get("/stats", response_model=GraphStatsResponse)
async def get_graph_stats():
    """Get comprehensive graph statistics."""
    service = get_graph_service()
    stats = service.get_stats()
    
    return GraphStatsResponse(
        total_nodes=stats.total_nodes,
        total_edges=stats.total_edges,
        node_type_distribution=stats.node_type_distribution,
        edge_type_distribution=stats.edge_type_distribution,
        avg_degree=stats.avg_degree,
        density=stats.density,
        connected_components=stats.connected_components,
        high_risk_nodes=stats.high_risk_nodes,
        vulnerability_hotspots=stats.vulnerability_hotspots
    )


# ==================== EXPORT ====================

@router.get("/export/cytoscape")
async def export_cytoscape():
    """
    Export graph in Cytoscape.js format.
    
    This is the primary format for frontend visualization.
    """
    service = get_graph_service()
    return service.to_cytoscape_json()


@router.get("/export/json")
async def export_json():
    """Export graph as JSON string."""
    service = get_graph_service()
    return {"data": service.to_json()}


@router.get("/export/gexf")
async def export_gexf():
    """
    Export graph in GEXF format for Gephi.
    
    Use this for advanced analysis in external tools.
    """
    service = get_graph_service()
    return {"gexf": service.to_gexf()}


# ==================== RESET ====================

@router.post("/reset")
async def reset_graph():
    """Clear the current graph and start fresh."""
    service = get_graph_service()
    service.graph.clear()
    service.nodes.clear()
    service.edges.clear()
    service._invalidate_cache()
    service.session_id = None
    service.created_at = None
    
    return {"message": "Graph reset successfully"}
