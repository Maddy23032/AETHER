/**
 * Graph Sitemap Service
 * 
 * Frontend service for interacting with the Dynamic Graph Sitemap API.
 * Provides methods for:
 * - Graph session management
 * - Node/edge operations
 * - Layout computation
 * - Security analysis (PageRank, risk scores, zones, attack paths)
 * - Data ingestion and export
 */

const API_BASE = 'http://localhost:8002/api/intelligence/graph';

// ==================== TYPES ====================

export type NodeType = 
  | 'domain'
  | 'subdomain'
  | 'ip_address'
  | 'port_service'
  | 'endpoint'
  | 'parameter'
  | 'vulnerability'
  | 'technology'
  | 'certificate'
  | 'api_endpoint'
  | 'third_party_service'
  | 'authentication_point'
  | 'file_resource'
  | 'mobile_endpoint';

export type EdgeType =
  | 'resolves_to'
  | 'has_subdomain'
  | 'hosts_service'
  | 'serves_endpoint'
  | 'accepts_parameter'
  | 'has_vulnerability'
  | 'uses_technology'
  | 'authenticates_via'
  | 'calls_api'
  | 'integrates_with'
  | 'leads_to'
  | 'protected_by'
  | 'exposes_data'
  | 'inferred';

export type LayoutType = 'force' | 'hierarchical' | 'radial' | 'cluster' | 'timeline';

export interface GraphNode {
  id: string;
  label: string;
  node_type: NodeType;
  risk_score: number;
  vulnerability_count: number;
  max_severity: number;
  is_external: boolean;
  position_x: number;
  position_y: number;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: EdgeType;
  weight: number;
  is_inferred: boolean;
}

export interface RiskScore {
  node_id: string;
  total_score: number;
  intrinsic_risk: number;
  propagated_risk: number;
  exposure_factor: number;
  criticality_factor: number;
}

export interface AttackPath {
  path_id: string;
  nodes: string[];
  total_risk: number;
  entry_point: string;
  target: string;
  exploitability_score: number;
  impact_score: number;
}

export interface FunctionalZone {
  zone_id: string;
  zone_name: string;
  zone_type: string;
  nodes: string[];
  aggregate_risk: number;
  boundary_nodes: string[];
  internal_connectivity: number;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  node_type_distribution: Record<string, number>;
  edge_type_distribution: Record<string, number>;
  avg_degree: number;
  density: number;
  connected_components: number;
  high_risk_nodes: number;
  vulnerability_hotspots: string[];
}

export interface CytoscapeElement {
  data: {
    id: string;
    label?: string;
    source?: string;
    target?: string;
    nodeType?: string;
    edgeType?: string;
    riskScore?: number;
    pagerank?: number;
    [key: string]: unknown;
  };
  position?: {
    x: number;
    y: number;
  };
  classes?: string;
}

export interface CytoscapeGraph {
  elements: CytoscapeElement[];
  stats: GraphStats;
  zones: FunctionalZone[];
  attackPaths: AttackPath[];
  sessionId: string | null;
  createdAt: string | null;
}

export interface SessionInfo {
  session_id: string;
  created_at: string;
  target_domain: string;
  node_count: number;
  edge_count: number;
}

// ==================== API FUNCTIONS ====================

/**
 * Create a new graph session for a target domain
 */
export async function createSession(
  targetDomain: string, 
  scanIds?: string[]
): Promise<{ session_id: string; target_domain: string; message: string }> {
  const response = await fetch(`${API_BASE}/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_domain: targetDomain, scan_ids: scanIds }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to create session: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get current session information
 */
export async function getSessionInfo(): Promise<SessionInfo> {
  const response = await fetch(`${API_BASE}/session`);
  
  if (!response.ok) {
    throw new Error(`Failed to get session: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get all nodes in the graph
 */
export async function getAllNodes(): Promise<GraphNode[]> {
  const response = await fetch(`${API_BASE}/nodes`);
  
  if (!response.ok) {
    throw new Error(`Failed to get nodes: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get a specific node by ID
 */
export async function getNode(nodeId: string): Promise<GraphNode> {
  const response = await fetch(`${API_BASE}/nodes/${encodeURIComponent(nodeId)}`);
  
  if (!response.ok) {
    throw new Error(`Failed to get node: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Add a new node to the graph
 */
export async function addNode(
  nodeId: string,
  label: string,
  nodeType: NodeType,
  properties?: Record<string, unknown>,
  sourceScanId?: string
): Promise<GraphNode> {
  const response = await fetch(`${API_BASE}/nodes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      node_id: nodeId,
      label,
      node_type: nodeType,
      properties,
      source_scan_id: sourceScanId,
    }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to add node: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Update an existing node
 */
export async function updateNode(
  nodeId: string, 
  updates: Record<string, unknown>
): Promise<GraphNode> {
  const response = await fetch(`${API_BASE}/nodes/${encodeURIComponent(nodeId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ updates }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to update node: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Delete a node and all its edges
 */
export async function deleteNode(nodeId: string): Promise<{ message: string }> {
  const response = await fetch(`${API_BASE}/nodes/${encodeURIComponent(nodeId)}`, {
    method: 'DELETE',
  });
  
  if (!response.ok) {
    throw new Error(`Failed to delete node: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get all edges in the graph
 */
export async function getAllEdges(): Promise<GraphEdge[]> {
  const response = await fetch(`${API_BASE}/edges`);
  
  if (!response.ok) {
    throw new Error(`Failed to get edges: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Add a new edge to the graph
 */
export async function addEdge(
  sourceId: string,
  targetId: string,
  edgeType: EdgeType,
  weight: number = 1.0,
  properties?: Record<string, unknown>,
  isBidirectional: boolean = false,
  isInferred: boolean = false,
  sourceScanId?: string
): Promise<GraphEdge> {
  const response = await fetch(`${API_BASE}/edges`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source_id: sourceId,
      target_id: targetId,
      edge_type: edgeType,
      weight,
      properties,
      is_bidirectional: isBidirectional,
      is_inferred: isInferred,
      source_scan_id: sourceScanId,
    }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to add edge: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Delete an edge
 */
export async function deleteEdge(edgeId: string): Promise<{ message: string }> {
  const response = await fetch(`${API_BASE}/edges/${encodeURIComponent(edgeId)}`, {
    method: 'DELETE',
  });
  
  if (!response.ok) {
    throw new Error(`Failed to delete edge: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Ingest a scan into the graph
 */
export async function ingestScan(
  scanType: 'recon' | 'enum' | 'mobile',
  scanData: Record<string, unknown>
): Promise<{ message: string; elements_created: number; total_nodes: number; total_edges: number }> {
  const response = await fetch(`${API_BASE}/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scan_type: scanType,
      scan_data: scanData,
    }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to ingest scan: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Ingest multiple scans at once
 */
export async function ingestBatch(
  scans: Array<{ scanType: 'recon' | 'enum' | 'mobile'; scanData: Record<string, unknown> }>
): Promise<{ message: string; total_elements_created: number; total_nodes: number; total_edges: number }> {
  const response = await fetch(`${API_BASE}/ingest/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(
      scans.map(s => ({ scan_type: s.scanType, scan_data: s.scanData }))
    ),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to batch ingest: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Compute node positions using specified layout algorithm
 */
export async function computeLayout(
  layoutType: LayoutType = 'force'
): Promise<{ layout_type: string; positions: Record<string, { x: number; y: number }> }> {
  const response = await fetch(`${API_BASE}/layout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ layout_type: layoutType }),
  });
  
  if (!response.ok) {
    throw new Error(`Failed to compute layout: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get Security-Aware PageRank scores
 */
export async function getPageRankScores(): Promise<{ 
  algorithm: string; 
  scores: Array<{ node_id: string; score: number }> 
}> {
  const response = await fetch(`${API_BASE}/analysis/pagerank`);
  
  if (!response.ok) {
    throw new Error(`Failed to get PageRank: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get comprehensive risk scores for all nodes
 */
export async function getRiskScores(): Promise<RiskScore[]> {
  const response = await fetch(`${API_BASE}/analysis/risk`);
  
  if (!response.ok) {
    throw new Error(`Failed to get risk scores: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get functional security zones
 */
export async function getFunctionalZones(): Promise<FunctionalZone[]> {
  const response = await fetch(`${API_BASE}/analysis/zones`);
  
  if (!response.ok) {
    throw new Error(`Failed to get zones: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get potential attack paths
 */
export async function getAttackPaths(maxPaths: number = 10): Promise<AttackPath[]> {
  const response = await fetch(`${API_BASE}/analysis/attack-paths?max_paths=${maxPaths}`);
  
  if (!response.ok) {
    throw new Error(`Failed to get attack paths: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Get graph statistics
 */
export async function getGraphStats(): Promise<GraphStats> {
  const response = await fetch(`${API_BASE}/stats`);
  
  if (!response.ok) {
    throw new Error(`Failed to get stats: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Export graph in Cytoscape.js format (primary format for visualization)
 */
export async function exportCytoscape(): Promise<CytoscapeGraph> {
  const response = await fetch(`${API_BASE}/export/cytoscape`);
  
  if (!response.ok) {
    throw new Error(`Failed to export graph: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Export graph as JSON string
 */
export async function exportJson(): Promise<{ data: string }> {
  const response = await fetch(`${API_BASE}/export/json`);
  
  if (!response.ok) {
    throw new Error(`Failed to export JSON: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Export graph in GEXF format for Gephi
 */
export async function exportGexf(): Promise<{ gexf: string }> {
  const response = await fetch(`${API_BASE}/export/gexf`);
  
  if (!response.ok) {
    throw new Error(`Failed to export GEXF: ${response.statusText}`);
  }
  
  return response.json();
}

/**
 * Reset the graph and clear all data
 */
export async function resetGraph(): Promise<{ message: string }> {
  const response = await fetch(`${API_BASE}/reset`, {
    method: 'POST',
  });
  
  if (!response.ok) {
    throw new Error(`Failed to reset graph: ${response.statusText}`);
  }
  
  return response.json();
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Get color for a node based on its type
 */
export function getNodeTypeColor(nodeType: NodeType): string {
  const colors: Record<NodeType, string> = {
    domain: '#3b82f6',           // Blue
    subdomain: '#60a5fa',        // Light blue
    ip_address: '#8b5cf6',       // Purple
    port_service: '#a855f7',     // Light purple
    endpoint: '#22c55e',         // Green
    parameter: '#84cc16',        // Lime
    vulnerability: '#ef4444',    // Red
    technology: '#f59e0b',       // Amber
    certificate: '#06b6d4',      // Cyan
    api_endpoint: '#14b8a6',     // Teal
    third_party_service: '#f97316', // Orange
    authentication_point: '#ec4899', // Pink
    file_resource: '#6b7280',    // Gray
    mobile_endpoint: '#8b5cf6',  // Purple
  };
  
  return colors[nodeType] || '#6b7280';
}

/**
 * Get color for risk score
 */
export function getRiskColor(score: number): string {
  if (score >= 8) return '#ef4444';      // Critical - Red
  if (score >= 6) return '#f97316';      // High - Orange
  if (score >= 4) return '#f59e0b';      // Medium - Amber
  if (score >= 2) return '#eab308';      // Low - Yellow
  return '#22c55e';                       // Minimal - Green
}

/**
 * Get label for risk level
 */
export function getRiskLabel(score: number): string {
  if (score >= 8) return 'Critical';
  if (score >= 6) return 'High';
  if (score >= 4) return 'Medium';
  if (score >= 2) return 'Low';
  return 'Minimal';
}

/**
 * Format node type for display
 */
export function formatNodeType(nodeType: NodeType): string {
  return nodeType
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}
