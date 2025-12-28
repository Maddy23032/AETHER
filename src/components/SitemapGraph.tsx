/**
 * SitemapGraph Component
 * 
 * Interactive graph visualization for the Dynamic Graph Sitemap.
 * Uses Cytoscape.js for rendering with custom styling and interactions.
 * 
 * Features:
 * - Multiple layout algorithms (force, hierarchical, radial, cluster)
 * - Risk-based node coloring
 * - Interactive zoom/pan
 * - Node selection with details panel
 * - Attack path highlighting
 * - Zone visualization
 * - Export functionality
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape, { Core, NodeSingular, EdgeSingular } from 'cytoscape';

// Import Cytoscape extensions
import coseBilkent from 'cytoscape-cose-bilkent';
import dagre from 'cytoscape-dagre';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Download,
  RefreshCw,
  Target,
  Shield,
  AlertTriangle,
  Network,
  Layers,
  Route,
} from 'lucide-react';
import {
  CytoscapeGraph,
  CytoscapeElement,
  GraphNode,
  AttackPath,
  FunctionalZone,
  LayoutType,
  getNodeTypeColor,
  getRiskColor,
  getRiskLabel,
  formatNodeType,
} from '@/services/graphService';

// Register extensions
if (typeof cytoscape === 'function') {
  try {
    cytoscape.use(coseBilkent);
    cytoscape.use(dagre);
  } catch (e) {
    // Extensions already registered
  }
}

interface SitemapGraphProps {
  graphData: CytoscapeGraph | null;
  isLoading?: boolean;
  onLayoutChange?: (layout: LayoutType) => void;
  onNodeSelect?: (nodeId: string | null) => void;
  onRefresh?: () => void;
}

interface SelectedNodeDetails {
  id: string;
  label: string;
  nodeType: string;
  riskScore: number;
  pagerank: number;
  vulnerabilityCount: number;
  maxSeverity: number;
  isExternal: boolean;
  properties: Record<string, unknown>;
}

const SitemapGraph: React.FC<SitemapGraphProps> = ({
  graphData,
  isLoading = false,
  onLayoutChange,
  onNodeSelect,
  onRefresh,
}) => {
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<SelectedNodeDetails | null>(null);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [currentLayout, setCurrentLayout] = useState<LayoutType>('force');
  const [showZones, setShowZones] = useState(false);
  const [highlightedElements, setHighlightedElements] = useState<Set<string>>(new Set());

  // Cytoscape stylesheet
  const stylesheet: cytoscape.StylesheetStyle[] = [
    // Node styles
    {
      selector: 'node',
      style: {
        'background-color': 'data(color)',
        'label': 'data(label)',
        'width': 'mapData(size, 10, 100, 30, 80)',
        'height': 'mapData(size, 10, 100, 30, 80)',
        'font-size': '10px',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 5,
        'color': '#e2e8f0',
        'text-outline-color': '#0f172a',
        'text-outline-width': 2,
        'border-width': 2,
        'border-color': '#475569',
        'transition-property': 'background-color, border-color, width, height',
        'transition-duration': 200,
      } as cytoscape.Css.Node,
    },
    // High risk nodes
    {
      selector: 'node.high-risk',
      style: {
        'border-color': '#ef4444',
        'border-width': 3,
      } as cytoscape.Css.Node,
    },
    // Selected node
    {
      selector: 'node:selected',
      style: {
        'border-color': '#3b82f6',
        'border-width': 4,
        'background-color': '#60a5fa',
      } as cytoscape.Css.Node,
    },
    // Highlighted nodes (attack path)
    {
      selector: 'node.highlighted',
      style: {
        'border-color': '#f59e0b',
        'border-width': 4,
        'background-opacity': 1,
      } as cytoscape.Css.Node,
    },
    // Vulnerability nodes
    {
      selector: 'node[nodeType = "vulnerability"]',
      style: {
        'shape': 'diamond',
        'background-color': '#ef4444',
      } as cytoscape.Css.Node,
    },
    // Authentication nodes
    {
      selector: 'node[nodeType = "authentication_point"]',
      style: {
        'shape': 'pentagon',
        'background-color': '#ec4899',
      } as cytoscape.Css.Node,
    },
    // Domain nodes
    {
      selector: 'node[nodeType = "domain"]',
      style: {
        'shape': 'round-rectangle',
        'width': 60,
        'height': 40,
      } as cytoscape.Css.Node,
    },
    // Edge styles
    {
      selector: 'edge',
      style: {
        'width': 'mapData(weight, 0.1, 1, 1, 4)',
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 0.7,
        'transition-property': 'line-color, opacity, width',
        'transition-duration': 200,
      } as cytoscape.Css.Edge,
    },
    // Vulnerability edges
    {
      selector: 'edge[edgeType = "has_vulnerability"]',
      style: {
        'line-color': '#ef4444',
        'target-arrow-color': '#ef4444',
        'line-style': 'dashed',
      } as cytoscape.Css.Edge,
    },
    // Authentication edges
    {
      selector: 'edge[edgeType = "authenticates_via"]',
      style: {
        'line-color': '#ec4899',
        'target-arrow-color': '#ec4899',
      } as cytoscape.Css.Edge,
    },
    // Highlighted edges (attack path)
    {
      selector: 'edge.highlighted',
      style: {
        'line-color': '#f59e0b',
        'target-arrow-color': '#f59e0b',
        'width': 4,
        'opacity': 1,
      } as cytoscape.Css.Edge,
    },
    // Inferred edges
    {
      selector: 'edge.inferred',
      style: {
        'line-style': 'dotted',
        'opacity': 0.5,
      } as cytoscape.Css.Edge,
    },
    // Faded elements (when path is highlighted)
    {
      selector: '.faded',
      style: {
        'opacity': 0.2,
      },
    },
  ];

  // Process graph data into Cytoscape format
  const processElements = useCallback((): CytoscapeElement[] => {
    if (!graphData?.elements) return [];

    return graphData.elements.map((el) => {
      if (el.data.source && el.data.target) {
        // Edge
        return {
          data: {
            ...el.data,
            weight: el.data.weight || 1,
          },
          classes: el.classes,
        };
      } else {
        // Node
        const riskScore = (el.data.riskScore as number) || 0;
        const nodeType = el.data.nodeType as string;
        
        return {
          data: {
            ...el.data,
            color: getNodeTypeColor(nodeType as never),
            size: 20 + (riskScore * 5) + ((el.data.pagerank as number || 0) * 100),
          },
          position: el.position,
          classes: el.classes,
        };
      }
    });
  }, [graphData]);

  // Handle layout change
  const handleLayoutChange = useCallback((layout: LayoutType) => {
    setCurrentLayout(layout);
    onLayoutChange?.(layout);

    if (!cyRef.current) return;

    const cy = cyRef.current;
    let layoutOptions: cytoscape.LayoutOptions;

    switch (layout) {
      case 'hierarchical':
        layoutOptions = {
          name: 'dagre',
          rankDir: 'TB',
          nodeSep: 50,
          rankSep: 100,
          animate: true,
          animationDuration: 500,
        } as cytoscape.LayoutOptions;
        break;
      case 'radial':
        layoutOptions = {
          name: 'concentric',
          concentric: (node: NodeSingular) => {
            return (node.data('riskScore') as number) || 0;
          },
          levelWidth: () => 2,
          animate: true,
          animationDuration: 500,
        } as cytoscape.LayoutOptions;
        break;
      case 'cluster':
        layoutOptions = {
          name: 'cose-bilkent',
          quality: 'default',
          nodeDimensionsIncludeLabels: true,
          animate: 'during',
          animationDuration: 500,
          nodeRepulsion: 4500,
          idealEdgeLength: 100,
        } as cytoscape.LayoutOptions;
        break;
      case 'force':
      default:
        layoutOptions = {
          name: 'cose',
          animate: true,
          animationDuration: 500,
          nodeRepulsion: () => 8000,
          idealEdgeLength: () => 100,
          gravity: 0.5,
        } as cytoscape.LayoutOptions;
    }

    cy.layout(layoutOptions).run();
  }, [onLayoutChange]);

  // Handle node selection
  const handleNodeSelect = useCallback((node: NodeSingular) => {
    const data = node.data();
    
    const details: SelectedNodeDetails = {
      id: data.id,
      label: data.label,
      nodeType: data.nodeType,
      riskScore: data.riskScore || 0,
      pagerank: data.pagerank || 0,
      vulnerabilityCount: data.vulnerabilityCount || 0,
      maxSeverity: data.maxSeverity || 0,
      isExternal: data.isExternal || false,
      properties: data,
    };
    
    setSelectedNode(details);
    onNodeSelect?.(data.id);
  }, [onNodeSelect]);

  // Highlight attack path
  const highlightAttackPath = useCallback((path: AttackPath | null) => {
    if (!cyRef.current) return;
    
    const cy = cyRef.current;
    
    // Clear previous highlights
    cy.elements().removeClass('highlighted faded');
    
    if (!path) {
      setSelectedPath(null);
      setHighlightedElements(new Set());
      return;
    }
    
    setSelectedPath(path);
    
    // Fade all elements
    cy.elements().addClass('faded');
    
    // Highlight path nodes
    const pathNodes = new Set(path.nodes);
    path.nodes.forEach((nodeId) => {
      const node = cy.getElementById(nodeId);
      if (node.length) {
        node.removeClass('faded').addClass('highlighted');
      }
    });
    
    // Highlight edges between consecutive path nodes
    for (let i = 0; i < path.nodes.length - 1; i++) {
      const source = path.nodes[i];
      const target = path.nodes[i + 1];
      
      cy.edges().forEach((edge: EdgeSingular) => {
        if (
          (edge.data('source') === source && edge.data('target') === target) ||
          (edge.data('source') === target && edge.data('target') === source)
        ) {
          edge.removeClass('faded').addClass('highlighted');
        }
      });
    }
    
    setHighlightedElements(pathNodes);
  }, []);

  // Zoom controls
  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() / 1.2);
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 50);
  };

  // Export graph
  const handleExport = () => {
    if (!cyRef.current) return;
    
    const png = cyRef.current.png({
      output: 'blob',
      bg: '#0f172a',
      full: true,
      scale: 2,
    });
    
    const url = URL.createObjectURL(png as Blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sitemap-graph.png';
    link.click();
    URL.revokeObjectURL(url);
  };

  // Setup Cytoscape event handlers
  useEffect(() => {
    if (!cyRef.current) return;

    const cy = cyRef.current;

    // Node click handler
    cy.on('tap', 'node', (evt) => {
      handleNodeSelect(evt.target as NodeSingular);
    });

    // Background click to deselect
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        onNodeSelect?.(null);
      }
    });

    // Node hover effects
    cy.on('mouseover', 'node', (evt) => {
      (evt.target as NodeSingular).style({
        'border-width': 4,
        'z-index': 999,
      });
    });

    cy.on('mouseout', 'node', (evt) => {
      if (!evt.target.selected()) {
        (evt.target as NodeSingular).style({
          'border-width': 2,
          'z-index': 1,
        });
      }
    });

    return () => {
      cy.removeAllListeners();
    };
  }, [handleNodeSelect, onNodeSelect]);

  const elements = processElements();

  return (
    <div className="flex h-full gap-4">
      {/* Main Graph Area */}
      <div className="flex-1 flex flex-col">
        {/* Toolbar */}
        <div className="flex items-center justify-between mb-4 p-2 bg-slate-800/50 rounded-lg">
          <div className="flex items-center gap-2">
            <Select value={currentLayout} onValueChange={(v) => handleLayoutChange(v as LayoutType)}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Layout" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="force">Force-Directed</SelectItem>
                <SelectItem value="hierarchical">Hierarchical</SelectItem>
                <SelectItem value="radial">Radial</SelectItem>
                <SelectItem value="cluster">Clustered</SelectItem>
              </SelectContent>
            </Select>
            
            <Separator orientation="vertical" className="h-6" />
            
            <Button variant="ghost" size="icon" onClick={handleZoomIn} title="Zoom In">
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleZoomOut} title="Zoom Out">
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleFit} title="Fit to View">
              <Maximize2 className="h-4 w-4" />
            </Button>
            
            <Separator orientation="vertical" className="h-6" />
            
            <Button 
              variant={showZones ? "secondary" : "ghost"} 
              size="sm"
              onClick={() => setShowZones(!showZones)}
            >
              <Layers className="h-4 w-4 mr-1" />
              Zones
            </Button>
          </div>
          
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={onRefresh} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleExport} title="Export PNG">
              <Download className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Graph Canvas */}
        <div className="flex-1 relative bg-slate-900 rounded-lg overflow-hidden border border-slate-700">
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center bg-slate-900/80 z-10">
              <div className="flex flex-col items-center gap-2">
                <RefreshCw className="h-8 w-8 animate-spin text-blue-500" />
                <span className="text-sm text-slate-400">Loading graph...</span>
              </div>
            </div>
          )}
          
          {elements.length > 0 ? (
            <CytoscapeComponent
              elements={elements}
              stylesheet={stylesheet}
              style={{ width: '100%', height: '100%' }}
              cy={(cy) => {
                cyRef.current = cy;
              }}
              minZoom={0.1}
              maxZoom={3}
              wheelSensitivity={0.3}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-slate-500">
              <div className="text-center">
                <Network className="h-16 w-16 mx-auto mb-4 opacity-50" />
                <p>No graph data available</p>
                <p className="text-sm">Run a scan or load existing data to visualize</p>
              </div>
            </div>
          )}
          
          {/* Stats overlay */}
          {graphData?.stats && (
            <div className="absolute bottom-4 left-4 bg-slate-800/90 rounded-lg px-3 py-2 text-xs text-slate-400">
              <div className="flex gap-4">
                <span>{graphData.stats.total_nodes} nodes</span>
                <span>{graphData.stats.total_edges} edges</span>
                <span>{graphData.stats.high_risk_nodes} high-risk</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Sidebar */}
      <div className="w-80 flex flex-col gap-4">
        <Tabs defaultValue="details" className="flex-1">
          <TabsList className="w-full">
            <TabsTrigger value="details" className="flex-1">
              <Target className="h-4 w-4 mr-1" />
              Details
            </TabsTrigger>
            <TabsTrigger value="paths" className="flex-1">
              <Route className="h-4 w-4 mr-1" />
              Paths
            </TabsTrigger>
            <TabsTrigger value="zones" className="flex-1">
              <Layers className="h-4 w-4 mr-1" />
              Zones
            </TabsTrigger>
          </TabsList>

          {/* Node Details Tab */}
          <TabsContent value="details" className="flex-1 mt-4">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="py-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  {selectedNode ? 'Node Details' : 'Select a Node'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {selectedNode ? (
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-medium text-white truncate" title={selectedNode.label}>
                        {selectedNode.label}
                      </h3>
                      <Badge variant="outline" className="mt-1">
                        {formatNodeType(selectedNode.nodeType as never)}
                      </Badge>
                    </div>
                    
                    <Separator />
                    
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-slate-400">Risk Score</span>
                        <div className="flex items-center gap-2">
                          <span 
                            className="font-medium"
                            style={{ color: getRiskColor(selectedNode.riskScore) }}
                          >
                            {selectedNode.riskScore.toFixed(1)}
                          </span>
                          <Badge 
                            variant="outline"
                            style={{ 
                              borderColor: getRiskColor(selectedNode.riskScore),
                              color: getRiskColor(selectedNode.riskScore) 
                            }}
                          >
                            {getRiskLabel(selectedNode.riskScore)}
                          </Badge>
                        </div>
                      </div>
                      
                      <div>
                        <span className="text-slate-400">PageRank</span>
                        <p className="font-medium">{selectedNode.pagerank.toFixed(4)}</p>
                      </div>
                      
                      <div>
                        <span className="text-slate-400">Vulnerabilities</span>
                        <p className="font-medium">{selectedNode.vulnerabilityCount}</p>
                      </div>
                      
                      <div>
                        <span className="text-slate-400">Max Severity</span>
                        <p className="font-medium">{selectedNode.maxSeverity.toFixed(1)}</p>
                      </div>
                    </div>
                    
                    {selectedNode.isExternal && (
                      <Badge variant="secondary">External</Badge>
                    )}
                    
                    <Separator />
                    
                    <div>
                      <span className="text-slate-400 text-sm">Properties</span>
                      <ScrollArea className="h-32 mt-2">
                        <pre className="text-xs text-slate-300 whitespace-pre-wrap">
                          {JSON.stringify(selectedNode.properties, null, 2)}
                        </pre>
                      </ScrollArea>
                    </div>
                  </div>
                ) : (
                  <p className="text-slate-500 text-sm text-center py-8">
                    Click on a node to view its details
                  </p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Attack Paths Tab */}
          <TabsContent value="paths" className="flex-1 mt-4">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="py-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  Attack Paths
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {graphData?.attackPaths && graphData.attackPaths.length > 0 ? (
                    <div className="space-y-3">
                      {graphData.attackPaths.map((path) => (
                        <div
                          key={path.path_id}
                          className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                            selectedPath?.path_id === path.path_id
                              ? 'border-amber-500 bg-amber-500/10'
                              : 'border-slate-700 hover:border-slate-600'
                          }`}
                          onClick={() => highlightAttackPath(
                            selectedPath?.path_id === path.path_id ? null : path
                          )}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <Badge variant="outline" className="text-xs">
                              {path.nodes.length} hops
                            </Badge>
                            <span 
                              className="text-sm font-medium"
                              style={{ color: getRiskColor(path.total_risk / path.nodes.length) }}
                            >
                              Risk: {path.total_risk.toFixed(1)}
                            </span>
                          </div>
                          
                          <div className="text-xs text-slate-400 space-y-1">
                            <div className="flex items-center gap-1">
                              <span>Entry:</span>
                              <span className="text-slate-300 truncate flex-1">
                                {path.entry_point}
                              </span>
                            </div>
                            <div className="flex items-center gap-1">
                              <span>Target:</span>
                              <span className="text-slate-300 truncate flex-1">
                                {path.target}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-sm text-center py-8">
                      No attack paths identified
                    </p>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Zones Tab */}
          <TabsContent value="zones" className="flex-1 mt-4">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="py-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Layers className="h-4 w-4" />
                  Functional Zones
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  {graphData?.zones && graphData.zones.length > 0 ? (
                    <div className="space-y-3">
                      {graphData.zones.map((zone) => (
                        <div
                          key={zone.zone_id}
                          className="p-3 rounded-lg border border-slate-700 hover:border-slate-600"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-medium text-white">
                              {zone.zone_name}
                            </span>
                            <Badge variant="outline">{zone.zone_type}</Badge>
                          </div>
                          
                          <div className="grid grid-cols-2 gap-2 text-xs text-slate-400">
                            <div>
                              <span>Nodes:</span>
                              <span className="ml-1 text-slate-300">{zone.nodes.length}</span>
                            </div>
                            <div>
                              <span>Risk:</span>
                              <span 
                                className="ml-1"
                                style={{ color: getRiskColor(zone.aggregate_risk) }}
                              >
                                {zone.aggregate_risk.toFixed(1)}
                              </span>
                            </div>
                            <div>
                              <span>Boundary:</span>
                              <span className="ml-1 text-slate-300">
                                {zone.boundary_nodes.length}
                              </span>
                            </div>
                            <div>
                              <span>Connectivity:</span>
                              <span className="ml-1 text-slate-300">
                                {(zone.internal_connectivity * 100).toFixed(0)}%
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-sm text-center py-8">
                      No zones identified
                    </p>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Legend */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader className="py-2">
            <CardTitle className="text-xs text-slate-400">Node Types</CardTitle>
          </CardHeader>
          <CardContent className="py-2">
            <div className="grid grid-cols-2 gap-1 text-xs">
              {[
                { type: 'domain', label: 'Domain' },
                { type: 'subdomain', label: 'Subdomain' },
                { type: 'ip_address', label: 'IP Address' },
                { type: 'endpoint', label: 'Endpoint' },
                { type: 'vulnerability', label: 'Vulnerability' },
                { type: 'technology', label: 'Technology' },
              ].map(({ type, label }) => (
                <div key={type} className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: getNodeTypeColor(type as never) }}
                  />
                  <span className="text-slate-400">{label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default SitemapGraph;
