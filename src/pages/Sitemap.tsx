/**
 * Sitemap Page
 * 
 * Dynamic Graph Sitemap - A novel visualization of security infrastructure.
 * 
 * Features:
 * - Real-time graph construction from scan data
 * - Multiple layout algorithms (force, hierarchical, radial, cluster)
 * - Security-Aware PageRank highlighting critical nodes
 * - Vulnerability propagation visualization
 * - Attack path analysis and highlighting
 * - Functional zone clustering
 * - Export to PNG/GEXF for research paper
 * 
 * This is the primary novel contribution for the research paper.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import SitemapGraph from '@/components/SitemapGraph';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Network,
  Play,
  Database,
  Loader2,
  Plus,
  FileDown,
  BarChart3,
  Target,
  AlertTriangle,
  TrendingUp,
  Layers,
  RefreshCw,
} from 'lucide-react';
import {
  CytoscapeGraph,
  LayoutType,
  GraphStats,
  createSession,
  getGraphStats,
  exportCytoscape,
  exportJson,
  exportGexf,
  ingestScan,
  computeLayout,
  resetGraph,
  getPageRankScores,
  getRiskScores,
  getAttackPaths,
  getFunctionalZones,
} from '@/services/graphService';
import { getAllScans, getLastScanByType, getAllMobileScans, getReconResultsByScan, getReconFindingsByScan, getScanById } from '@/services/supabaseService';

// Transform Supabase scan data to backend expected format
const transformScanData = (scan: Record<string, unknown>, reconResults?: unknown[], reconFindings?: unknown[]): Record<string, unknown> => {
  // Build the results object from recon_results and recon_findings
  const results: Record<string, unknown[]> = {
    subdomains: [],
    dns: [],
    ports: [],
    technologies: [],
    endpoints: [],
  };

  // Process recon results
  if (reconResults && Array.isArray(reconResults)) {
    for (const result of reconResults) {
      const r = result as Record<string, unknown>;
      const toolName = (r.tool_name as string || '').toLowerCase();
      const data = r.data as Record<string, unknown> | unknown[] || {};
      
      // Map tool results to the expected structure
      if (toolName.includes('subfinder') || toolName.includes('subdomain') || toolName.includes('amass')) {
        if (Array.isArray(data)) {
          results.subdomains.push(...data.map((d: unknown) => typeof d === 'string' ? { subdomain: d } : d as object));
        } else if (data && typeof data === 'object' && 'subdomains' in data) {
          results.subdomains.push(...(data.subdomains as unknown[] || []));
        }
      } else if (toolName.includes('dns') || toolName.includes('dnsenum')) {
        if (Array.isArray(data)) {
          results.dns.push(...data as unknown[]);
        } else if (data && typeof data === 'object' && 'records' in data) {
          results.dns.push(...(data.records as unknown[] || []));
        }
      } else if (toolName.includes('nmap') || toolName.includes('port')) {
        if (Array.isArray(data)) {
          results.ports.push(...data as unknown[]);
        } else if (data && typeof data === 'object' && 'ports' in data) {
          results.ports.push(...(data.ports as unknown[] || []));
        }
      } else if (toolName.includes('whatweb') || toolName.includes('tech') || toolName.includes('wappalyzer')) {
        if (Array.isArray(data)) {
          results.technologies.push(...data as unknown[]);
        } else if (data && typeof data === 'object' && 'technologies' in data) {
          results.technologies.push(...(data.technologies as unknown[] || []));
        }
      } else if (toolName.includes('gobuster') || toolName.includes('dirb') || toolName.includes('endpoint')) {
        if (Array.isArray(data)) {
          results.endpoints.push(...data as unknown[]);
        } else if (data && typeof data === 'object' && 'endpoints' in data) {
          results.endpoints.push(...(data.endpoints as unknown[] || []));
        }
      }
    }
  }

  // Process findings for additional data
  if (reconFindings && Array.isArray(reconFindings)) {
    for (const finding of reconFindings) {
      const f = finding as Record<string, unknown>;
      const findingType = (f.finding_type as string || '').toLowerCase();
      const data = f.data as Record<string, unknown> || {};
      
      if (findingType.includes('subdomain')) {
        results.subdomains.push(data);
      } else if (findingType.includes('tech') || findingType.includes('technology')) {
        results.technologies.push(data);
      } else if (findingType.includes('port') || findingType.includes('service')) {
        results.ports.push(data);
      }
    }
  }

  return {
    id: scan.id,
    target: scan.target_url || scan.target || 'unknown',
    results,
  };
};

const Sitemap: React.FC = () => {
  // Graph state
  const [graphData, setGraphData] = useState<CytoscapeGraph | null>(null);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [hasSession, setHasSession] = useState(false);

  // Dialog states
  const [showNewSessionDialog, setShowNewSessionDialog] = useState(false);
  const [showLoadScansDialog, setShowLoadScansDialog] = useState(false);
  const [showExportDialog, setShowExportDialog] = useState(false);

  // Form states
  const [targetDomain, setTargetDomain] = useState('');
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [availableScans, setAvailableScans] = useState<Array<{ id: string; target: string; type: string; date: string }>>([]);

  // Current layout
  const [currentLayout, setCurrentLayout] = useState<LayoutType>('force');

  // Load available scans from Supabase
  const loadAvailableScans = async () => {
    try {
      const [reconResult, mobileResult] = await Promise.all([
        getAllScans(),
        getAllMobileScans(),
      ]);

      const scans = [
        ...reconResult.scans.map(s => ({
          id: s.id,
          target: s.target_url || 'unknown',
          type: s.scan_type || 'recon',
          date: s.created_at ? new Date(s.created_at).toLocaleDateString() : 'Unknown',
        })),
        ...mobileResult.scans.map(s => ({
          id: s.id,
          target: s.app_name || s.package_name || 'Unknown App',
          type: 'mobile',
          date: s.created_at ? new Date(s.created_at).toLocaleDateString() : 'Unknown',
        })),
      ];

      setAvailableScans(scans);
    } catch (error) {
      console.error('Failed to load scans:', error);
    }
  };

  // Initialize - check if session exists
  useEffect(() => {
    loadAvailableScans();
  }, []);

  // Create new session
  const handleCreateSession = async () => {
    if (!targetDomain.trim()) {
      toast.error('Please enter a target domain');
      return;
    }

    setIsLoading(true);
    try {
      await createSession(targetDomain, selectedScans);
      setHasSession(true);
      setShowNewSessionDialog(false);
      toast.success('Graph session created');

      // If scans were selected, ingest them
      if (selectedScans.length > 0) {
        await loadSelectedScans();
      }
    } catch (error) {
      toast.error('Failed to create session');
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  // Load and ingest selected scans
  const loadSelectedScans = async () => {
    setIsLoading(true);
    try {
      for (const scanId of selectedScans) {
        const scan = availableScans.find(s => s.id === scanId);
        if (!scan) continue;

        // Fetch full scan data
        const scanData = await fetchScanData(scanId, scan.type);
        if (scanData) {
          await ingestScan(
            scan.type as 'recon' | 'enum' | 'mobile',
            scanData
          );
        }
      }

      // Refresh graph
      await refreshGraph();
      toast.success('Scans loaded into graph');
    } catch (error) {
      toast.error('Failed to load scans');
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch scan data helper - fetches scan and related results, then transforms to backend format
  const fetchScanData = async (scanId: string, scanType: string): Promise<Record<string, unknown> | null> => {
    try {
      if (scanType === 'mobile') {
        // Mobile scans have a different structure
        const result = await getAllMobileScans();
        const mobileScan = result.scans.find(s => s.id === scanId);
        if (!mobileScan) return null;
        
        // Transform mobile scan to expected format
        return {
          id: mobileScan.id,
          target: mobileScan.app_name || mobileScan.package_name || 'unknown',
          results: {
            permissions: mobileScan.permissions || [],
            components: mobileScan.components || [],
            security_issues: mobileScan.security_issues || [],
            trackers: mobileScan.trackers || [],
          },
        };
      } else {
        // Recon/Enum scans - fetch the scan and its related results
        const scan = await getScanById(scanId);
        if (!scan) return null;
        
        // Fetch related recon data
        const [reconResults, reconFindings] = await Promise.all([
          getReconResultsByScan(scanId).catch(() => []),
          getReconFindingsByScan(scanId).catch(() => []),
        ]);
        
        // Transform to backend expected format
        return transformScanData(
          scan as unknown as Record<string, unknown>,
          reconResults as unknown[],
          reconFindings as unknown[]
        );
      }
    } catch (error) {
      console.error('Failed to fetch scan data:', error);
      return null;
    }
  };

  // Load scans from Supabase into existing graph
  const handleLoadScans = async () => {
    if (selectedScans.length === 0) {
      toast.error('Please select at least one scan');
      return;
    }

    await loadSelectedScans();
    setShowLoadScansDialog(false);
  };

  // Refresh graph data
  const refreshGraph = async () => {
    setIsLoading(true);
    try {
      const [graphResult, statsResult] = await Promise.all([
        exportCytoscape(),
        getGraphStats(),
      ]);

      setGraphData(graphResult);
      setStats(statsResult);
    } catch (error) {
      console.error('Failed to refresh graph:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle layout change
  const handleLayoutChange = async (layout: LayoutType) => {
    setCurrentLayout(layout);
    setIsLoading(true);
    try {
      await computeLayout(layout);
      await refreshGraph();
    } catch (error) {
      console.error('Failed to change layout:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Export handlers
  const handleExportPng = () => {
    // This is handled in the SitemapGraph component
    toast.success('PNG export triggered');
  };

  const handleExportJson = async () => {
    try {
      const result = await exportJson();
      const blob = new Blob([result.data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'sitemap-graph.json';
      link.click();
      URL.revokeObjectURL(url);
      toast.success('JSON exported');
    } catch (error) {
      toast.error('Failed to export JSON');
    }
  };

  const handleExportGexf = async () => {
    try {
      const result = await exportGexf();
      const blob = new Blob([result.gexf], { type: 'application/xml' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'sitemap-graph.gexf';
      link.click();
      URL.revokeObjectURL(url);
      toast.success('GEXF exported (use with Gephi)');
    } catch (error) {
      toast.error('Failed to export GEXF');
    }
  };

  // Reset graph
  const handleReset = async () => {
    setIsLoading(true);
    try {
      await resetGraph();
      setGraphData(null);
      setStats(null);
      setHasSession(false);
      toast.success('Graph reset');
    } catch (error) {
      toast.error('Failed to reset graph');
    } finally {
      setIsLoading(false);
    }
  };

  // Quick action: Load latest scan
  const handleLoadLatestScan = async () => {
    setIsLoading(true);
    try {
      const lastScan = await getLastScanByType('recon');
      if (!lastScan) {
        toast.error('No scans found');
        return;
      }

      // Create session if needed
      if (!hasSession) {
        await createSession(lastScan.target_url || 'unknown');
        setHasSession(true);
      }

      // Fetch related recon data
      const [reconResults, reconFindings] = await Promise.all([
        getReconResultsByScan(lastScan.id).catch(() => []),
        getReconFindingsByScan(lastScan.id).catch(() => []),
      ]);

      // Transform to backend expected format
      const scanData = transformScanData(
        lastScan as unknown as Record<string, unknown>,
        reconResults as unknown[],
        reconFindings as unknown[]
      );

      await ingestScan('recon', scanData);
      await refreshGraph();
      toast.success('Latest scan loaded');
    } catch (error) {
      toast.error('Failed to load latest scan');
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Network className="h-6 w-6 text-blue-500" />
            Dynamic Graph Sitemap
          </h1>
          <p className="text-slate-400 mt-1">
            Security-Aware Infrastructure Visualization with Attack Path Analysis
          </p>
        </div>

        <div className="flex items-center gap-2">
            {/* New Session */}
            <Dialog open={showNewSessionDialog} onOpenChange={setShowNewSessionDialog}>
              <DialogTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Plus className="h-4 w-4" />
                  New Session
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create New Graph Session</DialogTitle>
                  <DialogDescription>
                    Start a new graph visualization for a target domain
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="target">Target Domain</Label>
                    <Input
                      id="target"
                      placeholder="example.com"
                      value={targetDomain}
                      onChange={(e) => setTargetDomain(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Include Existing Scans (optional)</Label>
                    <ScrollArea className="h-32 border rounded-md p-2">
                      {availableScans.map((scan) => (
                        <div
                          key={scan.id}
                          className={`flex items-center justify-between p-2 rounded cursor-pointer ${
                            selectedScans.includes(scan.id)
                              ? 'bg-blue-500/20'
                              : 'hover:bg-slate-700'
                          }`}
                          onClick={() => {
                            setSelectedScans((prev) =>
                              prev.includes(scan.id)
                                ? prev.filter((id) => id !== scan.id)
                                : [...prev, scan.id]
                            );
                          }}
                        >
                          <span className="text-sm text-slate-300">{scan.target}</span>
                          <Badge variant="outline">{scan.type}</Badge>
                        </div>
                      ))}
                      {availableScans.length === 0 && (
                        <p className="text-slate-500 text-sm text-center py-4">
                          No existing scans found
                        </p>
                      )}
                    </ScrollArea>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="ghost" onClick={() => setShowNewSessionDialog(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreateSession} disabled={isLoading}>
                    {isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                    Create Session
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            {/* Load Scans */}
            <Dialog open={showLoadScansDialog} onOpenChange={setShowLoadScansDialog}>
              <DialogTrigger asChild>
                <Button variant="outline" className="gap-2" disabled={!hasSession}>
                  <Database className="h-4 w-4" />
                  Load Scans
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Load Scans into Graph</DialogTitle>
                  <DialogDescription>
                    Select scans to visualize in the graph
                  </DialogDescription>
                </DialogHeader>
                <div className="py-4">
                  <ScrollArea className="h-64 border rounded-md p-2">
                    {availableScans.map((scan) => (
                      <div
                        key={scan.id}
                        className={`flex items-center justify-between p-2 rounded cursor-pointer ${
                          selectedScans.includes(scan.id)
                            ? 'bg-blue-500/20'
                            : 'hover:bg-slate-700'
                        }`}
                        onClick={() => {
                          setSelectedScans((prev) =>
                            prev.includes(scan.id)
                              ? prev.filter((id) => id !== scan.id)
                              : [...prev, scan.id]
                          );
                        }}
                      >
                        <div>
                          <span className="text-sm text-slate-300">{scan.target}</span>
                          <p className="text-xs text-slate-500">{scan.date}</p>
                        </div>
                        <Badge variant="outline">{scan.type}</Badge>
                      </div>
                    ))}
                  </ScrollArea>
                </div>
                <DialogFooter>
                  <Button variant="ghost" onClick={() => setShowLoadScansDialog(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleLoadScans} disabled={isLoading || selectedScans.length === 0}>
                    {isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                    Load {selectedScans.length} Scan(s)
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            {/* Export */}
            <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
              <DialogTrigger asChild>
                <Button variant="outline" className="gap-2" disabled={!graphData}>
                  <FileDown className="h-4 w-4" />
                  Export
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Export Graph</DialogTitle>
                  <DialogDescription>
                    Download the graph in various formats
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <Button variant="outline" onClick={handleExportJson} className="justify-start">
                    <FileDown className="h-4 w-4 mr-2" />
                    Export as JSON (Cytoscape format)
                  </Button>
                  <Button variant="outline" onClick={handleExportGexf} className="justify-start">
                    <FileDown className="h-4 w-4 mr-2" />
                    Export as GEXF (for Gephi)
                  </Button>
                </div>
              </DialogContent>
            </Dialog>

            {/* Quick Load Latest */}
            <Button onClick={handleLoadLatestScan} disabled={isLoading} className="gap-2">
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Quick Load Latest
            </Button>
          </div>
        </div>

        {/* Stats Bar */}
        {stats && (
          <div className="grid grid-cols-6 gap-4 mb-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-blue-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{stats.total_nodes}</p>
                    <p className="text-xs text-slate-400">Total Nodes</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-purple-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{stats.total_edges}</p>
                    <p className="text-xs text-slate-400">Relationships</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{stats.high_risk_nodes}</p>
                    <p className="text-xs text-slate-400">High Risk</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Layers className="h-4 w-4 text-green-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{stats.connected_components}</p>
                    <p className="text-xs text-slate-400">Components</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-amber-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{stats.avg_degree.toFixed(1)}</p>
                    <p className="text-xs text-slate-400">Avg Degree</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-slate-800/50 border-slate-700">
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-cyan-500" />
                  <div>
                    <p className="text-2xl font-bold text-white">{(stats.density * 100).toFixed(1)}%</p>
                    <p className="text-xs text-slate-400">Density</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Main Graph Area */}
        <div className="flex-1 min-h-0">
          {!hasSession && !graphData ? (
            // Empty state
            <div className="h-full flex items-center justify-center">
              <Card className="bg-slate-800/50 border-slate-700 max-w-lg">
                <CardHeader className="text-center">
                  <div className="mx-auto w-16 h-16 rounded-full bg-blue-500/10 flex items-center justify-center mb-4">
                    <Network className="h-8 w-8 text-blue-500" />
                  </div>
                  <CardTitle>Dynamic Graph Sitemap</CardTitle>
                  <CardDescription>
                    Visualize your security infrastructure with advanced graph analytics
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-3 text-sm text-slate-400">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4 text-blue-500" />
                      <span>Security-Aware PageRank analysis</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-amber-500" />
                      <span>Vulnerability propagation visualization</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Layers className="h-4 w-4 text-green-500" />
                      <span>Functional zone clustering</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-purple-500" />
                      <span>Attack path identification</span>
                    </div>
                  </div>
                  <Separator />
                  <div className="flex gap-2">
                    <Button 
                      className="flex-1" 
                      onClick={() => setShowNewSessionDialog(true)}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      New Session
                    </Button>
                    <Button 
                      variant="secondary" 
                      className="flex-1"
                      onClick={handleLoadLatestScan}
                      disabled={isLoading}
                    >
                      {isLoading ? (
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4 mr-2" />
                      )}
                      Quick Start
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : (
            // Graph visualization
            <SitemapGraph
              graphData={graphData}
              isLoading={isLoading}
              onLayoutChange={handleLayoutChange}
              onRefresh={refreshGraph}
            />
          )}
        </div>
      </div>
  );
};

export default Sitemap;
