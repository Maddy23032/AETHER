/**
 * Enumeration Page - Vulnerability Scanner Dashboard
 * Integrates with AETHER Scan API for vulnerability scanning with WebSocket support
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Globe, Play, Settings2, Terminal, ExternalLink, StopCircle, FileJson, FileText, FileCode, Download, Save, Search } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "sonner";

import { createScan, getScan, getScanResults, cancelScan } from "@/services/scanService";
import { ScanWebSocket } from "@/services/websocket";
import { saveScan, saveVulnerabilities, updateScan } from "@/services/supabaseService";
import { exportToJSON, exportToCSV, exportToHTML } from "@/services/exportService";
import type {
  ScanConfig,
  Vulnerability,
  ScanStatus,
  WSMessage,
  WSLogData,
  WSProgressData,
} from "@/types/scan";
import type { Vulnerability as DBVulnerability, VulnerabilityInsert } from "@/types/database";

interface LogEntry {
  id: number;
  type: "info" | "ok" | "warn" | "critical";
  message: string;
}

export default function Enumeration() {
  const queryClient = useQueryClient();
  const [targetUrl, setTargetUrl] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("");
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const wsRef = useRef<ScanWebSocket | null>(null);
  const logIdRef = useRef(0);

  const [scanOptions, setScanOptions] = useState({
    deepCrawl: true,
    subdomainEnum: false,
    apiDiscovery: false,
  });
  const [savedToSupabase, setSavedToSupabase] = useState(false);
  const [scanStartTime, setScanStartTime] = useState<string | null>(null);

  // Query for scan status
  const { data: scanJob } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (data) => {
      if (data?.state?.data?.status === "running" || data?.state?.data?.status === "pending") {
        return 2000;
      }
      return false;
    },
  });

  const isScanning = scanJob?.status === "running" || scanJob?.status === "pending";

  // Mutation for starting scan
  const startScanMutation = useMutation({
    mutationFn: createScan,
    onSuccess: async (data) => {
      setScanId(data.scan_id);
      setLogs([]);
      setVulnerabilities([]);
      setProgress(0);
      setSavedToSupabase(false);
      setScanStartTime(new Date().toISOString());
      toast.success("Scan started", { description: `Scanning ${targetUrl}` });

      // Save scan to Supabase
      try {
        await saveScan({
          id: data.scan_id,
          target_url: targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`,
          status: "running",
          started_at: new Date().toISOString(),
          config: {
            deep_crawl: scanOptions.deepCrawl,
            subdomain_enum: scanOptions.subdomainEnum,
            api_discovery: scanOptions.apiDiscovery,
          },
        });
      } catch (err) {
        console.warn("Failed to save scan to Supabase:", err);
      }
    },
    onError: (error: Error) => {
      toast.error("Failed to start scan", { description: error.message });
    },
  });

  // Mutation for cancelling scan
  const cancelScanMutation = useMutation({
    mutationFn: cancelScan,
    onSuccess: () => {
      toast.info("Scan cancelled");
      queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
    },
  });

  // Handle WebSocket messages
  const handleWSMessage = useCallback((message: WSMessage) => {
    switch (message.type) {
      case "log": {
        const logData = message.data as WSLogData;
        logIdRef.current += 1;
        setLogs((prev) => [
          ...prev,
          {
            id: logIdRef.current,
            type: logData.log_type,
            message: `[${logData.log_type.toUpperCase()}] ${logData.message}`,
          },
        ]);
        break;
      }
      case "progress": {
        const progressData = message.data as WSProgressData;
        setProgress(progressData.percentage);
        setPhase(progressData.phase);
        break;
      }
      case "finding": {
        const vuln = message.data as Vulnerability;
        setVulnerabilities((prev) => [...prev, vuln]);
        break;
      }
      case "status": {
        const statusData = message.data as { status: ScanStatus };
        if (statusData.status === "completed") {
          toast.success("Scan completed!");
          queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
        } else if (statusData.status === "failed") {
          toast.error("Scan failed");
          // Update Supabase with failed status
          if (scanId) {
            updateScan(scanId, { status: "failed" }).catch(console.warn);
          }
        }
        break;
      }
    }
  }, [scanId, queryClient]);

  // Connect WebSocket when scan starts
  useEffect(() => {
    if (scanId && isScanning) {
      wsRef.current = new ScanWebSocket(
        scanId,
        handleWSMessage,
        () => console.error("WebSocket error"),
        () => console.log("WebSocket closed")
      );
      wsRef.current.connect();

      return () => {
        wsRef.current?.disconnect();
      };
    }
  }, [scanId, isScanning, handleWSMessage]);

  // Fetch results when scan completes and save to Supabase
  useEffect(() => {
    if (scanJob?.status === "completed" && scanId && !savedToSupabase) {
      getScanResults(scanId).then(async (results) => {
        setVulnerabilities(results.vulnerabilities);

        // Save to Supabase
        try {
          // Convert vulnerabilities to database format
          const dbVulns: VulnerabilityInsert[] = results.vulnerabilities.map((v) => ({
            scan_id: scanId,
            name: v.name,
            severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
            confidence: v.confidence,
            owasp_category: v.owasp_category,
            cwe_id: v.cwe_id || null,
            endpoint: v.endpoint,
            method: v.method || "GET",
            parameter: v.parameter || null,
            evidence: v.evidence || null,
            description: v.description || "",
            remediation: v.remediation || "",
          }));

          if (dbVulns.length > 0) {
            await saveVulnerabilities(dbVulns);
          }

          // Update scan status in Supabase
          await updateScan(scanId, {
            status: "completed",
            completed_at: new Date().toISOString(),
            stats: {
              urls_scanned: results.urls_scanned || 0,
              requests_made: results.requests_made || 0,
              vulnerabilities_found: results.vulnerabilities.length,
              duration_seconds: results.duration_seconds || 0,
            },
          });

          setSavedToSupabase(true);
          toast.success("Results saved to database");
        } catch (err) {
          console.warn("Failed to save results to Supabase:", err);
        }
      }).catch(console.error);
    }
  }, [scanJob?.status, scanId, savedToSupabase]);

  const handleStartScan = () => {
    if (!targetUrl) return;

    const config: Partial<ScanConfig> = {
      deep_crawl: scanOptions.deepCrawl,
      subdomain_enum: scanOptions.subdomainEnum,
      api_discovery: scanOptions.apiDiscovery,
      enable_sqli: true,
      enable_xss: true,
      enable_ssrf: true,
      enable_path_traversal: true,
      enable_security_misconfig: true,
      enable_sensitive_data: true,
    };

    // Ensure URL has protocol
    let url = targetUrl;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = `https://${url}`;
    }

    startScanMutation.mutate({ target_url: url, config });
  };

  const handleCancel = () => {
    if (scanId) {
      cancelScanMutation.mutate(scanId);
    }
  };

  const getSeverityVariant = (severity: string) => {
    switch (severity) {
      case "critical": return "critical";
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      default: return "info";
    }
  };

  // Export handlers
  const handleExport = (format: "json" | "csv" | "html") => {
    if (!scanId || vulnerabilities.length === 0) return;

    const exportData = {
      id: scanId,
      targetUrl: targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`,
      createdAt: scanStartTime || new Date().toISOString(),
      completedAt: scanJob?.completed_at,
      vulnerabilities: vulnerabilities.map((v) => ({
        id: v.id,
        scan_id: scanId,
        name: v.name,
        severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
        confidence: v.confidence,
        owasp_category: v.owasp_category,
        cwe_id: v.cwe_id || null,
        endpoint: v.endpoint,
        method: v.method || "GET",
        parameter: v.parameter || null,
        evidence: v.evidence || null,
        description: v.description || "",
        remediation: v.remediation || "",
        request_sample: null,
        response_sample: null,
        created_at: new Date().toISOString(),
      })) as DBVulnerability[],
    };

    switch (format) {
      case "json":
        exportToJSON(exportData);
        toast.success("Exported as JSON");
        break;
      case "csv":
        exportToCSV(exportData);
        toast.success("Exported as CSV");
        break;
      case "html":
        exportToHTML(exportData);
        toast.success("Exported as HTML Report");
        break;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Search className="w-6 h-6 text-primary" />
            Vulnerability Enumeration
          </h1>
          <p className="text-muted-foreground">
            Scan web applications for security vulnerabilities with automated detection
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <GlassCard>
          <div className="flex items-center gap-2 mb-4">
            <Settings2 className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-semibold">Scan Configuration</h3>
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="target">Target URL</Label>
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="target"
                  placeholder="example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="pl-10 bg-muted/50 border-border"
                  disabled={isScanning}
                />
              </div>
            </div>

            <div className="space-y-3 pt-4 border-t border-border">
              <div className="flex items-center justify-between">
                <Label htmlFor="deep-crawl" className="cursor-pointer">Deep Crawl</Label>
                <Switch
                  id="deep-crawl"
                  checked={scanOptions.deepCrawl}
                  onCheckedChange={(checked) =>
                    setScanOptions((prev) => ({ ...prev, deepCrawl: checked }))
                  }
                  disabled={isScanning}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="subdomain" className="cursor-pointer">Subdomain Enumeration</Label>
                <Switch
                  id="subdomain"
                  checked={scanOptions.subdomainEnum}
                  onCheckedChange={(checked) =>
                    setScanOptions((prev) => ({ ...prev, subdomainEnum: checked }))
                  }
                  disabled={isScanning}
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="api" className="cursor-pointer">API Discovery</Label>
                <Switch
                  id="api"
                  checked={scanOptions.apiDiscovery}
                  onCheckedChange={(checked) =>
                    setScanOptions((prev) => ({ ...prev, apiDiscovery: checked }))
                  }
                  disabled={isScanning}
                />
              </div>
            </div>

            {isScanning ? (
              <Button
                variant="destructive"
                className="w-full gap-2 mt-4"
                onClick={handleCancel}
              >
                <StopCircle className="w-4 h-4" />
                Cancel Scan
              </Button>
            ) : (
              <Button
                className="w-full gap-2 mt-4"
                onClick={handleStartScan}
                disabled={startScanMutation.isPending || !targetUrl}
              >
                <Play className="w-4 h-4" />
                {startScanMutation.isPending ? "Starting..." : "Start Enumeration"}
              </Button>
            )}

            {/* Progress */}
            {isScanning && (
              <div className="space-y-2 pt-4">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground capitalize">{phase || "Initializing"}</span>
                  <span className="text-muted-foreground">{progress.toFixed(0)}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
            )}
          </div>
        </GlassCard>

        {/* Live Console */}
        <GlassCard className="lg:col-span-2 bg-background/95">
          <div className="flex items-center gap-2 mb-4">
            <Terminal className="w-5 h-5 text-success" />
            <h3 className="text-lg font-semibold">Live Console</h3>
            {isScanning && (
              <span className="ml-auto flex items-center gap-2 text-xs text-success">
                <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
                Scanning
              </span>
            )}
          </div>

          <div className="bg-background rounded-lg p-4 h-72 overflow-y-auto scrollbar-thin font-mono text-sm">
            <AnimatePresence>
              {logs.length === 0 ? (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  <span>Awaiting scan initiation...</span>
                  <span className="ml-1 animate-terminal-blink">█</span>
                </div>
              ) : (
                logs.map((log) => (
                  <motion.div
                    key={log.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={`py-0.5 ${
                      log.type === "ok" ? "text-success" :
                      log.type === "warn" ? "text-warning" :
                      log.type === "critical" ? "text-destructive" :
                      "text-muted-foreground"
                    }`}
                  >
                    {log.message}
                  </motion.div>
                ))
              )}
            </AnimatePresence>
            {logs.length > 0 && (
              <span className="text-success animate-pulse">█</span>
            )}
          </div>
        </GlassCard>
      </div>

      {/* Results Table */}
      <GlassCard>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4">
            <h3 className="text-lg font-semibold">Scan Results</h3>
            {vulnerabilities.length > 0 && (
              <span className="text-sm text-muted-foreground">
                {vulnerabilities.length} vulnerabilities found
              </span>
            )}
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2" disabled={vulnerabilities.length === 0}>
                <Download className="w-4 h-4" />
                Export Report
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => handleExport("json")}>
                <FileJson className="w-4 h-4 mr-2" />
                Export as JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport("csv")}>
                <FileText className="w-4 h-4 mr-2" />
                Export as CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport("html")}>
                <FileCode className="w-4 h-4 mr-2" />
                Export as HTML Report
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/30 hover:bg-muted/30">
                <TableHead className="w-24">Severity</TableHead>
                <TableHead>Vulnerability</TableHead>
                <TableHead>Endpoint</TableHead>
                <TableHead className="w-32">Confidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulnerabilities.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                    {isScanning ? "Scanning for vulnerabilities..." : "No vulnerabilities found yet. Start a scan to discover issues."}
                  </TableCell>
                </TableRow>
              ) : (
                vulnerabilities.map((vuln) => (
                  <TableRow key={vuln.id} className="hover:bg-muted/20">
                    <TableCell>
                      <StatusBadge variant={getSeverityVariant(vuln.severity)}>
                        {vuln.severity}
                      </StatusBadge>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">{vuln.name}</div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {vuln.owasp_category}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-sm text-muted-foreground">
                      <span className="text-primary">{vuln.method}</span> {vuln.endpoint}
                      {vuln.parameter && (
                        <span className="text-warning ml-2">?{vuln.parameter}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary"
                            style={{ width: `${vuln.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {(vuln.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </GlassCard>
    </div>
  );
}
