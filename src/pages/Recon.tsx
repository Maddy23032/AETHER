/**
 * Recon Page - Web Reconnaissance Dashboard
 * Integrates with AETHER Reconnaissance API for security scanning
 */

import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Globe,
  Play,
  Settings2,
  Terminal,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Wifi,
  WifiOff,
  ChevronDown,
  ChevronRight,
  Layers,
  Target,
  Shield,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { GlassCard } from "@/components/ui/glass-card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { useReconScan } from "@/hooks/useReconScan";
import { RECON_TOOLS } from "@/services/reconService";
import { setApiBaseUrl, getApiBaseUrl, resetApiBaseUrl } from "@/services/api";
import {
  ToolGrid,
  ToolOptionsPanel,
  ScanProgress,
  ResultsTable,
  ResultsTabs,
} from "@/components/recon";
import type { ToolId, ToolOptions } from "@/services/types/recon.types";

// Quick scan presets
const SCAN_PRESETS = {
  quick: {
    name: "Quick Scan",
    description: "Fast overview with essential tools",
    tools: ["httpx", "whatweb", "nmap"] as ToolId[],
  },
  standard: {
    name: "Standard Scan",
    description: "Balanced scan with common tools",
    tools: ["nmap", "whatweb", "nikto", "subfinder", "dnsenum"] as ToolId[],
  },
  comprehensive: {
    name: "Comprehensive Scan",
    description: "Full scan with all available tools",
    tools: RECON_TOOLS.map((t) => t.id) as ToolId[],
  },
  vuln: {
    name: "Vulnerability Focus",
    description: "Focus on vulnerability detection",
    tools: ["nmap", "nikto", "dirsearch", "gobuster"] as ToolId[],
  },
  osint: {
    name: "OSINT Focus",
    description: "Gather open-source intelligence",
    tools: ["theharvester", "dnsenum", "subfinder", "amass"] as ToolId[],
  },
};

export default function Recon() {
  // State
  const [targetUrl, setTargetUrl] = useState("");
  const [selectedTools, setSelectedTools] = useState<ToolId[]>(["httpx", "whatweb", "nmap"]);
  const [toolOptions, setToolOptions] = useState<Partial<Record<ToolId, ToolOptions>>>({});
  const [showToolConfig, setShowToolConfig] = useState(false);
  const [activeTab, setActiveTab] = useState("findings");
  const [apiUrl, setApiUrl] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('aether_api_url') || 'http://localhost:8000';
    }
    return 'http://localhost:8000';
  });
  const [showApiConfig, setShowApiConfig] = useState(false);
  const consoleRef = useRef<HTMLDivElement>(null);

  // Hooks
  const { toast } = useToast();
  const {
    status,
    logs,
    results,
    findings,
    progress,
    isApiAvailable,
    startScan,
    cancelScan,
    resetScan,
    checkApiStatus,
  } = useReconScan();

  // Check API status on mount
  useEffect(() => {
    checkApiStatus();
    const interval = setInterval(checkApiStatus, 30000); // Check every 30 seconds
    return () => clearInterval(interval);
  }, [checkApiStatus]);

  // Auto-scroll console
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logs]);

  // Calculate findings count by severity
  const findingsCount = useMemo(() => {
    return {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };
  }, [findings]);

  // Handle tool toggle
  const handleToolToggle = useCallback((toolId: ToolId) => {
    setSelectedTools((prev) =>
      prev.includes(toolId)
        ? prev.filter((t) => t !== toolId)
        : [...prev, toolId]
    );
  }, []);

  // Select all tools
  const handleSelectAll = useCallback(() => {
    setSelectedTools(RECON_TOOLS.map((t) => t.id));
  }, []);

  // Deselect all tools
  const handleDeselectAll = useCallback(() => {
    setSelectedTools([]);
  }, []);

  // Apply preset
  const applyPreset = useCallback((presetKey: keyof typeof SCAN_PRESETS) => {
    setSelectedTools(SCAN_PRESETS[presetKey].tools);
    toast({
      title: "Preset Applied",
      description: `${SCAN_PRESETS[presetKey].name}: ${SCAN_PRESETS[presetKey].tools.length} tools selected`,
    });
  }, [toast]);

  // Handle options change
  const handleOptionsChange = useCallback((toolId: ToolId, options: ToolOptions) => {
    setToolOptions((prev) => ({
      ...prev,
      [toolId]: options,
    }));
  }, []);

  // Validate target URL
  const isValidTarget = useCallback((target: string): boolean => {
    if (!target.trim()) return false;
    // Basic domain/URL validation
    const domainRegex = /^(?:https?:\/\/)?(?:[\w-]+\.)+[\w-]+(?:\/.*)?$/i;
    const ipRegex = /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?:\/.*)?$/;
    return domainRegex.test(target) || ipRegex.test(target);
  }, []);

  // Validate API URL
  const isValidApiUrl = useCallback((url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }, []);

  // Handle API URL change
  const handleApiUrlChange = useCallback((newUrl: string) => {
    setApiUrl(newUrl);
    if (isValidApiUrl(newUrl)) {
      setApiBaseUrl(newUrl);
      // Recheck API availability with new URL
      checkApiStatus();
      toast({
        title: "API URL Updated",
        description: `Now using: ${newUrl}`,
      });
    }
  }, [isValidApiUrl, checkApiStatus, toast]);

  // Reset API URL to default
  const handleResetApiUrl = useCallback(() => {
    resetApiBaseUrl();
    const defaultUrl = 'http://localhost:8000';
    setApiUrl(defaultUrl);
    checkApiStatus();
    toast({
      title: "API URL Reset",
      description: `Reset to default: ${defaultUrl}`,
    });
  }, [checkApiStatus, toast]);

  // Start scan
  const handleStartScan = useCallback(async () => {
    if (!targetUrl.trim()) {
      toast({
        variant: "destructive",
        title: "Target Required",
        description: "Please enter a target URL or domain to scan.",
      });
      return;
    }

    if (!isValidTarget(targetUrl)) {
      toast({
        variant: "destructive",
        title: "Invalid Target",
        description: "Please enter a valid URL or domain (e.g., example.com).",
      });
      return;
    }

    if (selectedTools.length === 0) {
      toast({
        variant: "destructive",
        title: "No Tools Selected",
        description: "Please select at least one reconnaissance tool.",
      });
      return;
    }

    if (!isApiAvailable) {
      toast({
        variant: "destructive",
        title: "API Unavailable",
        description: "The reconnaissance API is not available. Please ensure the server is running.",
      });
      return;
    }

    try {
      await startScan(targetUrl, selectedTools, toolOptions);
      toast({
        title: "Scan Complete",
        description: `Found ${findings.length} items across ${selectedTools.length} tools.`,
      });
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Scan Failed",
        description: error instanceof Error ? error.message : "An error occurred during the scan.",
      });
    }
  }, [targetUrl, selectedTools, toolOptions, isApiAvailable, startScan, findings.length, toast, isValidTarget]);

  // Reset everything
  const handleReset = useCallback(() => {
    resetScan();
    setTargetUrl("");
    setActiveTab("findings");
    toast({
      title: "Reset Complete",
      description: "All scan data has been cleared.",
    });
  }, [resetScan, toast]);

  // Determine log color
  const getLogColor = (type: string) => {
    switch (type) {
      case "success":
        return "text-success";
      case "warning":
        return "text-warning";
      case "error":
        return "text-destructive";
      default:
        return "text-muted-foreground";
    }
  };

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              Web Reconnaissance
            </h1>
            <p className="text-muted-foreground">
              Discover vulnerabilities and map attack surfaces using integrated security tools
            </p>
          </div>

          {/* API Status */}
          <Tooltip>
            <TooltipTrigger asChild>
              <div
                className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
                  isApiAvailable
                    ? "bg-success/20 text-success"
                    : "bg-destructive/20 text-destructive"
                }`}
              >
                {isApiAvailable ? (
                  <>
                    <Wifi className="w-4 h-4" />
                    API Connected
                  </>
                ) : (
                  <>
                    <WifiOff className="w-4 h-4" />
                    API Offline
                  </>
                )}
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {isApiAvailable
                ? "Connected to AETHER Reconnaissance API"
                : "Cannot connect to API. Ensure the server is running on localhost:8000"}
            </TooltipContent>
          </Tooltip>
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Left Column - Configuration */}
          <div className="xl:col-span-1 space-y-6">
            {/* API Configuration */}
            <GlassCard>
              <Collapsible open={showApiConfig} onOpenChange={setShowApiConfig}>
                <CollapsibleTrigger asChild>
                  <button className="flex items-center justify-between w-full mb-4">
                    <div className="flex items-center gap-2">
                      {isApiAvailable ? (
                        <Wifi className="w-5 h-5 text-success" />
                      ) : (
                        <WifiOff className="w-5 h-5 text-destructive" />
                      )}
                      <h3 className="text-lg font-semibold">API Configuration</h3>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        className={isApiAvailable ? "bg-success/20 text-success" : "bg-destructive/20 text-destructive"}
                      >
                        {isApiAvailable ? "Connected" : "Offline"}
                      </Badge>
                      {showApiConfig ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </div>
                  </button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="space-y-3 pt-2">
                    <div className="space-y-2">
                      <Label htmlFor="api-url">API Base URL</Label>
                      <div className="flex gap-2">
                        <Input
                          id="api-url"
                          placeholder="http://localhost:8000"
                          value={apiUrl}
                          onChange={(e) => setApiUrl(e.target.value)}
                          onBlur={(e) => handleApiUrlChange(e.target.value)}
                          className="flex-1 bg-muted/50 border-border font-mono text-sm"
                          disabled={status === "running"}
                        />
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="outline"
                              size="icon"
                              onClick={handleResetApiUrl}
                              disabled={status === "running"}
                            >
                              <RotateCcw className="w-4 h-4" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Reset to default URL</TooltipContent>
                        </Tooltip>
                      </div>
                      {apiUrl && !isValidApiUrl(apiUrl) && (
                        <p className="text-xs text-destructive flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          Please enter a valid URL (e.g., http://localhost:8000)
                        </p>
                      )}
                      <p className="text-xs text-muted-foreground">
                        Configure the reconnaissance API endpoint. Changes are saved automatically.
                      </p>
                    </div>
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </GlassCard>

            {/* Target Configuration */}
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <Target className="w-5 h-5 text-primary" />
                <h3 className="text-lg font-semibold">Target Configuration</h3>
              </div>

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="target">Target URL / Domain</Label>
                  <div className="relative">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="target"
                      placeholder="example.com or https://example.com"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      className="pl-10 bg-muted/50 border-border"
                      disabled={status === "running"}
                    />
                  </div>
                  {targetUrl && !isValidTarget(targetUrl) && (
                    <p className="text-xs text-destructive flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Please enter a valid domain or URL
                    </p>
                  )}
                </div>

                {/* Scan Presets */}
                <div className="space-y-2">
                  <Label>Quick Presets</Label>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(SCAN_PRESETS).map(([key, preset]) => (
                      <Tooltip key={key}>
                        <TooltipTrigger asChild>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => applyPreset(key as keyof typeof SCAN_PRESETS)}
                            disabled={status === "running"}
                          >
                            {preset.name}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{preset.description}</p>
                          <p className="text-xs text-muted-foreground">
                            {preset.tools.length} tools
                          </p>
                        </TooltipContent>
                      </Tooltip>
                    ))}
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex gap-2 pt-4 border-t border-border">
                  <Button
                    className="flex-1 gap-2"
                    onClick={handleStartScan}
                    disabled={
                      status === "running" ||
                      !targetUrl ||
                      !isValidTarget(targetUrl) ||
                      selectedTools.length === 0 ||
                      !isApiAvailable
                    }
                  >
                    <Play className="w-4 h-4" />
                    {status === "running" ? "Scanning..." : "Launch Recon"}
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={handleReset}
                    disabled={status === "running"}
                  >
                    <RotateCcw className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </GlassCard>

            {/* Tool Options (Collapsible) */}
            <GlassCard>
              <Collapsible open={showToolConfig} onOpenChange={setShowToolConfig}>
                <CollapsibleTrigger asChild>
                  <button className="flex items-center justify-between w-full">
                    <div className="flex items-center gap-2">
                      <Settings2 className="w-5 h-5 text-primary" />
                      <h3 className="text-lg font-semibold">Tool Options</h3>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline">{selectedTools.length} selected</Badge>
                      {showToolConfig ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </div>
                  </button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="pt-4">
                    <ToolOptionsPanel
                      selectedTools={selectedTools}
                      options={toolOptions}
                      onOptionsChange={handleOptionsChange}
                      disabled={status === "running"}
                    />
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </GlassCard>

            {/* Scan Progress */}
            {status !== "idle" && (
              <ScanProgress
                status={status}
                progress={progress}
                onCancel={cancelScan}
                findingsCount={status === "completed" ? findingsCount : undefined}
              />
            )}
          </div>

          {/* Right Column - Tools & Console */}
          <div className="xl:col-span-2 space-y-6">
            {/* Tool Selection Grid */}
            <GlassCard>
              <div className="flex items-center gap-2 mb-4">
                <Layers className="w-5 h-5 text-primary" />
                <h3 className="text-lg font-semibold">Reconnaissance Tools</h3>
              </div>
              <ToolGrid
                selectedTools={selectedTools}
                onToolToggle={handleToolToggle}
                onSelectAll={handleSelectAll}
                onDeselectAll={handleDeselectAll}
                disabled={status === "running"}
              />
            </GlassCard>

            {/* Live Console */}
            <GlassCard className="bg-background/95">
              <div className="flex items-center gap-2 mb-4">
                <Terminal className="w-5 h-5 text-success" />
                <h3 className="text-lg font-semibold">Live Console</h3>
                {status === "running" && (
                  <span className="ml-auto flex items-center gap-2 text-xs text-success">
                    <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
                    Scanning
                  </span>
                )}
                {status === "completed" && (
                  <span className="ml-auto flex items-center gap-2 text-xs text-success">
                    <CheckCircle2 className="w-4 h-4" />
                    Complete
                  </span>
                )}
              </div>

              <div
                ref={consoleRef}
                className="bg-background rounded-lg p-4 h-72 overflow-y-auto scrollbar-thin font-mono text-sm"
              >
                <AnimatePresence mode="popLayout">
                  {logs.length === 0 ? (
                    <div className="flex items-center justify-center h-full text-muted-foreground">
                      <span>Awaiting scan initiation...</span>
                      <span className="ml-1 animate-pulse">█</span>
                    </div>
                  ) : (
                    logs.map((log) => (
                      <motion.div
                        key={log.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`py-0.5 ${getLogColor(log.type)}`}
                      >
                        <span className="opacity-50 mr-2">
                          [{log.timestamp.toLocaleTimeString()}]
                        </span>
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
        </div>

        {/* Results Section */}
        <GlassCard>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <div className="flex items-center justify-between mb-4">
              <TabsList>
                <TabsTrigger value="findings" className="gap-2">
                  <Shield className="w-4 h-4" />
                  Findings
                  {findings.length > 0 && (
                    <Badge variant="secondary" className="ml-1">
                      {findings.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="raw" className="gap-2">
                  <Terminal className="w-4 h-4" />
                  Tool Outputs
                  {results.length > 0 && (
                    <Badge variant="secondary" className="ml-1">
                      {results.length}
                    </Badge>
                  )}
                </TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="findings">
              <ResultsTable findings={findings} results={results} />
            </TabsContent>

            <TabsContent value="raw">
              <ResultsTabs results={results} />
            </TabsContent>
          </Tabs>
        </GlassCard>
      </div>
    </TooltipProvider>
  );
}