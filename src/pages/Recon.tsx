import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Globe, Play, Settings2, Terminal, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const mockLogs = [
  { id: 1, type: "info", message: "[INFO] Initializing reconnaissance module..." },
  { id: 2, type: "info", message: "[INFO] Resolving DNS for target domain..." },
  { id: 3, type: "ok", message: "[OK] DNS resolved: 192.168.1.100" },
  { id: 4, type: "info", message: "[INFO] Starting port scan..." },
  { id: 5, type: "ok", message: "[OK] Port 80 (HTTP) - Open" },
  { id: 6, type: "ok", message: "[OK] Port 443 (HTTPS) - Open" },
  { id: 7, type: "warn", message: "[WARN] Port 22 (SSH) - Open (Review security)" },
  { id: 8, type: "info", message: "[INFO] Enumerating subdomains..." },
  { id: 9, type: "ok", message: "[OK] Found: api.example.com" },
  { id: 10, type: "ok", message: "[OK] Found: admin.example.com" },
  { id: 11, type: "critical", message: "[CRITICAL] SQLi vulnerability detected on /login" },
  { id: 12, type: "info", message: "[INFO] Scan complete. 14 findings identified." },
];

const mockResults = [
  { id: 1, severity: "critical", name: "SQL Injection", endpoint: "/api/v1/login", status: "Open" },
  { id: 2, severity: "critical", name: "Remote Code Execution", endpoint: "/admin/upload", status: "Open" },
  { id: 3, severity: "high", name: "Cross-Site Scripting (XSS)", endpoint: "/search", status: "Open" },
  { id: 4, severity: "high", name: "Insecure Direct Object Reference", endpoint: "/api/users/{id}", status: "Open" },
  { id: 5, severity: "medium", name: "Missing Security Headers", endpoint: "/*", status: "Open" },
  { id: 6, severity: "low", name: "Information Disclosure", endpoint: "/robots.txt", status: "Informational" },
];

export default function Recon() {
  const [targetUrl, setTargetUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<typeof mockLogs>([]);
  const [scanOptions, setScanOptions] = useState({
    deepCrawl: true,
    subdomainEnum: true,
    apiDiscovery: false,
  });

  const startScan = () => {
    if (!targetUrl) return;
    setIsScanning(true);
    setLogs([]);
    
    // Simulate log entries appearing
    mockLogs.forEach((log, index) => {
      setTimeout(() => {
        setLogs((prev) => [...prev, log]);
        if (index === mockLogs.length - 1) {
          setIsScanning(false);
        }
      }, (index + 1) * 500);
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Web Reconnaissance</h1>
        <p className="text-muted-foreground">Discover vulnerabilities and map attack surfaces</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <GlassCard className="lg:col-span-1">
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
                />
              </div>
            </div>

            <Button
              className="w-full gap-2 mt-4"
              onClick={startScan}
              disabled={isScanning || !targetUrl}
            >
              <Play className="w-4 h-4" />
              {isScanning ? "Scanning..." : "Launch Recon"}
            </Button>
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
                    className={`py-1 ${
                      log.type === "ok"
                        ? "text-success"
                        : log.type === "warn"
                        ? "text-warning"
                        : log.type === "critical"
                        ? "text-destructive"
                        : "text-muted-foreground"
                    }`}
                  >
                    {log.message}
                  </motion.div>
                ))
              )}
            </AnimatePresence>
            {logs.length > 0 && (
              <span className="text-success animate-terminal-blink">█</span>
            )}
          </div>
        </GlassCard>
      </div>

      {/* Results Table */}
      <GlassCard>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Scan Results</h3>
          <Button variant="outline" size="sm" className="gap-2">
            <ExternalLink className="w-4 h-4" />
            Export Report
          </Button>
        </div>

        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/30 hover:bg-muted/30">
                <TableHead className="w-24">Severity</TableHead>
                <TableHead>Vulnerability</TableHead>
                <TableHead>Endpoint</TableHead>
                <TableHead className="w-32">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockResults.map((result) => (
                <TableRow key={result.id} className="hover:bg-muted/20">
                  <TableCell>
                    <StatusBadge
                      variant={
                        result.severity === "critical"
                          ? "critical"
                          : result.severity === "high"
                          ? "high"
                          : result.severity === "medium"
                          ? "medium"
                          : "low"
                      }
                    >
                      {result.severity}
                    </StatusBadge>
                  </TableCell>
                  <TableCell className="font-medium">{result.name}</TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {result.endpoint}
                  </TableCell>
                  <TableCell>
                    <StatusBadge variant={result.status === "Open" ? "critical" : "info"} dot>
                      {result.status}
                    </StatusBadge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GlassCard>
    </div>
  );
}