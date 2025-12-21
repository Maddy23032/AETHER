/**
 * ResultsTable Component
 * Display scan findings in a sortable, filterable table
 */

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/ui/status-badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Search,
  ExternalLink,
  ChevronUp,
  ChevronDown,
  Eye,
  Download,
  FileJson,
  FileText,
} from "lucide-react";
import type { ScanResultItem, Severity, ToolId } from "@/services/types/recon.types";
import type { ReconResponse } from "@/services/types/recon.types";

interface ResultsTableProps {
  findings: ScanResultItem[];
  results: ReconResponse[];
  onExport?: (format: 'json' | 'csv') => void;
}

type SortField = 'severity' | 'name' | 'tool' | 'endpoint';
type SortDirection = 'asc' | 'desc';

const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityColors: Record<Severity, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

export function ResultsTable({ findings, results, onExport }: ResultsTableProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [toolFilter, setToolFilter] = useState<ToolId | "all">("all");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [selectedFinding, setSelectedFinding] = useState<ScanResultItem | null>(null);

  // Get unique tools from findings
  const uniqueTools = useMemo(() => {
    return Array.from(new Set(findings.map(f => f.tool)));
  }, [findings]);

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let filtered = findings.filter((finding) => {
      // Search filter
      const matchesSearch =
        searchQuery === "" ||
        finding.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        finding.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (finding.endpoint?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false);

      // Severity filter
      const matchesSeverity =
        severityFilter === "all" || finding.severity === severityFilter;

      // Tool filter
      const matchesTool = toolFilter === "all" || finding.tool === toolFilter;

      return matchesSearch && matchesSeverity && matchesTool;
    });

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case "severity":
          comparison = severityOrder[a.severity] - severityOrder[b.severity];
          break;
        case "name":
          comparison = a.name.localeCompare(b.name);
          break;
        case "tool":
          comparison = a.tool.localeCompare(b.tool);
          break;
        case "endpoint":
          comparison = (a.endpoint || "").localeCompare(b.endpoint || "");
          break;
      }
      return sortDirection === "asc" ? comparison : -comparison;
    });

    return filtered;
  }, [findings, searchQuery, severityFilter, toolFilter, sortField, sortDirection]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const SortIndicator = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDirection === "asc" ? (
      <ChevronUp className="w-4 h-4" />
    ) : (
      <ChevronDown className="w-4 h-4" />
    );
  };

  const handleExportJson = () => {
    const data = {
      scanDate: new Date().toISOString(),
      totalFindings: findings.length,
      findings: findings,
      rawResults: results,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aether-scan-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCsv = () => {
    const headers = ["Severity", "Name", "Tool", "Endpoint", "Description", "Status"];
    const rows = findings.map((f) => [
      f.severity,
      f.name,
      f.tool,
      f.endpoint || "",
      f.description.replace(/"/g, '""'),
      f.status,
    ]);
    const csv = [
      headers.join(","),
      ...rows.map((r) => r.map((c) => `"${c}"`).join(",")),
    ].join("\n");
    
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aether-scan-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Count by severity
  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const finding of findings) {
      counts[finding.severity]++;
    }
    return counts;
  }, [findings]);

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium">No findings yet</p>
        <p className="text-sm">Run a scan to discover vulnerabilities and gather intelligence</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary badges */}
      <div className="flex flex-wrap gap-2">
        {severityCounts.critical > 0 && (
          <Badge variant="destructive">{severityCounts.critical} Critical</Badge>
        )}
        {severityCounts.high > 0 && (
          <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">
            {severityCounts.high} High
          </Badge>
        )}
        {severityCounts.medium > 0 && (
          <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
            {severityCounts.medium} Medium
          </Badge>
        )}
        {severityCounts.low > 0 && (
          <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
            {severityCounts.low} Low
          </Badge>
        )}
        {severityCounts.info > 0 && (
          <Badge variant="outline">{severityCounts.info} Info</Badge>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 bg-muted/50"
          />
        </div>

        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as Severity | "all")}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select value={toolFilter} onValueChange={(v) => setToolFilter(v as ToolId | "all")}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Tool" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tools</SelectItem>
            {uniqueTools.map((tool) => (
              <SelectItem key={tool} value={tool}>
                {tool}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={handleExportJson} title="Export as JSON">
            <FileJson className="w-4 h-4" />
          </Button>
          <Button variant="outline" size="icon" onClick={handleExportCsv} title="Export as CSV">
            <FileText className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Results count */}
      <p className="text-sm text-muted-foreground">
        Showing {filteredFindings.length} of {findings.length} findings
      </p>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/30 hover:bg-muted/30">
              <TableHead
                className="w-28 cursor-pointer select-none"
                onClick={() => toggleSort("severity")}
              >
                <div className="flex items-center gap-1">
                  Severity
                  <SortIndicator field="severity" />
                </div>
              </TableHead>
              <TableHead
                className="cursor-pointer select-none"
                onClick={() => toggleSort("name")}
              >
                <div className="flex items-center gap-1">
                  Finding
                  <SortIndicator field="name" />
                </div>
              </TableHead>
              <TableHead
                className="w-28 cursor-pointer select-none"
                onClick={() => toggleSort("tool")}
              >
                <div className="flex items-center gap-1">
                  Tool
                  <SortIndicator field="tool" />
                </div>
              </TableHead>
              <TableHead
                className="cursor-pointer select-none"
                onClick={() => toggleSort("endpoint")}
              >
                <div className="flex items-center gap-1">
                  Endpoint
                  <SortIndicator field="endpoint" />
                </div>
              </TableHead>
              <TableHead className="w-20">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <AnimatePresence mode="popLayout">
              {filteredFindings.map((finding) => (
                <motion.tr
                  key={finding.id}
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="hover:bg-muted/20 border-b border-border last:border-0"
                >
                  <TableCell>
                    <StatusBadge variant={severityColors[finding.severity] as any}>
                      {finding.severity}
                    </StatusBadge>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium text-sm">{finding.name}</p>
                      <p className="text-xs text-muted-foreground line-clamp-1">
                        {finding.description}
                      </p>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {finding.tool}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {finding.endpoint || "-"}
                  </TableCell>
                  <TableCell>
                    <Dialog>
                      <DialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => setSelectedFinding(finding)}
                        >
                          <Eye className="w-4 h-4" />
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="max-w-2xl">
                        <DialogHeader>
                          <DialogTitle className="flex items-center gap-2">
                            <StatusBadge variant={severityColors[finding.severity] as any}>
                              {finding.severity}
                            </StatusBadge>
                            {finding.name}
                          </DialogTitle>
                          <DialogDescription>
                            Discovered by {finding.tool}
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4 mt-4">
                          <div>
                            <h4 className="text-sm font-medium mb-1">Description</h4>
                            <p className="text-sm text-muted-foreground">
                              {finding.description}
                            </p>
                          </div>
                          {finding.endpoint && (
                            <div>
                              <h4 className="text-sm font-medium mb-1">Endpoint</h4>
                              <code className="text-sm bg-muted px-2 py-1 rounded">
                                {finding.endpoint}
                              </code>
                            </div>
                          )}
                          <div>
                            <h4 className="text-sm font-medium mb-1">Status</h4>
                            <Badge variant="outline">{finding.status}</Badge>
                          </div>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </TableCell>
                </motion.tr>
              ))}
            </AnimatePresence>
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export default ResultsTable;
