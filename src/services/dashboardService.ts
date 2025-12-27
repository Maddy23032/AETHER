/**
 * Dashboard Service - Aggregates data from all sources for the dashboard
 */

import { supabase } from "@/lib/supabase";
import type { Scan, Vulnerability, ReconFinding, MobileScan } from "@/types/database";

// ============================================================================
// TYPES
// ============================================================================

export interface DashboardStats {
  totalScans: number;
  totalVulnerabilities: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  infoVulns: number;
  reconScans: number;
  enumScans: number;
  mobileScans: number;
  activeScans: number;
  averageSecurityScore: number;
  lastScanTime: string | null;
}

export interface ScanTrendData {
  date: string;
  scans: number;
  vulnerabilities: number;
}

export interface SeverityDistribution {
  name: string;
  value: number;
  color: string;
}

export interface ScanTypeDistribution {
  name: string;
  value: number;
  color: string;
}

export interface RecentActivity {
  id: string;
  event: string;
  time: string;
  type: "success" | "critical" | "warning" | "info";
  scanType?: string;
  target?: string;
}

export interface TopVulnerability {
  id: string;
  name: string;
  severity: string;
  count: number;
  endpoint?: string;
  owaspCategory?: string;
}

export interface TargetSummary {
  target: string;
  scanCount: number;
  vulnCount: number;
  lastScanned: string;
  worstSeverity: string;
}

export interface MobileAppSummary {
  id: string;
  filename: string;
  packageName: string | null;
  appName: string | null;
  grade: string | null;
  securityScore: number | null;
  platform: string;
  scannedAt: string;
}

// ============================================================================
// DATA FETCHING FUNCTIONS
// ============================================================================

/**
 * Get comprehensive dashboard statistics
 */
export async function getDashboardStats(): Promise<DashboardStats> {
  try {
    // Fetch all data in parallel
    const [scansResult, vulnsResult] = await Promise.all([
      supabase.from("scans").select("id, status, scan_type, created_at"),
      supabase.from("vulnerabilities").select("severity"),
    ]);

    // Mobile scans might not exist, so handle separately
    let mobileScans: { id: string; security_score: number | null }[] = [];
    try {
      const mobileResult = await supabase.from("mobile_scans").select("id, security_score");
      mobileScans = mobileResult.data || [];
    } catch {
      mobileScans = [];
    }

    const scans = scansResult.data || [];
    const vulns = vulnsResult.data || [];

    // Calculate vulnerability counts by severity
    const vulnBySeverity = vulns.reduce((acc, v) => {
      acc[v.severity] = (acc[v.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Calculate scan counts by type
    const scansByType = scans.reduce((acc, s) => {
      acc[s.scan_type] = (acc[s.scan_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Calculate average mobile security score
    const mobileScoresValid = mobileScans.filter(m => m.security_score !== null);
    const avgSecurityScore = mobileScoresValid.length > 0
      ? Math.round(mobileScoresValid.reduce((sum, m) => sum + (m.security_score || 0), 0) / mobileScoresValid.length)
      : 0;

    // Get last scan time
    const lastScan = scans.sort((a, b) => 
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    )[0];

    return {
      totalScans: scans.length + mobileScans.length,
      totalVulnerabilities: vulns.length,
      criticalVulns: vulnBySeverity["critical"] || 0,
      highVulns: vulnBySeverity["high"] || 0,
      mediumVulns: vulnBySeverity["medium"] || 0,
      lowVulns: vulnBySeverity["low"] || 0,
      infoVulns: vulnBySeverity["info"] || 0,
      reconScans: scansByType["recon"] || 0,
      enumScans: scansByType["enumeration"] || 0,
      mobileScans: mobileScans.length,
      activeScans: scans.filter(s => s.status === "running").length,
      averageSecurityScore: avgSecurityScore,
      lastScanTime: lastScan?.created_at || null,
    };
  } catch (error) {
    console.error("Failed to fetch dashboard stats:", error);
    throw error;
  }
}

/**
 * Get scan trend data for the last N days
 */
export async function getScanTrendData(days: number = 30): Promise<ScanTrendData[]> {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const [scansResult, vulnsResult] = await Promise.all([
      supabase
        .from("scans")
        .select("created_at")
        .gte("created_at", startDate.toISOString()),
      supabase
        .from("vulnerabilities")
        .select("created_at")
        .gte("created_at", startDate.toISOString()),
    ]);

    const scans = scansResult.data || [];
    const vulns = vulnsResult.data || [];

    // Group by date
    const dateMap: Record<string, { scans: number; vulnerabilities: number }> = {};
    
    // Initialize all days
    for (let i = 0; i < days; i++) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split("T")[0];
      dateMap[dateStr] = { scans: 0, vulnerabilities: 0 };
    }

    // Count scans per day
    scans.forEach(s => {
      const dateStr = s.created_at.split("T")[0];
      if (dateMap[dateStr]) {
        dateMap[dateStr].scans++;
      }
    });

    // Count vulns per day
    vulns.forEach(v => {
      const dateStr = v.created_at.split("T")[0];
      if (dateMap[dateStr]) {
        dateMap[dateStr].vulnerabilities++;
      }
    });

    // Convert to array and sort
    return Object.entries(dateMap)
      .map(([date, data]) => ({
        date: new Date(date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
        scans: data.scans,
        vulnerabilities: data.vulnerabilities,
      }))
      .reverse();
  } catch (error) {
    console.error("Failed to fetch scan trend data:", error);
    return [];
  }
}

/**
 * Get severity distribution for pie chart
 */
export async function getSeverityDistribution(): Promise<SeverityDistribution[]> {
  try {
    const { data, error } = await supabase.from("vulnerabilities").select("severity");
    
    if (error) throw error;

    const counts = (data || []).reduce((acc, v) => {
      acc[v.severity] = (acc[v.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const colorMap: Record<string, string> = {
      critical: "hsl(0, 84%, 60%)",
      high: "hsl(25, 95%, 53%)",
      medium: "hsl(45, 93%, 47%)",
      low: "hsl(200, 80%, 50%)",
      info: "hsl(240, 5%, 65%)",
    };

    return Object.entries(counts).map(([severity, count]) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: count,
      color: colorMap[severity] || "hsl(240, 5%, 65%)",
    }));
  } catch (error) {
    console.error("Failed to fetch severity distribution:", error);
    return [];
  }
}

/**
 * Get scan type distribution
 */
export async function getScanTypeDistribution(): Promise<ScanTypeDistribution[]> {
  try {
    const scansResult = await supabase.from("scans").select("scan_type");
    
    // Mobile scans might not exist, so handle separately
    let mobileCount = 0;
    try {
      const mobileResult = await supabase.from("mobile_scans").select("id");
      mobileCount = (mobileResult.data || []).length;
    } catch {
      mobileCount = 0;
    }

    const scans = scansResult.data || [];

    const counts = scans.reduce((acc, s) => {
      acc[s.scan_type] = (acc[s.scan_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const colorMap: Record<string, string> = {
      recon: "hsl(239, 84%, 67%)",
      enumeration: "hsl(160, 84%, 39%)",
      mobile: "hsl(280, 65%, 60%)",
    };

    const result = [
      { name: "Recon", value: counts["recon"] || 0, color: colorMap.recon },
      { name: "Enumeration", value: counts["enumeration"] || 0, color: colorMap.enumeration },
      { name: "Mobile", value: mobileCount, color: colorMap.mobile },
    ];

    return result.filter(r => r.value > 0);
  } catch (error) {
    console.error("Failed to fetch scan type distribution:", error);
    return [];
  }
}

/**
 * Get recent activity from all scan types
 */
export async function getRecentActivity(limit: number = 10): Promise<RecentActivity[]> {
  try {
    const [scansResult, vulnsResult, findingsResult] = await Promise.all([
      supabase
        .from("scans")
        .select("id, target_url, status, scan_type, created_at, completed_at")
        .order("created_at", { ascending: false })
        .limit(limit),
      supabase
        .from("vulnerabilities")
        .select("id, name, severity, endpoint, created_at")
        .order("created_at", { ascending: false })
        .limit(limit),
      supabase
        .from("recon_findings")
        .select("id, name, severity, tool, created_at")
        .order("created_at", { ascending: false })
        .limit(limit),
    ]);
    
    // Mobile scans might not exist, so handle separately
    let mobileData: MobileScan[] = [];
    try {
      const mobileResult = await supabase
        .from("mobile_scans")
        .select("id, filename, grade, security_score, created_at")
        .order("created_at", { ascending: false })
        .limit(limit);
      mobileData = (mobileResult.data || []) as MobileScan[];
    } catch {
      mobileData = [];
    }

    const activities: RecentActivity[] = [];

    // Add scan events
    (scansResult.data || []).forEach(scan => {
      const status = scan.status === "completed" ? "success" : scan.status === "failed" ? "critical" : "info";
      activities.push({
        id: `scan-${scan.id}`,
        event: `${scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} scan ${scan.status} on ${scan.target_url}`,
        time: scan.completed_at || scan.created_at,
        type: status,
        scanType: scan.scan_type,
        target: scan.target_url,
      });
    });

    // Add vulnerability discoveries
    (vulnsResult.data || []).forEach(vuln => {
      const type = vuln.severity === "critical" ? "critical" : vuln.severity === "high" ? "warning" : "info";
      activities.push({
        id: `vuln-${vuln.id}`,
        event: `${vuln.severity.toUpperCase()} vulnerability found: ${vuln.name}`,
        time: vuln.created_at,
        type: type as "critical" | "warning" | "info",
      });
    });

    // Add recon findings
    (findingsResult.data || []).forEach(finding => {
      const type = finding.severity === "critical" ? "critical" : finding.severity === "high" ? "warning" : "info";
      activities.push({
        id: `finding-${finding.id}`,
        event: `[${finding.tool}] ${finding.name}`,
        time: finding.created_at,
        type: type as "critical" | "warning" | "info",
      });
    });

    // Add mobile scan events
    mobileData.forEach(mobile => {
      const type = mobile.grade === "F" || mobile.grade === "D" ? "warning" : "success";
      activities.push({
        id: `mobile-${mobile.id}`,
        event: `Mobile scan completed: ${mobile.filename} (Grade: ${mobile.grade || "N/A"})`,
        time: mobile.created_at,
        type: type as "warning" | "success",
        scanType: "mobile",
      });
    });

    // Sort by time and return top N
    return activities
      .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
      .slice(0, limit)
      .map(a => ({
        ...a,
        time: formatTimeAgo(a.time),
      }));
  } catch (error) {
    console.error("Failed to fetch recent activity:", error);
    return [];
  }
}

/**
 * Get top vulnerabilities by occurrence
 */
export async function getTopVulnerabilities(limit: number = 5): Promise<TopVulnerability[]> {
  try {
    const { data, error } = await supabase
      .from("vulnerabilities")
      .select("id, name, severity, endpoint, owasp_category");

    if (error) throw error;

    // Group by name and count
    const vulnMap = (data || []).reduce((acc, v) => {
      if (!acc[v.name]) {
        acc[v.name] = {
          id: v.id,
          name: v.name,
          severity: v.severity,
          count: 0,
          endpoint: v.endpoint,
          owaspCategory: v.owasp_category,
        };
      }
      acc[v.name].count++;
      return acc;
    }, {} as Record<string, TopVulnerability>);

    // Sort by count and severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return Object.values(vulnMap)
      .sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        return (severityOrder[a.severity as keyof typeof severityOrder] || 5) - 
               (severityOrder[b.severity as keyof typeof severityOrder] || 5);
      })
      .slice(0, limit);
  } catch (error) {
    console.error("Failed to fetch top vulnerabilities:", error);
    return [];
  }
}

/**
 * Get targets with most vulnerabilities
 */
export async function getTargetSummaries(limit: number = 5): Promise<TargetSummary[]> {
  try {
    const { data: scans, error: scanError } = await supabase
      .from("scans")
      .select("id, target_url, created_at");

    if (scanError) throw scanError;

    const { data: vulns, error: vulnError } = await supabase
      .from("vulnerabilities")
      .select("scan_id, severity");

    if (vulnError) throw vulnError;

    // Group vulnerabilities by scan
    const vulnsByScan = (vulns || []).reduce((acc, v) => {
      if (!acc[v.scan_id]) {
        acc[v.scan_id] = { count: 0, worstSeverity: "info" };
      }
      acc[v.scan_id].count++;
      
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      if ((severityOrder[v.severity as keyof typeof severityOrder] || 5) < 
          (severityOrder[acc[v.scan_id].worstSeverity as keyof typeof severityOrder] || 5)) {
        acc[v.scan_id].worstSeverity = v.severity;
      }
      
      return acc;
    }, {} as Record<string, { count: number; worstSeverity: string }>);

    // Group by target
    const targetMap = (scans || []).reduce((acc, s) => {
      if (!acc[s.target_url]) {
        acc[s.target_url] = {
          target: s.target_url,
          scanCount: 0,
          vulnCount: 0,
          lastScanned: s.created_at,
          worstSeverity: "info",
        };
      }
      acc[s.target_url].scanCount++;
      
      const scanVulns = vulnsByScan[s.id];
      if (scanVulns) {
        acc[s.target_url].vulnCount += scanVulns.count;
        
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        if ((severityOrder[scanVulns.worstSeverity as keyof typeof severityOrder] || 5) < 
            (severityOrder[acc[s.target_url].worstSeverity as keyof typeof severityOrder] || 5)) {
          acc[s.target_url].worstSeverity = scanVulns.worstSeverity;
        }
      }
      
      if (new Date(s.created_at) > new Date(acc[s.target_url].lastScanned)) {
        acc[s.target_url].lastScanned = s.created_at;
      }
      
      return acc;
    }, {} as Record<string, TargetSummary>);

    return Object.values(targetMap)
      .sort((a, b) => b.vulnCount - a.vulnCount)
      .slice(0, limit);
  } catch (error) {
    console.error("Failed to fetch target summaries:", error);
    return [];
  }
}

/**
 * Get mobile app scan summaries
 */
export async function getMobileAppSummaries(limit: number = 5): Promise<MobileAppSummary[]> {
  try {
    const { data, error } = await supabase
      .from("mobile_scans")
      .select("id, filename, package_name, app_name, grade, security_score, platform, created_at")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) throw error;

    return (data || []).map(m => ({
      id: m.id,
      filename: m.filename,
      packageName: m.package_name,
      appName: m.app_name,
      grade: m.grade,
      securityScore: m.security_score,
      platform: m.platform || "android",
      scannedAt: m.created_at,
    }));
  } catch (error) {
    console.error("Failed to fetch mobile app summaries:", error);
    return [];
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} min ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
  
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}
