/**
 * Supabase Service - Handles all database operations for scans
 */

import { supabase } from "@/lib/supabase";
import type {
  Scan,
  ScanInsert,
  Vulnerability,
  VulnerabilityInsert,
  ScanStats,
  ReconLog,
  ReconLogInsert,
  ReconFinding,
  ReconFindingInsert,
  ReconResult,
  ReconResultInsert,
  ScanType,
} from "@/types/database";

/**
 * Save a new scan to Supabase
 */
export async function saveScan(scan: ScanInsert): Promise<Scan> {
  const { data, error } = await supabase
    .from("scans")
    .insert(scan)
    .select()
    .single();

  if (error) throw new Error(`Failed to save scan: ${error.message}`);
  return data;
}

/**
 * Update an existing scan
 */
export async function updateScan(
  scanId: string,
  updates: Partial<Scan>
): Promise<Scan> {
  const { data, error } = await supabase
    .from("scans")
    .update(updates)
    .eq("id", scanId)
    .select()
    .single();

  if (error) throw new Error(`Failed to update scan: ${error.message}`);
  return data;
}

/**
 * Get a scan by ID
 */
export async function getScanById(scanId: string): Promise<Scan | null> {
  const { data, error } = await supabase
    .from("scans")
    .select()
    .eq("id", scanId)
    .single();

  if (error) {
    if (error.code === "PGRST116") return null;
    throw new Error(`Failed to fetch scan: ${error.message}`);
  }
  return data;
}

/**
 * Get all scans with pagination
 */
export async function getAllScans(
  page: number = 1,
  limit: number = 20
): Promise<{ scans: Scan[]; total: number }> {
  const from = (page - 1) * limit;
  const to = from + limit - 1;

  const { data, error, count } = await supabase
    .from("scans")
    .select("*", { count: "exact" })
    .order("created_at", { ascending: false })
    .range(from, to);

  if (error) throw new Error(`Failed to fetch scans: ${error.message}`);
  return { scans: data || [], total: count || 0 };
}

/**
 * Save vulnerabilities for a scan
 */
export async function saveVulnerabilities(
  vulnerabilities: VulnerabilityInsert[]
): Promise<Vulnerability[]> {
  if (vulnerabilities.length === 0) return [];

  const { data, error } = await supabase
    .from("vulnerabilities")
    .insert(vulnerabilities)
    .select();

  if (error) throw new Error(`Failed to save vulnerabilities: ${error.message}`);
  return data || [];
}

/**
 * Get vulnerabilities for a scan
 */
export async function getVulnerabilitiesByScan(
  scanId: string
): Promise<Vulnerability[]> {
  const { data, error } = await supabase
    .from("vulnerabilities")
    .select()
    .eq("scan_id", scanId)
    .order("severity", { ascending: true });

  if (error) throw new Error(`Failed to fetch vulnerabilities: ${error.message}`);
  return data || [];
}

/**
 * Delete a scan and its vulnerabilities (cascade)
 */
export async function deleteScan(scanId: string): Promise<void> {
  const { error } = await supabase.from("scans").delete().eq("id", scanId);

  if (error) throw new Error(`Failed to delete scan: ${error.message}`);
}

/**
 * Get scan with vulnerabilities
 */
export async function getScanWithVulnerabilities(scanId: string): Promise<{
  scan: Scan;
  vulnerabilities: Vulnerability[];
} | null> {
  const [scanResult, vulnResult] = await Promise.all([
    supabase.from("scans").select().eq("id", scanId).single(),
    supabase
      .from("vulnerabilities")
      .select()
      .eq("scan_id", scanId)
      .order("severity", { ascending: true }),
  ]);

  if (scanResult.error) {
    if (scanResult.error.code === "PGRST116") return null;
    throw new Error(`Failed to fetch scan: ${scanResult.error.message}`);
  }

  return {
    scan: scanResult.data,
    vulnerabilities: vulnResult.data || [],
  };
}

/**
 * Complete a scan and save final stats
 */
export async function completeScan(
  scanId: string,
  stats: ScanStats,
  vulnerabilities: VulnerabilityInsert[]
): Promise<void> {
  // Save vulnerabilities first
  if (vulnerabilities.length > 0) {
    await saveVulnerabilities(vulnerabilities);
  }

  // Update scan status
  await updateScan(scanId, {
    status: "completed",
    completed_at: new Date().toISOString(),
    stats,
  });
}

/**
 * Get recent scans summary
 */
export async function getRecentScans(limit: number = 10): Promise<Scan[]> {
  const { data, error } = await supabase
    .from("scans")
    .select()
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) throw new Error(`Failed to fetch recent scans: ${error.message}`);
  return data || [];
}

/**
 * Get vulnerability statistics
 */
export async function getVulnerabilityStats(): Promise<{
  total: number;
  bySeverity: Record<string, number>;
}> {
  const { data, error } = await supabase.from("vulnerabilities").select("severity");

  if (error) throw new Error(`Failed to fetch vulnerability stats: ${error.message}`);

  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  (data || []).forEach((v) => {
    bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
  });

  return {
    total: data?.length || 0,
    bySeverity,
  };
}

// ============================================================================
// RECON SCAN FUNCTIONS
// ============================================================================

/**
 * Save a recon scan to the database
 */
export async function saveReconScan(
  target: string,
  selectedTools: string[]
): Promise<Scan> {
  const { data, error } = await supabase
    .from("scans")
    .insert({
      target_url: target,
      status: "running",
      scan_type: "recon" as ScanType,
      started_at: new Date().toISOString(),
      parameters: { selected_tools: selectedTools },
    })
    .select()
    .single();

  if (error) throw new Error(`Failed to save recon scan: ${error.message}`);
  return data;
}

/**
 * Save recon logs to the database
 */
export async function saveReconLogs(logs: ReconLogInsert[]): Promise<ReconLog[]> {
  if (logs.length === 0) return [];
  
  const { data, error } = await supabase
    .from("recon_logs")
    .insert(logs)
    .select();

  if (error) throw new Error(`Failed to save recon logs: ${error.message}`);
  return data || [];
}

/**
 * Save recon findings to the database
 */
export async function saveReconFindings(findings: ReconFindingInsert[]): Promise<ReconFinding[]> {
  if (findings.length === 0) return [];
  
  const { data, error } = await supabase
    .from("recon_findings")
    .insert(findings)
    .select();

  if (error) throw new Error(`Failed to save recon findings: ${error.message}`);
  return data || [];
}

/**
 * Save recon results to the database
 */
export async function saveReconResults(results: ReconResultInsert[]): Promise<ReconResult[]> {
  if (results.length === 0) return [];
  
  const { data, error } = await supabase
    .from("recon_results")
    .insert(results)
    .select();

  if (error) throw new Error(`Failed to save recon results: ${error.message}`);
  return data || [];
}

/**
 * Get the last scan by type (enumeration or recon)
 */
export async function getLastScanByType(scanType: ScanType): Promise<Scan | null> {
  const { data, error } = await supabase
    .from("scans")
    .select("*")
    .eq("scan_type", scanType)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw new Error(`Failed to fetch last ${scanType} scan: ${error.message}`);
  return data;
}

/**
 * Get recon logs by scan ID
 */
export async function getReconLogsByScan(scanId: string): Promise<ReconLog[]> {
  const { data, error } = await supabase
    .from("recon_logs")
    .select("*")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: true });

  if (error) throw new Error(`Failed to fetch recon logs: ${error.message}`);
  return data || [];
}

/**
 * Get recon findings by scan ID
 */
export async function getReconFindingsByScan(scanId: string): Promise<ReconFinding[]> {
  const { data, error } = await supabase
    .from("recon_findings")
    .select("*")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: true });

  if (error) throw new Error(`Failed to fetch recon findings: ${error.message}`);
  return data || [];
}

/**
 * Get recon results by scan ID
 */
export async function getReconResultsByScan(scanId: string): Promise<ReconResult[]> {
  const { data, error } = await supabase
    .from("recon_results")
    .select("*")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: true });

  if (error) throw new Error(`Failed to fetch recon results: ${error.message}`);
  return data || [];
}

/**
 * Complete a recon scan and save all data
 */
export async function completeReconScan(
  scanId: string,
  logs: ReconLogInsert[],
  findings: ReconFindingInsert[],
  results: ReconResultInsert[],
  status: "completed" | "failed" | "cancelled" = "completed"
): Promise<void> {
  // Update scan status
  await updateScan(scanId, {
    status,
    completed_at: new Date().toISOString(),
  });

  // Save all data in parallel
  await Promise.all([
    saveReconLogs(logs),
    saveReconFindings(findings),
    saveReconResults(results),
  ]);
}

/**
 * Load full recon scan data including logs, findings, and results
 */
export async function loadFullReconScan(scanId: string): Promise<{
  scan: Scan;
  logs: ReconLog[];
  findings: ReconFinding[];
  results: ReconResult[];
} | null> {
  const scan = await getScanById(scanId);
  if (!scan) return null;

  const [logs, findings, results] = await Promise.all([
    getReconLogsByScan(scanId),
    getReconFindingsByScan(scanId),
    getReconResultsByScan(scanId),
  ]);

  return { scan, logs, findings, results };
}

/**
 * Load the last recon scan with all its data
 */
export async function loadLastReconScan(): Promise<{
  scan: Scan;
  logs: ReconLog[];
  findings: ReconFinding[];
  results: ReconResult[];
} | null> {
  const lastScan = await getLastScanByType("recon");
  if (!lastScan) return null;

  return loadFullReconScan(lastScan.id);
}

/**
 * Load the last enumeration scan with all its data
 */
export async function loadLastEnumerationScan(): Promise<{
  scan: Scan;
  vulnerabilities: Vulnerability[];
} | null> {
  const lastScan = await getLastScanByType("enumeration");
  if (!lastScan) return null;

  const vulnerabilities = await getVulnerabilitiesByScan(lastScan.id);

  return { scan: lastScan, vulnerabilities };
}
