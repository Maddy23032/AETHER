/**
 * Mobile Security API Service
 * Handles communication with the AETHER Mobile Security Backend
 */

export const MOBILE_API_URL = import.meta.env.VITE_MOBILE_API_URL || 'http://localhost:8001';
export const INTELLIGENCE_API_URL = import.meta.env.VITE_INTELLIGENCE_API_URL || 'http://localhost:8002';

// ==================== Types ====================

export interface UploadResponse {
  success: boolean;
  file_hash: string;
  filename: string;
  message: string;
}

export interface ScanResponse {
  success: boolean;
  file_hash: string;
  scan_type: string;
  status: string;
}

export interface ScrapedData {
  malware_lookup: Record<string, string>;
  apkid_analysis: Array<Record<string, string>>;
  behaviour_analysis: Array<Record<string, string>>;
  domain_malware_check: Array<Record<string, string>>;
  urls: Array<Record<string, string>>;
  emails: Array<Record<string, string>>;
}

export interface FullAnalysisResponse {
  success: boolean;
  file_hash: string;
  filename: string;
  scan_completed_at: string;
  json_report: Record<string, unknown> | null;
  scorecard: Record<string, unknown> | null;
  scan_logs: Record<string, unknown> | null;
  scraped_data: ScrapedData | null;
  pdf_available: boolean;
  pdf_path: string | null;
}

export interface HealthResponse {
  status: string;
  mobsf_connected: boolean;
  api_key_available: boolean;
  version?: string;
}

export interface ScanHistoryItem {
  // MobSF returns various property names depending on version
  HASH?: string;
  MD5?: string;
  hash?: string;
  FILE_NAME?: string;
  APP_NAME?: string;
  file_name?: string;
  TIMESTAMP?: string;
  timestamp?: string;
  SCAN_TYPE?: string;
  scan_type?: string;
  [key: string]: unknown;
}

// ==================== API Functions ====================

/**
 * Check API health status
 */
export async function checkHealth(): Promise<HealthResponse> {
  const response = await fetch(`${MOBILE_API_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }
  return response.json();
}

/**
 * Refresh MobSF API key (use after Docker restart)
 */
export async function refreshApiKey(): Promise<{ success: boolean; message: string }> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/refresh-key`, {
    method: 'POST',
  });
  return response.json();
}

/**
 * Upload APK/IPA file
 */
export async function uploadFile(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(error.detail || 'Upload failed');
  }

  return response.json();
}

/**
 * Run static analysis scan
 */
export async function runScan(fileHash: string): Promise<ScanResponse> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/analyze/${fileHash}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(error.detail || 'Scan failed');
  }

  return response.json();
}

/**
 * Get JSON report
 */
export async function getReport(fileHash: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/report/${fileHash}`);
  
  if (!response.ok) {
    throw new Error(`Failed to get report: ${response.status}`);
  }

  const data = await response.json();
  return data.report;
}

/**
 * Get scorecard
 */
export async function getScorecard(fileHash: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/scorecard/${fileHash}`);
  
  if (!response.ok) {
    throw new Error(`Failed to get scorecard: ${response.status}`);
  }

  const data = await response.json();
  return data.scorecard;
}

/**
 * Get scraped data (malware lookups, APKiD, behaviour, URLs, emails)
 */
export async function getScrapedData(fileHash: string): Promise<ScrapedData> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/scraped/${fileHash}`);
  
  if (!response.ok) {
    throw new Error(`Failed to get scraped data: ${response.status}`);
  }

  return response.json();
}

/**
 * Run full analysis pipeline (upload + scan + all reports)
 */
export async function runFullAnalysis(file: File): Promise<FullAnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/full-analysis`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Analysis failed' }));
    throw new Error(error.detail || 'Analysis failed');
  }

  return response.json();
}

/**
 * Get scan history
 */
export async function getScanHistory(page = 1, pageSize = 10): Promise<{ content: ScanHistoryItem[] }> {
  const response = await fetch(
    `${MOBILE_API_URL}/api/v1/scan/history?page=${page}&page_size=${pageSize}`
  );
  
  if (!response.ok) {
    return { content: [] };
  }

  return response.json();
}

/**
 * Ingest mobile scan results into Intelligence RAG for AI analysis
 */
export async function ingestMobileScanToRAG(
  fileHash: string,
  filename: string,
  report: FullAnalysisResponse
): Promise<void> {
  try {
    // Extract relevant data for RAG
    const jsonReport = report.json_report || {};
    const scorecard = report.scorecard || {};
    const scrapedData = report.scraped_data || {};
    
    // Build structured results for RAG
    const results: Record<string, unknown> = {
      app_info: {
        package_name: (jsonReport as Record<string, unknown>).package_name || filename,
        app_name: (jsonReport as Record<string, unknown>).app_name || filename,
        version: (jsonReport as Record<string, unknown>).version_name || 'Unknown',
        platform: (jsonReport as Record<string, unknown>).file_name?.toString().endsWith('.ipa') ? 'iOS' : 'Android',
        min_sdk: (jsonReport as Record<string, unknown>).min_sdk,
        target_sdk: (jsonReport as Record<string, unknown>).target_sdk,
      },
      security_score: (scorecard as Record<string, unknown>).security_score || (jsonReport as Record<string, unknown>).security_score,
      grade: (scorecard as Record<string, unknown>).grade,
      permissions: {
        dangerous: (jsonReport as Record<string, unknown>).permissions?.dangerous || [],
        normal: (jsonReport as Record<string, unknown>).permissions?.normal || [],
      },
      security_issues: [
        ...((jsonReport as Record<string, unknown[]>).code_analysis || []).map((issue: Record<string, unknown>) => ({
          title: issue.title,
          description: issue.description,
          severity: issue.severity,
        })),
        ...((jsonReport as Record<string, unknown[]>).manifest_analysis || []).map((issue: Record<string, unknown>) => ({
          title: issue.title,
          description: issue.description,
          severity: issue.severity,
        })),
      ],
      malware_analysis: {
        detected: Object.keys(scrapedData.malware_lookup || {}).length > 0,
        threats: Object.entries(scrapedData.malware_lookup || {}).map(([k, v]) => `${k}: ${v}`),
      },
      urls: scrapedData.urls?.map((u: Record<string, string>) => u.url || Object.values(u)[0]) || [],
      secrets: (jsonReport as Record<string, unknown[]>).secrets || [],
    };

    // Call Intelligence ingest endpoint
    const response = await fetch(`${INTELLIGENCE_API_URL}/api/intelligence/ingest/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        scan_id: fileHash,
        scan_type: 'mobile',
        target: filename,
        results,
        metadata: {
          file_hash: fileHash,
          scan_completed_at: report.scan_completed_at,
          pdf_available: report.pdf_available,
        },
      }),
    });

    if (!response.ok) {
      console.warn('[Mobile] Failed to ingest scan to RAG:', await response.text());
    } else {
      console.log('[Mobile] Successfully ingested scan to Intelligence RAG');
    }
  } catch (error) {
    // Don't fail the scan if RAG ingestion fails
    console.warn('[Mobile] Failed to ingest to Intelligence RAG:', error);
  }
}

/**
 * Delete a scan
 */
export async function deleteScan(fileHash: string): Promise<void> {
  const response = await fetch(`${MOBILE_API_URL}/api/v1/scan/${fileHash}`, {
    method: 'DELETE',
  });
  
  if (!response.ok) {
    throw new Error(`Failed to delete scan: ${response.status}`);
  }
}

/**
 * Get PDF download URL
 */
export function getPdfUrl(fileHash: string): string {
  return `${MOBILE_API_URL}/api/v1/scan/pdf/${fileHash}`;
}

// ==================== Utility Functions ====================

/**
 * Get security grade from score
 */
export function getSecurityGrade(score: number | null | undefined): string {
  if (score === null || score === undefined) return '?';
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Get grade color class
 */
export function getGradeColor(score: number | null | undefined): string {
  if (score === null || score === undefined) return 'text-gray-500';
  if (score >= 80) return 'text-green-500';
  if (score >= 60) return 'text-yellow-500';
  if (score >= 40) return 'text-orange-500';
  return 'text-red-500';
}

/**
 * Get severity badge variant
 */
export function getSeverityVariant(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': case 'warning': return 'medium';
    case 'low': case 'secure': return 'low';
    default: return 'info';
  }
}

/**
 * Get risk level color
 */
export function getRiskLevelColor(level: string): string {
  switch (level?.toLowerCase()) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': case 'warning': return 'text-yellow-500';
    case 'low': return 'text-green-500';
    default: return 'text-gray-500';
  }
}
