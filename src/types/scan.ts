/**
 * Scan-related type definitions for AETHER
 */

// Severity levels matching backend
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

// Scan job status
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

// OWASP categories
export type OWASPCategory =
  | "A01:2021-Broken Access Control"
  | "A02:2021-Cryptographic Failures"
  | "A03:2021-Injection"
  | "A04:2021-Insecure Design"
  | "A05:2021-Security Misconfiguration"
  | "A06:2021-Vulnerable and Outdated Components"
  | "A07:2021-Identification and Authentication Failures"
  | "A08:2021-Software and Data Integrity Failures"
  | "A09:2021-Security Logging and Monitoring Failures"
  | "A10:2021-Server-Side Request Forgery";

// Scan configuration options
export interface ScanConfig {
  deep_crawl: boolean;
  max_depth: number;
  subdomain_enum: boolean;
  api_discovery: boolean;
  rate_limit_ms: number;
  enable_sqli: boolean;
  enable_xss: boolean;
  enable_ssrf: boolean;
  enable_path_traversal: boolean;
  enable_security_misconfig: boolean;
  enable_sensitive_data: boolean;
}

// Request to create a new scan
export interface CreateScanRequest {
  target_url: string;
  config?: Partial<ScanConfig>;
}

// Response after creating a scan
export interface CreateScanResponse {
  scan_id: string;
  status: ScanStatus;
  message: string;
}

// Discovered endpoint
export interface DiscoveredEndpoint {
  url: string;
  method: string;
  parameters: string[];
  forms: FormInfo[];
  discovered_at: string;
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: FormInput[];
}

export interface FormInput {
  name: string;
  type: string;
  value: string;
}

// Vulnerability finding
export interface Vulnerability {
  id: string;
  name: string;
  severity: SeverityLevel;
  owasp_category: OWASPCategory;
  cwe_id?: string;
  endpoint: string;
  method: string;
  parameter: string | null;
  evidence: string;
  description: string;
  remediation: string;
  confidence: number;
  ai_analysis?: string;
  detected_at: string;
  detector_name: string;
}

// Scan job record
export interface ScanJob {
  id: string;
  target_url: string;
  status: ScanStatus;
  config: ScanConfig;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  endpoints_discovered: number;
  endpoints_scanned: number;
  vulnerabilities_found: number;
  error_message?: string;
  current_phase: string;
  progress_percentage: number;
}

// Complete scan results
export interface ScanResult {
  scan_id: string;
  target_url: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  urls_scanned: number;
  requests_made: number;
  total_endpoints: number;
  total_vulnerabilities: number;
  severity_counts: Record<SeverityLevel, number>;
  owasp_counts: Record<string, number>;
  endpoints: DiscoveredEndpoint[];
  vulnerabilities: Vulnerability[];
  config_used: ScanConfig;
  scanner_version: string;
}

// WebSocket message types
export type WSMessageType = "connected" | "log" | "progress" | "finding" | "status" | "ping" | "pong";

export interface WSMessage {
  type: WSMessageType;
  data: WSLogData | WSProgressData | Vulnerability | WSStatusData | WSConnectedData;
}

export interface WSConnectedData {
  scan_id: string;
  message: string;
}

export interface WSLogData {
  log_type: "info" | "ok" | "warn" | "critical";
  message: string;
}

export interface WSProgressData {
  current: number;
  total: number;
  percentage: number;
  phase: string;
}

export interface WSStatusData {
  status: ScanStatus;
}

// Default scan config
export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  deep_crawl: true,
  max_depth: 3,
  subdomain_enum: false,
  api_discovery: false,
  rate_limit_ms: 500,
  enable_sqli: true,
  enable_xss: true,
  enable_ssrf: true,
  enable_path_traversal: true,
  enable_security_misconfig: true,
  enable_sensitive_data: true,
};
