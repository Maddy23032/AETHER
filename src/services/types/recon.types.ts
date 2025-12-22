/**
 * TypeScript interfaces for AETHER Reconnaissance API
 */

// Scan status types
export type ScanStatus = 'idle' | 'running' | 'completed' | 'error';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type LogType = 'info' | 'success' | 'warning' | 'error';

// Tool categories
export type ToolCategory = 
  | 'port-scan' 
  | 'web-analysis' 
  | 'dns' 
  | 'subdomain' 
  | 'directory' 
  | 'vuln-scan'
  | 'osint';

// Available tools
export type ToolId = 
  | 'nmap' 
  | 'whatweb' 
  | 'nikto' 
  | 'dirsearch' 
  | 'gobuster' 
  | 'amass' 
  | 'theharvester' 
  | 'dnsenum' 
  | 'subfinder' 
  | 'httpx';

// Tool definition
export interface ReconTool {
  id: ToolId;
  name: string;
  description: string;
  category: ToolCategory;
  endpoint: string;
  icon: string;
  enabled: boolean;
  estimatedTime: string;
}

// Tool-specific options
export interface NmapOptions {
  scanType?: 'service' | 'ping' | 'syn' | 'full';
  ports?: string;
  timeout?: number;
}

export interface NiktoOptions {
  ssl?: boolean;
  timeout?: number;
}

export interface WhatwebOptions {
  aggression?: 1 | 2 | 3;
  timeout?: number;
}

export interface DirsearchOptions {
  wordlist?: 'small' | 'medium' | 'large';
  extensions?: string[];
  timeout?: number;
}

export interface GobusterOptions {
  mode?: 'dir' | 'dns' | 'vhost';
  wordlist?: string;
  timeout?: number;
}

export interface SubdomainOptions {
  timeout?: number;
}

export interface DnsOptions {
  timeout?: number;
}

export interface HttpxOptions {
  timeout?: number;
}

export interface HarvesterOptions {
  timeout?: number;
}

// Combined tool options type
export type ToolOptions = 
  | NmapOptions 
  | NiktoOptions 
  | WhatwebOptions 
  | DirsearchOptions 
  | GobusterOptions
  | SubdomainOptions
  | DnsOptions
  | HttpxOptions
  | HarvesterOptions;

// Scan configuration
export interface ScanConfig {
  target: string;
  tools: ToolId[];
  options: Partial<Record<ToolId, ToolOptions>>;
}

// API Response types
export interface ReconResponse {
  tool: string;
  target: string;
  status: 'success' | 'error';
  execution_time: string;
  parameters: Record<string, unknown>;
  results: {
    raw: string;
    parsed: ParsedResult;
  };
  errors?: string;
}

// Parsed result types
export interface ParsedResult {
  // Port scan results
  open_ports?: PortInfo[];
  services?: ServiceInfo[];
  
  // Web analysis
  technologies?: string[];
  headers?: Record<string, string>;
  status_code?: number;
  title?: string;
  server?: string;
  
  // DNS results
  records?: Record<string, string[]>;
  nameservers?: string[];
  mx_records?: string[];
  ip_addresses?: string[];
  
  // Subdomain results
  subdomains?: string[];
  count?: number;
  
  // Directory results
  found_paths?: PathInfo[];
  paths_checked?: number;
  
  // Vulnerability results
  vulnerabilities?: VulnerabilityInfo[];
  missing_headers?: MissingHeader[];
  sensitive_files?: SensitiveFile[];
  server_info?: ServerInfo;
  ssl_info?: SSLInfo;
  
  // OSINT results
  emails?: string[];
  hosts?: string[];
  ips?: string[];
  
  // HTTP probe results
  probes?: ProbeResult[];
  live_hosts?: string[];
}

export interface PortInfo {
  port: number;
  state: string;
  service: string;
  version?: string;
}

export interface ServiceInfo {
  port: number;
  state: string;
  service: string;
  version?: string;
}

export interface PathInfo {
  path: string;
  status: number;
  size: number;
  redirect?: string;
}

export interface VulnerabilityInfo {
  type: string;
  severity: Severity;
  description: string;
  endpoint?: string;
  recommendation?: string;
}

export interface MissingHeader {
  header: string;
  description: string;
  severity: Severity;
}

export interface SensitiveFile {
  path: string;
  status: number;
  size: number;
}

export interface ServerInfo {
  server?: string;
  powered_by?: string;
  status_code?: number;
  final_url?: string;
}

export interface SSLInfo {
  subject?: {
    commonName?: string;
  };
  issuer?: string;
  expires?: string;
  error?: string;
}

export interface ProbeResult {
  url: string;
  status_code?: number;
  title?: string;
  server?: string;
  content_length?: number;
  final_url?: string;
  error?: string;
}

// Log entry for live console
export interface LogEntry {
  id: string;
  timestamp: Date;
  tool: string;
  type: LogType;
  message: string;
}

// Scan result for display
export interface ScanResultItem {
  id: string;
  tool: ToolId;
  severity: Severity;
  name: string;
  description?: string;
  endpoint?: string;
  status: 'open' | 'resolved' | 'informational' | 'fixed' | 'false-positive';
  raw?: string;
}

// API health check response
export interface HealthCheckResponse {
  service: string;
  status: string;
  version: string;
}

// Tools list response
export interface ToolsListResponse {
  tools: Array<{
    name: string;
    endpoint: string;
  }>;
}

// Export all types
export type {
  ScanStatus as ReconScanStatus,
  Severity as ReconSeverity,
  LogType as ReconLogType,
};
