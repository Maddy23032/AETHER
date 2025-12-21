/**
 * Supabase Database Types
 * These types match the database schema for scans and vulnerabilities
 */

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export interface Database {
  public: {
    Tables: {
      scans: {
        Row: {
          id: string;
          target_url: string;
          status: ScanStatus;
          started_at: string | null;
          completed_at: string | null;
          created_at: string;
          updated_at: string;
          config: ScanConfig;
          stats: ScanStats | null;
          user_id: string | null;
        };
        Insert: {
          id?: string;
          target_url: string;
          status?: ScanStatus;
          started_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
          config?: ScanConfig;
          stats?: ScanStats | null;
          user_id?: string | null;
        };
        Update: {
          id?: string;
          target_url?: string;
          status?: ScanStatus;
          started_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
          config?: ScanConfig;
          stats?: ScanStats | null;
          user_id?: string | null;
        };
      };
      vulnerabilities: {
        Row: {
          id: string;
          scan_id: string;
          name: string;
          severity: SeverityLevel;
          confidence: number;
          owasp_category: string;
          cwe_id: string | null;
          endpoint: string;
          method: string;
          parameter: string | null;
          evidence: string | null;
          description: string;
          remediation: string;
          request_sample: string | null;
          response_sample: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          name: string;
          severity: SeverityLevel;
          confidence: number;
          owasp_category: string;
          cwe_id?: string | null;
          endpoint: string;
          method: string;
          parameter?: string | null;
          evidence?: string | null;
          description: string;
          remediation: string;
          request_sample?: string | null;
          response_sample?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          scan_id?: string;
          name?: string;
          severity?: SeverityLevel;
          confidence?: number;
          owasp_category?: string;
          cwe_id?: string | null;
          endpoint?: string;
          method?: string;
          parameter?: string | null;
          evidence?: string | null;
          description?: string;
          remediation?: string;
          request_sample?: string | null;
          response_sample?: string | null;
          created_at?: string;
        };
      };
    };
    Views: {};
    Functions: {};
    Enums: {
      scan_status: ScanStatus;
      severity_level: SeverityLevel;
    };
  };
}

export interface ScanConfig {
  deep_crawl?: boolean;
  subdomain_enum?: boolean;
  api_discovery?: boolean;
  max_depth?: number;
  rate_limit_ms?: number;
  enable_sqli?: boolean;
  enable_xss?: boolean;
  enable_ssrf?: boolean;
  enable_path_traversal?: boolean;
  enable_security_misconfig?: boolean;
  enable_sensitive_data?: boolean;
}

export interface ScanStats {
  urls_scanned: number;
  requests_made: number;
  vulnerabilities_found: number;
  duration_seconds: number;
}

// Helper types for working with the database
export type Scan = Database["public"]["Tables"]["scans"]["Row"];
export type ScanInsert = Database["public"]["Tables"]["scans"]["Insert"];
export type ScanUpdate = Database["public"]["Tables"]["scans"]["Update"];
export type Vulnerability = Database["public"]["Tables"]["vulnerabilities"]["Row"];
export type VulnerabilityInsert = Database["public"]["Tables"]["vulnerabilities"]["Insert"];
