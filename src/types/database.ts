/**
 * Supabase Database Types
 * These types match the database schema for scans and vulnerabilities
 */

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";
export type ScanType = "enumeration" | "recon";
export type ReconLogType = "info" | "success" | "warning" | "error";
export type FindingStatus = "open" | "resolved" | "informational" | "fixed" | "false-positive";

export interface Database {
  public: {
    Tables: {
      scans: {
        Row: {
          id: string;
          target_url: string;
          status: ScanStatus;
          scan_type: ScanType;
          started_at: string | null;
          completed_at: string | null;
          created_at: string;
          updated_at: string;
          config: ScanConfig;
          stats: ScanStats | null;
          parameters: Record<string, unknown> | null;
          user_id: string | null;
        };
        Insert: {
          id?: string;
          target_url: string;
          status?: ScanStatus;
          scan_type?: ScanType;
          started_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
          config?: ScanConfig;
          stats?: ScanStats | null;
          parameters?: Record<string, unknown> | null;
          user_id?: string | null;
        };
        Update: {
          id?: string;
          target_url?: string;
          status?: ScanStatus;
          scan_type?: ScanType;
          started_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          updated_at?: string;
          config?: ScanConfig;
          stats?: ScanStats | null;
          parameters?: Record<string, unknown> | null;
          user_id?: string | null;
        };
        Relationships: [];
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
        Relationships: [
          {
            foreignKeyName: "vulnerabilities_scan_id_fkey";
            columns: ["scan_id"];
            referencedRelation: "scans";
            referencedColumns: ["id"];
          }
        ];
      };
      recon_logs: {
        Row: {
          id: string;
          scan_id: string;
          tool: string;
          log_type: ReconLogType;
          message: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          tool: string;
          log_type: ReconLogType;
          message: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          scan_id?: string;
          tool?: string;
          log_type?: ReconLogType;
          message?: string;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "recon_logs_scan_id_fkey";
            columns: ["scan_id"];
            referencedRelation: "scans";
            referencedColumns: ["id"];
          }
        ];
      };
      recon_findings: {
        Row: {
          id: string;
          scan_id: string;
          tool: string;
          severity: SeverityLevel;
          name: string;
          description: string | null;
          endpoint: string | null;
          status: FindingStatus;
          raw_data: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          tool: string;
          severity: SeverityLevel;
          name: string;
          description?: string | null;
          endpoint?: string | null;
          status?: FindingStatus;
          raw_data?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          scan_id?: string;
          tool?: string;
          severity?: SeverityLevel;
          name?: string;
          description?: string | null;
          endpoint?: string | null;
          status?: FindingStatus;
          raw_data?: string | null;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "recon_findings_scan_id_fkey";
            columns: ["scan_id"];
            referencedRelation: "scans";
            referencedColumns: ["id"];
          }
        ];
      };
      recon_results: {
        Row: {
          id: string;
          scan_id: string;
          tool: string;
          status: "success" | "error";
          execution_time: string | null;
          parameters: Record<string, unknown>;
          raw_output: string | null;
          parsed_results: Record<string, unknown>;
          errors: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          scan_id: string;
          tool: string;
          status: "success" | "error";
          execution_time?: string | null;
          parameters?: Record<string, unknown>;
          raw_output?: string | null;
          parsed_results?: Record<string, unknown>;
          errors?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          scan_id?: string;
          tool?: string;
          status?: "success" | "error";
          execution_time?: string | null;
          parameters?: Record<string, unknown>;
          raw_output?: string | null;
          parsed_results?: Record<string, unknown>;
          errors?: string | null;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "recon_results_scan_id_fkey";
            columns: ["scan_id"];
            referencedRelation: "scans";
            referencedColumns: ["id"];
          }
        ];
      };
    };
    Views: {};
    Functions: {};
    Enums: {
      scan_status: ScanStatus;
      severity_level: SeverityLevel;
      scan_type: ScanType;
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

// Recon types
export type ReconLog = Database["public"]["Tables"]["recon_logs"]["Row"];
export type ReconLogInsert = Database["public"]["Tables"]["recon_logs"]["Insert"];
export type ReconFinding = Database["public"]["Tables"]["recon_findings"]["Row"];
export type ReconFindingInsert = Database["public"]["Tables"]["recon_findings"]["Insert"];
export type ReconResult = Database["public"]["Tables"]["recon_results"]["Row"];
export type ReconResultInsert = Database["public"]["Tables"]["recon_results"]["Insert"];
