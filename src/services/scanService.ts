/**
 * Scan API service
 */

import { apiFetch } from "./api";
import type {
  CreateScanRequest,
  CreateScanResponse,
  ScanJob,
  ScanResult,
} from "@/types/scan";

/**
 * Create a new scan job
 */
export async function createScan(request: CreateScanRequest): Promise<CreateScanResponse> {
  return apiFetch<CreateScanResponse>("/api/scans/", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

/**
 * Get scan job details
 */
export async function getScan(scanId: string): Promise<ScanJob> {
  return apiFetch<ScanJob>(`/api/scans/${scanId}`);
}

/**
 * Get scan results
 */
export async function getScanResults(scanId: string): Promise<ScanResult> {
  return apiFetch<ScanResult>(`/api/scans/${scanId}/results`);
}

/**
 * List all scans
 */
export async function listScans(limit = 20, offset = 0): Promise<{ scans: ScanJob[]; total: number }> {
  return apiFetch(`/api/scans/?limit=${limit}&offset=${offset}`);
}

/**
 * Cancel a running scan
 */
export async function cancelScan(scanId: string): Promise<{ message: string }> {
  return apiFetch(`/api/scans/${scanId}`, { method: "DELETE" });
}

/**
 * Export scan results in RAG format
 */
export async function exportScanForRAG(scanId: string): Promise<unknown> {
  return apiFetch(`/api/scans/${scanId}/export?format=rag`);
}
