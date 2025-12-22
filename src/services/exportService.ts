/**
 * Export Service - Generates PDF and JSON reports for scan results
 */

import type { Vulnerability } from "@/types/database";

export interface ExportScanData {
  id: string;
  targetUrl: string;
  createdAt: string;
  completedAt?: string;
  vulnerabilities: Vulnerability[];
}

/**
 * Generate JSON report and trigger download
 */
export function exportToJSON(scan: ExportScanData): void {
  const report = {
    metadata: {
      tool: "AETHER Security Scanner",
      version: "0.1.0",
      generated_at: new Date().toISOString(),
      scan_id: scan.id,
    },
    target: {
      url: scan.targetUrl,
      scanned_at: scan.createdAt,
      completed_at: scan.completedAt,
    },
    summary: {
      total_vulnerabilities: scan.vulnerabilities.length,
      by_severity: {
        critical: scan.vulnerabilities.filter((v) => v.severity === "critical").length,
        high: scan.vulnerabilities.filter((v) => v.severity === "high").length,
        medium: scan.vulnerabilities.filter((v) => v.severity === "medium").length,
        low: scan.vulnerabilities.filter((v) => v.severity === "low").length,
        info: scan.vulnerabilities.filter((v) => v.severity === "info").length,
      },
    },
    vulnerabilities: scan.vulnerabilities.map((v) => ({
      id: v.id,
      name: v.name,
      severity: v.severity,
      confidence: v.confidence,
      owasp_category: v.owasp_category,
      cwe_id: v.cwe_id,
      endpoint: v.endpoint,
      method: v.method,
      parameter: v.parameter,
      evidence: v.evidence,
      description: v.description,
      remediation: v.remediation,
    })),
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, `aether-scan-${scan.id.slice(0, 8)}.json`);
}

/**
 * Generate CSV report and trigger download
 */
export function exportToCSV(scan: ExportScanData): void {
  const headers = [
    "Severity",
    "Name",
    "OWASP Category",
    "CWE ID",
    "Endpoint",
    "Method",
    "Parameter",
    "Confidence",
    "Description",
    "Remediation",
  ];

  const rows = scan.vulnerabilities.map((v) => [
    v.severity,
    escapeCSV(v.name),
    escapeCSV(v.owasp_category),
    v.cwe_id || "",
    escapeCSV(v.endpoint),
    v.method,
    v.parameter || "",
    (v.confidence * 100).toFixed(0) + "%",
    escapeCSV(v.description),
    escapeCSV(v.remediation),
  ]);

  const csvContent = [
    `# AETHER Security Scan Report`,
    `# Target: ${scan.targetUrl}`,
    `# Scan ID: ${scan.id}`,
    `# Generated: ${new Date().toISOString()}`,
    ``,
    headers.join(","),
    ...rows.map((row) => row.join(",")),
  ].join("\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  downloadBlob(blob, `aether-scan-${scan.id.slice(0, 8)}.csv`);
}

/**
 * Generate HTML report and trigger download
 */
export function exportToHTML(scan: ExportScanData): void {
  const severityColors: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#16a34a",
    info: "#0284c7",
  };

  const vulnRows = scan.vulnerabilities
    .map(
      (v) => `
    <tr>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <span style="background: ${severityColors[v.severity]}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; text-transform: uppercase;">
          ${v.severity}
        </span>
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
        <strong>${escapeHTML(v.name)}</strong>
        <br><small style="color: #6b7280;">${escapeHTML(v.owasp_category)}</small>
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb; font-family: monospace; font-size: 13px;">
        <span style="color: #7c3aed;">${v.method}</span> ${escapeHTML(v.endpoint)}
        ${v.parameter ? `<span style="color: #d97706;">?${escapeHTML(v.parameter)}</span>` : ""}
      </td>
      <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">${(v.confidence * 100).toFixed(0)}%</td>
    </tr>
  `
    )
    .join("");

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AETHER Scan Report - ${scan.targetUrl}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; background: #f9fafb; }
    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); overflow: hidden; }
    .header { background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); color: white; padding: 40px; }
    .header h1 { margin: 0 0 8px 0; font-size: 28px; }
    .header p { margin: 0; opacity: 0.8; }
    .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; padding: 30px 40px; border-bottom: 1px solid #e5e7eb; }
    .stat { text-align: center; }
    .stat-value { font-size: 32px; font-weight: bold; }
    .stat-label { font-size: 12px; text-transform: uppercase; color: #6b7280; margin-top: 4px; }
    .stat.critical .stat-value { color: #dc2626; }
    .stat.high .stat-value { color: #ea580c; }
    .stat.medium .stat-value { color: #ca8a04; }
    .stat.low .stat-value { color: #16a34a; }
    .stat.info .stat-value { color: #0284c7; }
    .content { padding: 40px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 12px; background: #f3f4f6; font-weight: 600; border-bottom: 2px solid #e5e7eb; }
    .footer { padding: 20px 40px; background: #f9fafb; text-align: center; color: #6b7280; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 AETHER Security Scan Report</h1>
      <p>Target: ${escapeHTML(scan.targetUrl)} | Scan ID: ${scan.id.slice(0, 8)} | ${new Date().toLocaleDateString()}</p>
    </div>
    
    <div class="summary">
      <div class="stat critical">
        <div class="stat-value">${scan.vulnerabilities.filter((v) => v.severity === "critical").length}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat high">
        <div class="stat-value">${scan.vulnerabilities.filter((v) => v.severity === "high").length}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat medium">
        <div class="stat-value">${scan.vulnerabilities.filter((v) => v.severity === "medium").length}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat low">
        <div class="stat-value">${scan.vulnerabilities.filter((v) => v.severity === "low").length}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat info">
        <div class="stat-value">${scan.vulnerabilities.filter((v) => v.severity === "info").length}</div>
        <div class="stat-label">Info</div>
      </div>
    </div>
    
    <div class="content">
      <h2>Vulnerabilities Found</h2>
      <table>
        <thead>
          <tr>
            <th style="width: 100px;">Severity</th>
            <th>Vulnerability</th>
            <th>Endpoint</th>
            <th style="width: 80px;">Confidence</th>
          </tr>
        </thead>
        <tbody>
          ${vulnRows || '<tr><td colspan="4" style="text-align: center; padding: 40px; color: #6b7280;">No vulnerabilities found</td></tr>'}
        </tbody>
      </table>
    </div>
    
    <div class="footer">
      Generated by AETHER - AI-Enhanced Threat Enumeration and Reconnaissance Platform
    </div>
  </div>
</body>
</html>
  `.trim();

  const blob = new Blob([html], { type: "text/html;charset=utf-8;" });
  downloadBlob(blob, `aether-scan-${scan.id.slice(0, 8)}.html`);
}

// Helper functions
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function escapeCSV(str: string): string {
  if (!str) return "";
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function escapeHTML(str: string): string {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
