/**
 * useReconScan Hook
 * Custom hook for managing reconnaissance scan operations
 */

import { useState, useCallback, useRef } from 'react';
import { reconService } from '@/services/reconService';
import type {
  ScanStatus,
  LogEntry,
  ToolId,
  ToolOptions,
  ReconResponse,
  ScanResultItem,
  Severity,
} from '@/services/types/recon.types';

export interface UseReconScanReturn {
  status: ScanStatus;
  logs: LogEntry[];
  results: ReconResponse[];
  findings: ScanResultItem[];
  progress: { current: number; total: number; currentTool: string };
  isApiAvailable: boolean;
  startScan: (target: string, tools: ToolId[], options?: Partial<Record<ToolId, ToolOptions>>) => Promise<ReconResponse[]>;
  cancelScan: () => void;
  resetScan: () => void;
  checkApiStatus: () => Promise<boolean>;
}

/**
 * Generate unique ID
 */
function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Extract findings from scan results
 */
function extractFindings(results: ReconResponse[]): ScanResultItem[] {
  const findings: ScanResultItem[] = [];
  
  for (const result of results) {
    const parsed = result.results?.parsed || {};
    const tool = result.tool as ToolId;
    
    // Extract vulnerabilities
    if (parsed.vulnerabilities) {
      for (const vuln of parsed.vulnerabilities) {
        findings.push({
          id: generateId(),
          tool,
          severity: vuln.severity as Severity,
          name: vuln.type,
          description: vuln.description,
          endpoint: vuln.endpoint,
          status: 'open',
        });
      }
    }
    
    // Extract missing headers as medium severity
    if (parsed.missing_headers) {
      for (const header of parsed.missing_headers) {
        findings.push({
          id: generateId(),
          tool,
          severity: header.severity || 'medium',
          name: `Missing Security Header: ${header.header}`,
          description: header.description,
          status: 'open',
        });
      }
    }
    
    // Extract sensitive files as high severity
    if (parsed.sensitive_files) {
      for (const file of parsed.sensitive_files) {
        findings.push({
          id: generateId(),
          tool,
          severity: 'high',
          name: 'Sensitive File Exposed',
          description: `Sensitive file found: ${file.path}`,
          endpoint: file.path,
          status: 'open',
        });
      }
    }
    
    // Extract open ports as informational
    if (parsed.open_ports || parsed.services) {
      const services = parsed.services || parsed.open_ports || [];
      for (const svc of services) {
        findings.push({
          id: generateId(),
          tool,
          severity: 'info',
          name: `Open Port: ${svc.port}/${svc.service}`,
          description: `Port ${svc.port} is open running ${svc.service}${svc.version ? ` (${svc.version})` : ''}`,
          endpoint: `:${svc.port}`,
          status: 'informational',
        });
      }
    }
    
    // Extract subdomains
    if (parsed.subdomains && parsed.subdomains.length > 0) {
      findings.push({
        id: generateId(),
        tool,
        severity: 'info',
        name: 'Subdomains Discovered',
        description: `Found ${parsed.subdomains.length} subdomains: ${parsed.subdomains.slice(0, 5).join(', ')}${parsed.subdomains.length > 5 ? '...' : ''}`,
        status: 'informational',
      });
    }
    
    // Extract discovered paths
    if (parsed.found_paths) {
      for (const path of parsed.found_paths) {
        const severity: Severity = 
          path.status === 200 ? 'info' :
          path.status === 403 ? 'low' :
          path.status === 301 || path.status === 302 ? 'info' : 'info';
        
        findings.push({
          id: generateId(),
          tool,
          severity,
          name: `Discovered Path: ${path.path}`,
          description: `Path returns HTTP ${path.status} (${path.size} bytes)`,
          endpoint: path.path,
          status: 'informational',
        });
      }
    }
    
    // Extract technologies
    if (parsed.technologies && parsed.technologies.length > 0) {
      findings.push({
        id: generateId(),
        tool,
        severity: 'info',
        name: 'Technologies Detected',
        description: `Identified technologies: ${parsed.technologies.join(', ')}`,
        status: 'informational',
      });
    }
    
    // Extract emails from OSINT
    if (parsed.emails && parsed.emails.length > 0) {
      findings.push({
        id: generateId(),
        tool,
        severity: 'info',
        name: 'Email Addresses Found',
        description: `Found ${parsed.emails.length} email addresses`,
        status: 'informational',
      });
    }
    
    // Handle errors
    if (result.status === 'error' && result.errors) {
      findings.push({
        id: generateId(),
        tool,
        severity: 'low',
        name: `${tool} Scan Error`,
        description: result.errors,
        status: 'informational',
      });
    }
  }
  
  // Sort by severity
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  
  return findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

export function useReconScan(): UseReconScanReturn {
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [results, setResults] = useState<ReconResponse[]>([]);
  const [findings, setFindings] = useState<ScanResultItem[]>([]);
  const [progress, setProgress] = useState({ current: 0, total: 0, currentTool: '' });
  const [isApiAvailable, setIsApiAvailable] = useState(true);
  const abortRef = useRef(false);

  const addLog = useCallback((tool: string, type: LogEntry['type'], message: string) => {
    const entry: LogEntry = {
      id: generateId(),
      timestamp: new Date(),
      tool,
      type,
      message,
    };
    setLogs(prev => [...prev, entry]);
  }, []);

  const checkApiStatus = useCallback(async (): Promise<boolean> => {
    try {
      const available = await reconService.isAvailable();
      setIsApiAvailable(available);
      return available;
    } catch {
      setIsApiAvailable(false);
      return false;
    }
  }, []);

  const startScan = useCallback(async (
    target: string,
    tools: ToolId[],
    options: Partial<Record<ToolId, ToolOptions>> = {}
  ): Promise<ReconResponse[]> => {
    // Reset state
    abortRef.current = false;
    setStatus('running');
    setLogs([]);
    setResults([]);
    setFindings([]);
    setProgress({ current: 0, total: tools.length, currentTool: '' });

    // Check API availability
    const apiAvailable = await checkApiStatus();
    if (!apiAvailable) {
      addLog('system', 'error', 'Reconnaissance API is not available. Please ensure the server is running.');
      setStatus('error');
      return [];
    }

    addLog('system', 'info', `[INIT] Starting reconnaissance on ${target}`);
    addLog('system', 'info', `[INFO] Selected tools: ${tools.join(', ')}`);
    addLog('system', 'info', `[INFO] Total scans to run: ${tools.length}`);

    const scanResults: ReconResponse[] = [];

    for (let i = 0; i < tools.length; i++) {
      if (abortRef.current) {
        addLog('system', 'warning', '[ABORT] Scan cancelled by user');
        break;
      }

      const tool = tools[i];
      const toolOptions = options[tool] || {};
      
      setProgress({ current: i + 1, total: tools.length, currentTool: tool });
      addLog(tool, 'info', `[${(i + 1)}/${tools.length}] Starting ${tool} scan...`);

      const scanMethod = reconService.getScanMethod(tool);
      
      if (scanMethod) {
        try {
          const startTime = Date.now();
          const result = await scanMethod(target, toolOptions);
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
          
          scanResults.push(result);
          setResults(prev => [...prev, result]);

          if (result.status === 'success') {
            addLog(tool, 'success', `[OK] ${tool} completed in ${result.execution_time || elapsed + 's'}`);
            
            // Log some interesting findings
            const parsed = result.results?.parsed || {};
            if (parsed.open_ports?.length) {
              addLog(tool, 'info', `[INFO] Found ${parsed.open_ports.length} open ports`);
            }
            if (parsed.technologies?.length) {
              addLog(tool, 'info', `[INFO] Detected technologies: ${parsed.technologies.slice(0, 3).join(', ')}`);
            }
            if (parsed.vulnerabilities?.length) {
              addLog(tool, 'warning', `[VULN] Found ${parsed.vulnerabilities.length} potential vulnerabilities`);
            }
            if (parsed.subdomains?.length) {
              addLog(tool, 'info', `[INFO] Discovered ${parsed.subdomains.length} subdomains`);
            }
          } else {
            addLog(tool, 'error', `[ERROR] ${tool} failed: ${result.errors || 'Unknown error'}`);
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          addLog(tool, 'error', `[ERROR] ${tool} failed: ${errorMessage}`);
          
          const errorResult: ReconResponse = {
            tool,
            target,
            status: 'error',
            execution_time: '0s',
            parameters: toolOptions as Record<string, unknown>,
            results: { raw: '', parsed: {} },
            errors: errorMessage,
          };
          scanResults.push(errorResult);
          setResults(prev => [...prev, errorResult]);
        }
      }
    }

    // Extract and set findings
    const extractedFindings = extractFindings(scanResults);
    setFindings(extractedFindings);

    // Final summary
    const successCount = scanResults.filter(r => r.status === 'success').length;
    const errorCount = scanResults.filter(r => r.status === 'error').length;
    const criticalCount = extractedFindings.filter(f => f.severity === 'critical').length;
    const highCount = extractedFindings.filter(f => f.severity === 'high').length;

    addLog('system', 'info', '');
    addLog('system', 'info', '═══════════════════════════════════════════════');
    addLog('system', 'success', `[COMPLETE] Reconnaissance finished`);
    addLog('system', 'info', `[STATS] Tools: ${successCount} succeeded, ${errorCount} failed`);
    addLog('system', 'info', `[STATS] Findings: ${extractedFindings.length} total`);
    
    if (criticalCount > 0) {
      addLog('system', 'error', `[CRITICAL] ${criticalCount} critical vulnerabilities found!`);
    }
    if (highCount > 0) {
      addLog('system', 'warning', `[HIGH] ${highCount} high severity issues found`);
    }

    setStatus(abortRef.current ? 'idle' : 'completed');
    return scanResults;
  }, [addLog, checkApiStatus]);

  const cancelScan = useCallback(() => {
    abortRef.current = true;
    addLog('system', 'warning', '[CANCEL] Cancellation requested...');
  }, [addLog]);

  const resetScan = useCallback(() => {
    abortRef.current = false;
    setStatus('idle');
    setLogs([]);
    setResults([]);
    setFindings([]);
    setProgress({ current: 0, total: 0, currentTool: '' });
  }, []);

  return {
    status,
    logs,
    results,
    findings,
    progress,
    isApiAvailable,
    startScan,
    cancelScan,
    resetScan,
    checkApiStatus,
  };
}

export default useReconScan;
