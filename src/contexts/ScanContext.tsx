/**
 * Global Scan Context
 * Persists scan state across page navigation for both Recon and Enumeration scans
 */

import React, { createContext, useContext, useReducer, useCallback, useRef, useEffect } from 'react';
import { reconService } from '@/services/reconService';
import {
  saveReconScan,
  completeReconScan,
  loadLastReconScan,
  loadLastEnumerationScan,
} from '@/services/supabaseService';
import type { ReconLogInsert, ReconFindingInsert, ReconResultInsert } from '@/types/database';
import type {
  ScanStatus,
  LogEntry,
  ToolId,
  ToolOptions,
  ReconResponse,
  ScanResultItem,
  Severity,
} from '@/services/types/recon.types';
import type { Vulnerability } from '@/types/scan';

// ============================================================================
// Types
// ============================================================================

interface ReconScanState {
  scanId: string | null;
  status: ScanStatus;
  target: string;
  logs: LogEntry[];
  results: ReconResponse[];
  findings: ScanResultItem[];
  progress: { current: number; total: number; currentTool: string };
  isApiAvailable: boolean;
  selectedTools: ToolId[];
  toolOptions: Partial<Record<ToolId, ToolOptions>>;
  savedToSupabase: boolean;
  scanStartTime: string | null;
}

interface EnumerationScanState {
  scanId: string | null;
  target: string;
  status: ScanStatus;
  logs: Array<{ id: number; type: 'info' | 'ok' | 'warn' | 'critical'; message: string }>;
  progress: number;
  phase: string;
  vulnerabilities: Vulnerability[];
  savedToSupabase: boolean;
  scanStartTime: string | null;
}

interface ScanContextState {
  recon: ReconScanState;
  enumeration: EnumerationScanState;
}

type ReconAction =
  | { type: 'RECON_SET_SCAN_ID'; payload: string | null }
  | { type: 'RECON_SET_STATUS'; payload: ScanStatus }
  | { type: 'RECON_SET_TARGET'; payload: string }
  | { type: 'RECON_ADD_LOG'; payload: LogEntry }
  | { type: 'RECON_SET_LOGS'; payload: LogEntry[] }
  | { type: 'RECON_ADD_RESULT'; payload: ReconResponse }
  | { type: 'RECON_SET_RESULTS'; payload: ReconResponse[] }
  | { type: 'RECON_SET_FINDINGS'; payload: ScanResultItem[] }
  | { type: 'RECON_SET_PROGRESS'; payload: { current: number; total: number; currentTool: string } }
  | { type: 'RECON_SET_API_AVAILABLE'; payload: boolean }
  | { type: 'RECON_SET_SELECTED_TOOLS'; payload: ToolId[] }
  | { type: 'RECON_SET_TOOL_OPTIONS'; payload: Partial<Record<ToolId, ToolOptions>> }
  | { type: 'RECON_SET_SAVED_TO_SUPABASE'; payload: boolean }
  | { type: 'RECON_SET_SCAN_START_TIME'; payload: string | null }
  | { type: 'RECON_RESET' };

type EnumerationAction =
  | { type: 'ENUM_SET_SCAN_ID'; payload: string | null }
  | { type: 'ENUM_SET_TARGET'; payload: string }
  | { type: 'ENUM_SET_STATUS'; payload: ScanStatus }
  | { type: 'ENUM_ADD_LOG'; payload: { id: number; type: 'info' | 'ok' | 'warn' | 'critical'; message: string } }
  | { type: 'ENUM_SET_LOGS'; payload: Array<{ id: number; type: 'info' | 'ok' | 'warn' | 'critical'; message: string }> }
  | { type: 'ENUM_SET_PROGRESS'; payload: number }
  | { type: 'ENUM_SET_PHASE'; payload: string }
  | { type: 'ENUM_ADD_VULNERABILITY'; payload: Vulnerability }
  | { type: 'ENUM_SET_VULNERABILITIES'; payload: Vulnerability[] }
  | { type: 'ENUM_SET_SAVED_TO_SUPABASE'; payload: boolean }
  | { type: 'ENUM_SET_SCAN_START_TIME'; payload: string | null }
  | { type: 'ENUM_RESET' };

type ScanAction = ReconAction | EnumerationAction;

// ============================================================================
// Initial State
// ============================================================================

const initialReconState: ReconScanState = {
  scanId: null,
  status: 'idle',
  target: '',
  logs: [],
  results: [],
  findings: [],
  progress: { current: 0, total: 0, currentTool: '' },
  isApiAvailable: true,
  selectedTools: ['httpx', 'whatweb', 'nmap'],
  toolOptions: {},
  savedToSupabase: false,
  scanStartTime: null,
};

const initialEnumerationState: EnumerationScanState = {
  scanId: null,
  target: '',
  status: 'idle',
  logs: [],
  progress: 0,
  phase: '',
  vulnerabilities: [],
  savedToSupabase: false,
  scanStartTime: null,
};

const initialState: ScanContextState = {
  recon: initialReconState,
  enumeration: initialEnumerationState,
};

// ============================================================================
// Reducer
// ============================================================================

function scanReducer(state: ScanContextState, action: ScanAction): ScanContextState {
  switch (action.type) {
    // Recon actions
    case 'RECON_SET_SCAN_ID':
      return { ...state, recon: { ...state.recon, scanId: action.payload } };
    case 'RECON_SET_STATUS':
      return { ...state, recon: { ...state.recon, status: action.payload } };
    case 'RECON_SET_TARGET':
      return { ...state, recon: { ...state.recon, target: action.payload } };
    case 'RECON_ADD_LOG':
      return { ...state, recon: { ...state.recon, logs: [...state.recon.logs, action.payload] } };
    case 'RECON_SET_LOGS':
      return { ...state, recon: { ...state.recon, logs: action.payload } };
    case 'RECON_ADD_RESULT':
      return { ...state, recon: { ...state.recon, results: [...state.recon.results, action.payload] } };
    case 'RECON_SET_RESULTS':
      return { ...state, recon: { ...state.recon, results: action.payload } };
    case 'RECON_SET_FINDINGS':
      return { ...state, recon: { ...state.recon, findings: action.payload } };
    case 'RECON_SET_PROGRESS':
      return { ...state, recon: { ...state.recon, progress: action.payload } };
    case 'RECON_SET_API_AVAILABLE':
      return { ...state, recon: { ...state.recon, isApiAvailable: action.payload } };
    case 'RECON_SET_SELECTED_TOOLS':
      return { ...state, recon: { ...state.recon, selectedTools: action.payload } };
    case 'RECON_SET_TOOL_OPTIONS':
      return { ...state, recon: { ...state.recon, toolOptions: action.payload } };
    case 'RECON_SET_SAVED_TO_SUPABASE':
      return { ...state, recon: { ...state.recon, savedToSupabase: action.payload } };
    case 'RECON_SET_SCAN_START_TIME':
      return { ...state, recon: { ...state.recon, scanStartTime: action.payload } };
    case 'RECON_RESET':
      return { ...state, recon: { ...initialReconState, isApiAvailable: state.recon.isApiAvailable } };

    // Enumeration actions
    case 'ENUM_SET_SCAN_ID':
      return { ...state, enumeration: { ...state.enumeration, scanId: action.payload } };
    case 'ENUM_SET_TARGET':
      return { ...state, enumeration: { ...state.enumeration, target: action.payload } };
    case 'ENUM_SET_STATUS':
      return { ...state, enumeration: { ...state.enumeration, status: action.payload } };
    case 'ENUM_ADD_LOG':
      return { ...state, enumeration: { ...state.enumeration, logs: [...state.enumeration.logs, action.payload] } };
    case 'ENUM_SET_LOGS':
      return { ...state, enumeration: { ...state.enumeration, logs: action.payload } };
    case 'ENUM_SET_PROGRESS':
      return { ...state, enumeration: { ...state.enumeration, progress: action.payload } };
    case 'ENUM_SET_PHASE':
      return { ...state, enumeration: { ...state.enumeration, phase: action.payload } };
    case 'ENUM_ADD_VULNERABILITY':
      return { ...state, enumeration: { ...state.enumeration, vulnerabilities: [...state.enumeration.vulnerabilities, action.payload] } };
    case 'ENUM_SET_VULNERABILITIES':
      return { ...state, enumeration: { ...state.enumeration, vulnerabilities: action.payload } };
    case 'ENUM_SET_SAVED_TO_SUPABASE':
      return { ...state, enumeration: { ...state.enumeration, savedToSupabase: action.payload } };
    case 'ENUM_SET_SCAN_START_TIME':
      return { ...state, enumeration: { ...state.enumeration, scanStartTime: action.payload } };
    case 'ENUM_RESET':
      return { ...state, enumeration: initialEnumerationState };

    default:
      return state;
  }
}

// ============================================================================
// Context
// ============================================================================

interface ScanContextValue {
  state: ScanContextState;
  dispatch: React.Dispatch<ScanAction>;
  // Recon helpers
  reconAddLog: (tool: string, type: LogEntry['type'], message: string) => void;
  reconStartScan: (target: string, tools: ToolId[], options?: Partial<Record<ToolId, ToolOptions>>) => Promise<ReconResponse[]>;
  reconCancelScan: () => void;
  reconResetScan: () => void;
  reconCheckApiStatus: () => Promise<boolean>;
  loadLastRecon: () => Promise<void>;
  // Enumeration helpers
  enumAddLog: (id: number, type: 'info' | 'ok' | 'warn' | 'critical', message: string) => void;
  loadLastEnumeration: () => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | null>(null);

// ============================================================================
// Helper Functions
// ============================================================================

function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

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

// ============================================================================
// Provider
// ============================================================================

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);
  const abortRef = useRef(false);
  const hasLoadedLastScan = useRef({ recon: false, enumeration: false });

  // Recon: Add log
  const reconAddLog = useCallback((tool: string, type: LogEntry['type'], message: string) => {
    const entry: LogEntry = {
      id: generateId(),
      timestamp: new Date(),
      tool,
      type,
      message,
    };
    dispatch({ type: 'RECON_ADD_LOG', payload: entry });
  }, []);

  // Recon: Check API status
  const reconCheckApiStatus = useCallback(async (): Promise<boolean> => {
    try {
      const available = await reconService.isAvailable();
      dispatch({ type: 'RECON_SET_API_AVAILABLE', payload: available });
      return available;
    } catch {
      dispatch({ type: 'RECON_SET_API_AVAILABLE', payload: false });
      return false;
    }
  }, []);

  // Recon: Start scan
  const reconStartScan = useCallback(async (
    target: string,
    tools: ToolId[],
    options: Partial<Record<ToolId, ToolOptions>> = {}
  ): Promise<ReconResponse[]> => {
    // Reset state
    abortRef.current = false;
    dispatch({ type: 'RECON_SET_STATUS', payload: 'running' });
    dispatch({ type: 'RECON_SET_TARGET', payload: target });
    dispatch({ type: 'RECON_SET_LOGS', payload: [] });
    dispatch({ type: 'RECON_SET_RESULTS', payload: [] });
    dispatch({ type: 'RECON_SET_FINDINGS', payload: [] });
    dispatch({ type: 'RECON_SET_PROGRESS', payload: { current: 0, total: tools.length, currentTool: '' } });
    dispatch({ type: 'RECON_SET_SELECTED_TOOLS', payload: tools });
    dispatch({ type: 'RECON_SET_TOOL_OPTIONS', payload: options });
    dispatch({ type: 'RECON_SET_SAVED_TO_SUPABASE', payload: false });
    dispatch({ type: 'RECON_SET_SCAN_START_TIME', payload: new Date().toISOString() });

    // Save scan to Supabase
    let scanId: string | null = null;
    try {
      const savedScan = await saveReconScan(target, tools);
      scanId = savedScan.id;
      dispatch({ type: 'RECON_SET_SCAN_ID', payload: scanId });
    } catch (error) {
      console.error('Failed to save recon scan to database:', error);
    }

    // Check API availability
    const apiAvailable = await reconCheckApiStatus();
    if (!apiAvailable) {
      reconAddLog('system', 'error', 'Reconnaissance API is not available. Please ensure the server is running.');
      dispatch({ type: 'RECON_SET_STATUS', payload: 'error' });
      return [];
    }

    reconAddLog('system', 'info', `[INIT] Starting reconnaissance on ${target}`);
    reconAddLog('system', 'info', `[INFO] Selected tools: ${tools.join(', ')}`);
    reconAddLog('system', 'info', `[INFO] Total scans to run: ${tools.length}`);

    const scanResults: ReconResponse[] = [];
    const collectedLogs: LogEntry[] = [];

    for (let i = 0; i < tools.length; i++) {
      if (abortRef.current) {
        reconAddLog('system', 'warning', '[ABORT] Scan cancelled by user');
        break;
      }

      const tool = tools[i];
      const toolOptions = options[tool] || {};
      
      dispatch({ type: 'RECON_SET_PROGRESS', payload: { current: i + 1, total: tools.length, currentTool: tool } });
      
      const logEntry: LogEntry = {
        id: generateId(),
        timestamp: new Date(),
        tool,
        type: 'info',
        message: `[${(i + 1)}/${tools.length}] Starting ${tool} scan...`,
      };
      dispatch({ type: 'RECON_ADD_LOG', payload: logEntry });
      collectedLogs.push(logEntry);

      const scanMethod = reconService.getScanMethod(tool);
      
      if (scanMethod) {
        try {
          const startTime = Date.now();
          const result = await scanMethod(target, toolOptions);
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
          
          scanResults.push(result);
          dispatch({ type: 'RECON_ADD_RESULT', payload: result });

          if (result.status === 'success') {
            const successLog: LogEntry = {
              id: generateId(),
              timestamp: new Date(),
              tool,
              type: 'success',
              message: `[OK] ${tool} completed in ${result.execution_time || elapsed + 's'}`,
            };
            dispatch({ type: 'RECON_ADD_LOG', payload: successLog });
            collectedLogs.push(successLog);
            
            // Log some interesting findings
            const parsed = result.results?.parsed || {};
            if (parsed.open_ports?.length) {
              const portLog: LogEntry = {
                id: generateId(),
                timestamp: new Date(),
                tool,
                type: 'info',
                message: `[INFO] Found ${parsed.open_ports.length} open ports`,
              };
              dispatch({ type: 'RECON_ADD_LOG', payload: portLog });
              collectedLogs.push(portLog);
            }
            if (parsed.technologies?.length) {
              const techLog: LogEntry = {
                id: generateId(),
                timestamp: new Date(),
                tool,
                type: 'info',
                message: `[INFO] Detected technologies: ${parsed.technologies.slice(0, 3).join(', ')}`,
              };
              dispatch({ type: 'RECON_ADD_LOG', payload: techLog });
              collectedLogs.push(techLog);
            }
            if (parsed.vulnerabilities?.length) {
              const vulnLog: LogEntry = {
                id: generateId(),
                timestamp: new Date(),
                tool,
                type: 'warning',
                message: `[VULN] Found ${parsed.vulnerabilities.length} potential vulnerabilities`,
              };
              dispatch({ type: 'RECON_ADD_LOG', payload: vulnLog });
              collectedLogs.push(vulnLog);
            }
            if (parsed.subdomains?.length) {
              const subLog: LogEntry = {
                id: generateId(),
                timestamp: new Date(),
                tool,
                type: 'info',
                message: `[INFO] Discovered ${parsed.subdomains.length} subdomains`,
              };
              dispatch({ type: 'RECON_ADD_LOG', payload: subLog });
              collectedLogs.push(subLog);
            }
          } else {
            const errorLog: LogEntry = {
              id: generateId(),
              timestamp: new Date(),
              tool,
              type: 'error',
              message: `[ERROR] ${tool} failed: ${result.errors || 'Unknown error'}`,
            };
            dispatch({ type: 'RECON_ADD_LOG', payload: errorLog });
            collectedLogs.push(errorLog);
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          const errorLog: LogEntry = {
            id: generateId(),
            timestamp: new Date(),
            tool,
            type: 'error',
            message: `[ERROR] ${tool} failed: ${errorMessage}`,
          };
          dispatch({ type: 'RECON_ADD_LOG', payload: errorLog });
          collectedLogs.push(errorLog);
          
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
          dispatch({ type: 'RECON_ADD_RESULT', payload: errorResult });
        }
      }
    }

    // Extract and set findings
    const extractedFindings = extractFindings(scanResults);
    dispatch({ type: 'RECON_SET_FINDINGS', payload: extractedFindings });

    // Final summary
    const successCount = scanResults.filter(r => r.status === 'success').length;
    const errorCount = scanResults.filter(r => r.status === 'error').length;
    const criticalCount = extractedFindings.filter(f => f.severity === 'critical').length;
    const highCount = extractedFindings.filter(f => f.severity === 'high').length;

    const summaryLogs: LogEntry[] = [
      { id: generateId(), timestamp: new Date(), tool: 'system', type: 'info', message: '' },
      { id: generateId(), timestamp: new Date(), tool: 'system', type: 'info', message: '═══════════════════════════════════════════════' },
      { id: generateId(), timestamp: new Date(), tool: 'system', type: 'success', message: '[COMPLETE] Reconnaissance finished' },
      { id: generateId(), timestamp: new Date(), tool: 'system', type: 'info', message: `[STATS] Tools: ${successCount} succeeded, ${errorCount} failed` },
      { id: generateId(), timestamp: new Date(), tool: 'system', type: 'info', message: `[STATS] Findings: ${extractedFindings.length} total` },
    ];
    
    if (criticalCount > 0) {
      summaryLogs.push({ id: generateId(), timestamp: new Date(), tool: 'system', type: 'error', message: `[CRITICAL] ${criticalCount} critical vulnerabilities found!` });
    }
    if (highCount > 0) {
      summaryLogs.push({ id: generateId(), timestamp: new Date(), tool: 'system', type: 'warning', message: `[HIGH] ${highCount} high severity issues found` });
    }

    summaryLogs.forEach(log => {
      dispatch({ type: 'RECON_ADD_LOG', payload: log });
      collectedLogs.push(log);
    });

    dispatch({ type: 'RECON_SET_STATUS', payload: abortRef.current ? 'idle' : 'completed' });

    // Save to Supabase
    if (scanId) {
      try {
        // Convert logs to database format
        const dbLogs: ReconLogInsert[] = collectedLogs.map(log => ({
          scan_id: scanId,
          tool: log.tool,
          log_type: log.type,
          message: log.message,
        }));

        // Convert findings to database format
        const dbFindings: ReconFindingInsert[] = extractedFindings.map(finding => ({
          scan_id: scanId,
          tool: finding.tool,
          severity: finding.severity,
          name: finding.name,
          description: finding.description || null,
          endpoint: finding.endpoint || null,
          status: finding.status,
        }));

        // Convert results to database format
        const dbResults: ReconResultInsert[] = scanResults.map(result => ({
          scan_id: scanId,
          tool: result.tool,
          status: result.status,
          execution_time: result.execution_time || null,
          parameters: result.parameters,
          raw_output: result.results?.raw || null,
          parsed_results: (result.results?.parsed as Record<string, unknown>) || null,
          errors: result.errors || null,
        }));

        await completeReconScan(
          scanId,
          dbLogs,
          dbFindings,
          dbResults,
          abortRef.current ? 'cancelled' : 'completed'
        );
        dispatch({ type: 'RECON_SET_SAVED_TO_SUPABASE', payload: true });
      } catch (error) {
        console.error('Failed to save recon results to database:', error);
      }
    }

    return scanResults;
  }, [reconAddLog, reconCheckApiStatus]);

  // Recon: Cancel scan
  const reconCancelScan = useCallback(() => {
    abortRef.current = true;
    reconAddLog('system', 'warning', '[CANCEL] Cancellation requested...');
  }, [reconAddLog]);

  // Recon: Reset scan
  const reconResetScan = useCallback(() => {
    abortRef.current = false;
    dispatch({ type: 'RECON_RESET' });
  }, []);

  // Recon: Load last scan from database
  const loadLastRecon = useCallback(async () => {
    if (hasLoadedLastScan.current.recon || state.recon.status === 'running') {
      console.log('[ScanContext] Skipping loadLastRecon - already loaded or running');
      return;
    }
    
    try {
      console.log('[ScanContext] Loading last recon scan from database...');
      const lastScan = await loadLastReconScan();
      
      if (!lastScan || !lastScan.scan) {
        console.log('[ScanContext] No previous recon scan found in database');
        return;
      }
      
      console.log('[ScanContext] Found last recon scan:', lastScan.scan.id, 'with', lastScan.logs.length, 'logs');
      hasLoadedLastScan.current.recon = true;
        
        // Convert database logs to LogEntry format
        const logs: LogEntry[] = lastScan.logs.map(log => ({
          id: log.id,
          timestamp: new Date(log.created_at || Date.now()),
          tool: log.tool,
          type: log.log_type as LogEntry['type'],
          message: log.message,
        }));

        // Convert database findings to ScanResultItem format
        const findings: ScanResultItem[] = lastScan.findings.map(f => ({
          id: f.id,
          tool: f.tool as ToolId,
          severity: f.severity as Severity,
          name: f.name,
          description: f.description || undefined,
          endpoint: f.endpoint || undefined,
          status: f.status as ScanResultItem['status'],
        }));

        // Convert database results to ReconResponse format
        const results: ReconResponse[] = lastScan.results.map(r => ({
          tool: r.tool,
          target: lastScan.scan.target_url,
          status: r.status as 'success' | 'error',
          execution_time: r.execution_time || undefined,
          parameters: (r.parameters as Record<string, unknown>) || {},
          results: {
            raw: r.raw_output || '',
            parsed: (r.parsed_results as Record<string, unknown>) || {},
          },
          errors: r.errors || undefined,
        }));

        dispatch({ type: 'RECON_SET_SCAN_ID', payload: lastScan.scan.id });
        dispatch({ type: 'RECON_SET_TARGET', payload: lastScan.scan.target_url });
        dispatch({ type: 'RECON_SET_STATUS', payload: lastScan.scan.status as ScanStatus });
        dispatch({ type: 'RECON_SET_LOGS', payload: logs });
        dispatch({ type: 'RECON_SET_FINDINGS', payload: findings });
        dispatch({ type: 'RECON_SET_RESULTS', payload: results });
        dispatch({ type: 'RECON_SET_SAVED_TO_SUPABASE', payload: true });
        dispatch({ type: 'RECON_SET_SCAN_START_TIME', payload: lastScan.scan.started_at });
        
        // Set selected tools from the scan
        if (lastScan.scan.parameters && typeof lastScan.scan.parameters === 'object') {
          const params = lastScan.scan.parameters as { selected_tools?: string[] };
          if (params.selected_tools) {
            dispatch({ type: 'RECON_SET_SELECTED_TOOLS', payload: params.selected_tools as ToolId[] });
          }
        }
        
        console.log('[ScanContext] Recon scan restored successfully');
    } catch (error) {
      console.error('Failed to load last recon scan:', error);
    }
  }, [state.recon.status]);

  // Enumeration: Load last scan from database
  const loadLastEnumeration = useCallback(async () => {
    if (hasLoadedLastScan.current.enumeration || state.enumeration.status === 'running') return;
    
    try {
      const lastScan = await loadLastEnumerationScan();
      if (lastScan && lastScan.scan) {
        hasLoadedLastScan.current.enumeration = true;
        
        // Convert database vulnerabilities to frontend Vulnerability format
        const vulnerabilities: Vulnerability[] = lastScan.vulnerabilities.map(v => ({
          id: v.id,
          name: v.name,
          severity: v.severity as Vulnerability['severity'],
          owasp_category: v.owasp_category as Vulnerability['owasp_category'],
          cwe_id: v.cwe_id || undefined,
          endpoint: v.endpoint,
          method: v.method,
          parameter: v.parameter,
          evidence: v.evidence || '',
          description: v.description,
          remediation: v.remediation,
          confidence: v.confidence,
          detected_at: v.created_at,
          detector_name: 'scanner',
        }));
        
        dispatch({ type: 'ENUM_SET_SCAN_ID', payload: lastScan.scan.id });
        dispatch({ type: 'ENUM_SET_TARGET', payload: lastScan.scan.target_url });
        dispatch({ type: 'ENUM_SET_STATUS', payload: lastScan.scan.status as ScanStatus });
        dispatch({ type: 'ENUM_SET_VULNERABILITIES', payload: vulnerabilities });
        dispatch({ type: 'ENUM_SET_SAVED_TO_SUPABASE', payload: true });
        dispatch({ type: 'ENUM_SET_SCAN_START_TIME', payload: lastScan.scan.started_at });
        dispatch({ type: 'ENUM_SET_PROGRESS', payload: 100 });
        dispatch({ type: 'ENUM_SET_PHASE', payload: 'Completed' });
      }
    } catch (error) {
      console.error('Failed to load last enumeration scan:', error);
    }
  }, [state.enumeration.status]);

  // Enumeration: Add log
  const enumAddLog = useCallback((id: number, type: 'info' | 'ok' | 'warn' | 'critical', message: string) => {
    dispatch({ type: 'ENUM_ADD_LOG', payload: { id, type, message } });
  }, []);

  const value: ScanContextValue = {
    state,
    dispatch,
    reconAddLog,
    reconStartScan,
    reconCancelScan,
    reconResetScan,
    reconCheckApiStatus,
    loadLastRecon,
    enumAddLog,
    loadLastEnumeration,
  };

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useScanContext() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScanContext must be used within a ScanProvider');
  }
  return context;
}

// ============================================================================
// Convenience Hooks
// ============================================================================

export function useReconScanContext() {
  const { state, dispatch, reconAddLog, reconStartScan, reconCancelScan, reconResetScan, reconCheckApiStatus, loadLastRecon } = useScanContext();
  
  return {
    scanId: state.recon.scanId,
    status: state.recon.status,
    target: state.recon.target,
    logs: state.recon.logs,
    results: state.recon.results,
    findings: state.recon.findings,
    progress: state.recon.progress,
    isApiAvailable: state.recon.isApiAvailable,
    selectedTools: state.recon.selectedTools,
    toolOptions: state.recon.toolOptions,
    savedToSupabase: state.recon.savedToSupabase,
    scanStartTime: state.recon.scanStartTime,
    setScanId: (id: string | null) => dispatch({ type: 'RECON_SET_SCAN_ID', payload: id }),
    setSelectedTools: (tools: ToolId[]) => dispatch({ type: 'RECON_SET_SELECTED_TOOLS', payload: tools }),
    setToolOptions: (options: Partial<Record<ToolId, ToolOptions>>) => dispatch({ type: 'RECON_SET_TOOL_OPTIONS', payload: options }),
    addLog: reconAddLog,
    startScan: reconStartScan,
    cancelScan: reconCancelScan,
    resetScan: reconResetScan,
    checkApiStatus: reconCheckApiStatus,
    loadLastScan: loadLastRecon,
  };
}

export function useEnumerationScanContext() {
  const { state, dispatch, enumAddLog, loadLastEnumeration } = useScanContext();
  
  return {
    scanId: state.enumeration.scanId,
    target: state.enumeration.target,
    status: state.enumeration.status,
    logs: state.enumeration.logs,
    progress: state.enumeration.progress,
    phase: state.enumeration.phase,
    vulnerabilities: state.enumeration.vulnerabilities,
    savedToSupabase: state.enumeration.savedToSupabase,
    scanStartTime: state.enumeration.scanStartTime,
    setScanId: (id: string | null) => dispatch({ type: 'ENUM_SET_SCAN_ID', payload: id }),
    setTarget: (target: string) => dispatch({ type: 'ENUM_SET_TARGET', payload: target }),
    setStatus: (status: ScanStatus) => dispatch({ type: 'ENUM_SET_STATUS', payload: status }),
    addLog: enumAddLog,
    setLogs: (logs: Array<{ id: number; type: 'info' | 'ok' | 'warn' | 'critical'; message: string }>) => 
      dispatch({ type: 'ENUM_SET_LOGS', payload: logs }),
    setProgress: (progress: number) => dispatch({ type: 'ENUM_SET_PROGRESS', payload: progress }),
    setPhase: (phase: string) => dispatch({ type: 'ENUM_SET_PHASE', payload: phase }),
    addVulnerability: (vuln: Vulnerability) => dispatch({ type: 'ENUM_ADD_VULNERABILITY', payload: vuln }),
    setVulnerabilities: (vulns: Vulnerability[]) => dispatch({ type: 'ENUM_SET_VULNERABILITIES', payload: vulns }),
    setSavedToSupabase: (saved: boolean) => dispatch({ type: 'ENUM_SET_SAVED_TO_SUPABASE', payload: saved }),
    setScanStartTime: (time: string | null) => dispatch({ type: 'ENUM_SET_SCAN_START_TIME', payload: time }),
    resetScan: () => dispatch({ type: 'ENUM_RESET' }),
    loadLastScan: loadLastEnumeration,
  };
}

export default ScanContext;
