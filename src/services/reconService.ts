/**
 * Reconnaissance API Service
 * Provides methods to interact with the AETHER Recon API endpoints
 */

import { apiRequest, checkApiHealth } from './api';
import type {
  ReconResponse,
  ToolsListResponse,
  HealthCheckResponse,
  ToolId,
  NmapOptions,
  NiktoOptions,
  WhatwebOptions,
  DirsearchOptions,
  GobusterOptions,
  SubdomainOptions,
  DnsOptions,
  HttpxOptions,
  HarvesterOptions,
  ToolOptions,
  ReconTool,
  ToolCategory,
} from './types/recon.types';

// Tool definitions with metadata
export const RECON_TOOLS: ReconTool[] = [
  {
    id: 'nmap',
    name: 'Nmap',
    description: 'Network discovery and port scanning',
    category: 'port-scan',
    endpoint: '/api/recon/nmap',
    icon: 'Network',
    enabled: true,
    estimatedTime: '30-180s',
  },
  {
    id: 'whatweb',
    name: 'WhatWeb',
    description: 'Web technology identification',
    category: 'web-analysis',
    endpoint: '/api/recon/whatweb',
    icon: 'Globe',
    enabled: true,
    estimatedTime: '10-60s',
  },
  {
    id: 'nikto',
    name: 'Nikto',
    description: 'Web server vulnerability scanner',
    category: 'vuln-scan',
    endpoint: '/api/recon/nikto',
    icon: 'Shield',
    enabled: true,
    estimatedTime: '60-300s',
  },
  {
    id: 'gobuster',
    name: 'Gobuster',
    description: 'Directory/DNS/VHost busting tool',
    category: 'directory',
    endpoint: '/api/recon/gobuster',
    icon: 'Search',
    enabled: true,
    estimatedTime: '30-120s',
  },
  {
    id: 'subfinder',
    name: 'Subfinder',
    description: 'Fast subdomain enumeration',
    category: 'subdomain',
    endpoint: '/api/recon/subfinder',
    icon: 'GitBranch',
    enabled: true,
    estimatedTime: '15-60s',
  },
  {
    id: 'amass',
    name: 'Amass',
    description: 'In-depth subdomain enumeration',
    category: 'subdomain',
    endpoint: '/api/recon/amass',
    icon: 'Radar',
    enabled: true,
    estimatedTime: '60-180s',
  },
  {
    id: 'dnsenum',
    name: 'DNSenum',
    description: 'DNS enumeration tool',
    category: 'dns',
    endpoint: '/api/recon/dnsenum',
    icon: 'Database',
    enabled: true,
    estimatedTime: '15-60s',
  },
  {
    id: 'httpx',
    name: 'HTTPX',
    description: 'HTTP toolkit for probing',
    category: 'web-analysis',
    endpoint: '/api/recon/httpx',
    icon: 'Zap',
    enabled: true,
    estimatedTime: '10-30s',
  },
  {
    id: 'theharvester',
    name: 'TheHarvester',
    description: 'Email and subdomain harvesting',
    category: 'osint',
    endpoint: '/api/recon/theharvester',
    icon: 'Mail',
    enabled: true,
    estimatedTime: '30-60s',
  },
];

// Tool categories for UI organization
export const TOOL_CATEGORIES: Record<ToolCategory, { name: string; description: string }> = {
  'port-scan': { name: 'Network Discovery', description: 'Port and service scanning' },
  'web-analysis': { name: 'Web Analysis', description: 'Technology detection and HTTP probing' },
  'dns': { name: 'DNS Enumeration', description: 'DNS record discovery' },
  'subdomain': { name: 'Subdomain Discovery', description: 'Find subdomains and related hosts' },
  'directory': { name: 'Directory Discovery', description: 'Web path brute-forcing' },
  'vuln-scan': { name: 'Vulnerability Scanning', description: 'Security assessment' },
  'osint': { name: 'OSINT', description: 'Open source intelligence gathering' },
};

/**
 * Reconnaissance API Service
 */
export const reconService = {
  /**
   * Check API health
   */
  async checkHealth(): Promise<HealthCheckResponse> {
    return apiRequest<HealthCheckResponse>('/');
  },

  /**
   * Check if API is available
   */
  async isAvailable(): Promise<boolean> {
    return checkApiHealth();
  },

  /**
   * Get available tools from API
   */
  async getTools(): Promise<ToolsListResponse> {
    return apiRequest<ToolsListResponse>('/api/tools');
  },

  /**
   * Run Nmap port scan
   */
  async runNmap(target: string, options: NmapOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/nmap', {
      method: 'POST',
      body: JSON.stringify({
        target,
        scan_type: options.scanType || 'service',
        ports: options.ports || 'top-100',
        timeout: options.timeout || 180,
      }),
    });
  },

  /**
   * Run WhatWeb technology detection
   */
  async runWhatweb(target: string, options: WhatwebOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/whatweb', {
      method: 'POST',
      body: JSON.stringify({
        target,
        aggression: options.aggression || 1,
        timeout: options.timeout || 60,
      }),
    });
  },

  /**
   * Run Nikto vulnerability scan
   */
  async runNikto(target: string, options: NiktoOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/nikto', {
      method: 'POST',
      body: JSON.stringify({
        target,
        ssl: options.ssl || false,
        timeout: options.timeout || 300,
      }),
    });
  },

  /**
   * Run Dirsearch directory brute-force
   */
  async runDirsearch(target: string, options: DirsearchOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/dirsearch', {
      method: 'POST',
      body: JSON.stringify({
        target,
        wordlist: options.wordlist || 'small',
        extensions: options.extensions || ['php', 'html', 'js'],
        timeout: options.timeout || 120,
      }),
    });
  },

  /**
   * Run Gobuster directory/DNS busting
   */
  async runGobuster(target: string, options: GobusterOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/gobuster', {
      method: 'POST',
      body: JSON.stringify({
        target,
        mode: options.mode || 'dir',
        wordlist: options.wordlist || 'small',
        timeout: options.timeout || 120,
      }),
    });
  },

  /**
   * Run Subfinder subdomain enumeration
   */
  async runSubfinder(target: string, options: SubdomainOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/subfinder', {
      method: 'POST',
      body: JSON.stringify({
        target,
        timeout: options.timeout || 60,
      }),
    });
  },

  /**
   * Run Amass subdomain enumeration
   */
  async runAmass(target: string, options: SubdomainOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/amass', {
      method: 'POST',
      body: JSON.stringify({
        target,
        timeout: options.timeout || 180,
      }),
    });
  },

  /**
   * Run DNSenum DNS enumeration
   */
  async runDnsenum(target: string, options: DnsOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/dnsenum', {
      method: 'POST',
      body: JSON.stringify({
        target,
        timeout: options.timeout || 60,
      }),
    });
  },

  /**
   * Run HTTPX HTTP probing
   */
  async runHttpx(target: string, options: HttpxOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/httpx', {
      method: 'POST',
      body: JSON.stringify({
        target,
        timeout: options.timeout || 30,
      }),
    });
  },

  /**
   * Run TheHarvester OSINT gathering
   */
  async runTheharvester(target: string, options: HarvesterOptions = {}): Promise<ReconResponse> {
    return apiRequest<ReconResponse>('/api/recon/theharvester', {
      method: 'POST',
      body: JSON.stringify({
        target,
        timeout: options.timeout || 60,
      }),
    });
  },

  /**
   * Get the appropriate scan method for a tool
   */
  getScanMethod(toolId: ToolId): ((target: string, options?: ToolOptions) => Promise<ReconResponse>) | null {
    const methods: Record<ToolId, (target: string, options?: ToolOptions) => Promise<ReconResponse>> = {
      nmap: (t, o) => this.runNmap(t, o as NmapOptions),
      whatweb: (t, o) => this.runWhatweb(t, o as WhatwebOptions),
      nikto: (t, o) => this.runNikto(t, o as NiktoOptions),
      dirsearch: (t, o) => this.runDirsearch(t, o as DirsearchOptions),
      gobuster: (t, o) => this.runGobuster(t, o as GobusterOptions),
      subfinder: (t, o) => this.runSubfinder(t, o as SubdomainOptions),
      amass: (t, o) => this.runAmass(t, o as SubdomainOptions),
      dnsenum: (t, o) => this.runDnsenum(t, o as DnsOptions),
      httpx: (t, o) => this.runHttpx(t, o as HttpxOptions),
      theharvester: (t, o) => this.runTheharvester(t, o as HarvesterOptions),
    };
    return methods[toolId] || null;
  },

  /**
   * Run a scan pipeline with multiple tools
   */
  async runScanPipeline(
    target: string,
    tools: ToolId[],
    options: Partial<Record<ToolId, ToolOptions>> = {},
    onProgress?: (tool: ToolId, result: ReconResponse, index: number, total: number) => void
  ): Promise<ReconResponse[]> {
    const results: ReconResponse[] = [];
    
    for (let i = 0; i < tools.length; i++) {
      const tool = tools[i];
      const toolOptions = options[tool] || {};
      const scanMethod = this.getScanMethod(tool);
      
      if (scanMethod) {
        try {
          const result = await scanMethod(target, toolOptions);
          results.push(result);
          onProgress?.(tool, result, i, tools.length);
        } catch (error) {
          const errorResult: ReconResponse = {
            tool,
            target,
            status: 'error',
            execution_time: '0s',
            parameters: toolOptions as Record<string, unknown>,
            results: { raw: '', parsed: {} },
            errors: error instanceof Error ? error.message : 'Unknown error occurred',
          };
          results.push(errorResult);
          onProgress?.(tool, errorResult, i, tools.length);
        }
      }
    }
    
    return results;
  },
};

export default reconService;
