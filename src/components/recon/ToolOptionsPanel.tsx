/**
 * ToolOptionsPanel Component
 * Dynamic configuration panel for tool-specific options
 */

import { useState } from "react";
import { ChevronDown, ChevronRight, Settings2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";
import type {
  ToolId,
  ToolOptions,
  NmapOptions,
  NiktoOptions,
  WhatwebOptions,
  DirsearchOptions,
  GobusterOptions,
} from "@/services/types/recon.types";

interface ToolOptionsPanelProps {
  selectedTools: ToolId[];
  options: Partial<Record<ToolId, ToolOptions>>;
  onOptionsChange: (toolId: ToolId, options: ToolOptions) => void;
  disabled?: boolean;
}

interface ToolConfigProps<T extends ToolOptions> {
  options: T;
  onChange: (options: T) => void;
  disabled?: boolean;
}

// Nmap Configuration
function NmapConfig({ options, onChange, disabled }: ToolConfigProps<NmapOptions>) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="nmap-scan-type">Scan Type</Label>
        <Select
          value={options.scanType || "service"}
          onValueChange={(value) => onChange({ ...options, scanType: value as NmapOptions["scanType"] })}
          disabled={disabled}
        >
          <SelectTrigger id="nmap-scan-type">
            <SelectValue placeholder="Select scan type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="service">Service Detection (-sV)</SelectItem>
            <SelectItem value="ping">Ping Scan (-sn)</SelectItem>
            <SelectItem value="syn">SYN Scan (-sS)</SelectItem>
            <SelectItem value="full">Full Scan (-A)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="nmap-ports">Ports</Label>
        <Select
          value={options.ports || "top-100"}
          onValueChange={(value) => onChange({ ...options, ports: value })}
          disabled={disabled}
        >
          <SelectTrigger id="nmap-ports">
            <SelectValue placeholder="Select port range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="top-100">Top 100 Ports</SelectItem>
            <SelectItem value="top-1000">Top 1000 Ports</SelectItem>
            <SelectItem value="1-1024">Well-known (1-1024)</SelectItem>
            <SelectItem value="1-65535">All Ports (1-65535)</SelectItem>
            <SelectItem value="21,22,23,25,80,443,3306,3389,8080">Common Services</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Timeout: {options.timeout || 180}s</Label>
        </div>
        <Slider
          value={[options.timeout || 180]}
          onValueChange={([value]) => onChange({ ...options, timeout: value })}
          min={30}
          max={300}
          step={10}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

// Nikto Configuration
function NiktoConfig({ options, onChange, disabled }: ToolConfigProps<NiktoOptions>) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="space-y-0.5">
          <Label htmlFor="nikto-ssl">Force SSL</Label>
          <p className="text-xs text-muted-foreground">Use HTTPS for scanning</p>
        </div>
        <Switch
          id="nikto-ssl"
          checked={options.ssl || false}
          onCheckedChange={(checked) => onChange({ ...options, ssl: checked })}
          disabled={disabled}
        />
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Timeout: {options.timeout || 300}s</Label>
        </div>
        <Slider
          value={[options.timeout || 300]}
          onValueChange={([value]) => onChange({ ...options, timeout: value })}
          min={60}
          max={600}
          step={30}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

// WhatWeb Configuration
function WhatwebConfig({ options, onChange, disabled }: ToolConfigProps<WhatwebOptions>) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="whatweb-aggression">Aggression Level</Label>
        <Select
          value={String(options.aggression || 1)}
          onValueChange={(value) => onChange({ ...options, aggression: Number(value) as 1 | 2 | 3 })}
          disabled={disabled}
        >
          <SelectTrigger id="whatweb-aggression">
            <SelectValue placeholder="Select aggression level" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1">1 - Stealthy (Passive)</SelectItem>
            <SelectItem value="2">2 - Moderate</SelectItem>
            <SelectItem value="3">3 - Aggressive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Timeout: {options.timeout || 60}s</Label>
        </div>
        <Slider
          value={[options.timeout || 60]}
          onValueChange={([value]) => onChange({ ...options, timeout: value })}
          min={10}
          max={180}
          step={10}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

// Dirsearch Configuration
function DirsearchConfig({ options, onChange, disabled }: ToolConfigProps<DirsearchOptions>) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="dirsearch-wordlist">Wordlist Size</Label>
        <Select
          value={options.wordlist || "small"}
          onValueChange={(value) => onChange({ ...options, wordlist: value as DirsearchOptions["wordlist"] })}
          disabled={disabled}
        >
          <SelectTrigger id="dirsearch-wordlist">
            <SelectValue placeholder="Select wordlist" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="small">Small (~500 entries)</SelectItem>
            <SelectItem value="medium">Medium (~5000 entries)</SelectItem>
            <SelectItem value="large">Large (~20000 entries)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dirsearch-extensions">File Extensions</Label>
        <Input
          id="dirsearch-extensions"
          placeholder="php,html,js,txt"
          value={options.extensions?.join(",") || "php,html,js"}
          onChange={(e) =>
            onChange({
              ...options,
              extensions: e.target.value.split(",").map((s) => s.trim()).filter(Boolean),
            })
          }
          disabled={disabled}
        />
        <p className="text-xs text-muted-foreground">Comma-separated file extensions to test</p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Timeout: {options.timeout || 120}s</Label>
        </div>
        <Slider
          value={[options.timeout || 120]}
          onValueChange={([value]) => onChange({ ...options, timeout: value })}
          min={30}
          max={300}
          step={15}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

// Gobuster Configuration
function GobusterConfig({ options, onChange, disabled }: ToolConfigProps<GobusterOptions>) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="gobuster-mode">Mode</Label>
        <Select
          value={options.mode || "dir"}
          onValueChange={(value) => onChange({ ...options, mode: value as GobusterOptions["mode"] })}
          disabled={disabled}
        >
          <SelectTrigger id="gobuster-mode">
            <SelectValue placeholder="Select mode" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="dir">Directory Brute-force</SelectItem>
            <SelectItem value="dns">DNS Subdomain</SelectItem>
            <SelectItem value="vhost">Virtual Host</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="gobuster-wordlist">Wordlist</Label>
        <Select
          value={options.wordlist || "small"}
          onValueChange={(value) => onChange({ ...options, wordlist: value })}
          disabled={disabled}
        >
          <SelectTrigger id="gobuster-wordlist">
            <SelectValue placeholder="Select wordlist" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="small">Small (~500 entries)</SelectItem>
            <SelectItem value="medium">Medium (~5000 entries)</SelectItem>
            <SelectItem value="large">Large (~20000 entries)</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label>Timeout: {options.timeout || 120}s</Label>
        </div>
        <Slider
          value={[options.timeout || 120]}
          onValueChange={([value]) => onChange({ ...options, timeout: value })}
          min={30}
          max={300}
          step={15}
          disabled={disabled}
        />
      </div>
    </div>
  );
}

// Generic timeout-only config for simpler tools
function SimpleTimeoutConfig({ 
  options, 
  onChange, 
  disabled,
  defaultTimeout = 60,
  minTimeout = 10,
  maxTimeout = 180,
}: ToolConfigProps<{ timeout?: number }> & { defaultTimeout?: number; minTimeout?: number; maxTimeout?: number }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label>Timeout: {options.timeout || defaultTimeout}s</Label>
      </div>
      <Slider
        value={[options.timeout || defaultTimeout]}
        onValueChange={([value]) => onChange({ ...options, timeout: value })}
        min={minTimeout}
        max={maxTimeout}
        step={10}
        disabled={disabled}
      />
    </div>
  );
}

// Tool config mapping
const toolConfigs: Record<ToolId, React.ComponentType<ToolConfigProps<any>> | null> = {
  nmap: NmapConfig,
  nikto: NiktoConfig,
  whatweb: WhatwebConfig,
  dirsearch: DirsearchConfig,
  gobuster: GobusterConfig,
  subfinder: SimpleTimeoutConfig,
  amass: SimpleTimeoutConfig,
  dnsenum: SimpleTimeoutConfig,
  httpx: SimpleTimeoutConfig,
  theharvester: SimpleTimeoutConfig,
};

const toolNames: Record<ToolId, string> = {
  nmap: "Nmap",
  nikto: "Nikto",
  whatweb: "WhatWeb",
  dirsearch: "DirSearch",
  gobuster: "Gobuster",
  subfinder: "Subfinder",
  amass: "Amass",
  dnsenum: "DNSenum",
  httpx: "HTTPX",
  theharvester: "TheHarvester",
};

export function ToolOptionsPanel({
  selectedTools,
  options,
  onOptionsChange,
  disabled = false,
}: ToolOptionsPanelProps) {
  const [openTools, setOpenTools] = useState<Set<ToolId>>(new Set());

  const toggleTool = (toolId: ToolId) => {
    setOpenTools((prev) => {
      const next = new Set(prev);
      if (next.has(toolId)) {
        next.delete(toolId);
      } else {
        next.add(toolId);
      }
      return next;
    });
  };

  if (selectedTools.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Settings2 className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p>Select tools above to configure their options</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 mb-4">
        <Settings2 className="w-4 h-4 text-muted-foreground" />
        <span className="text-sm font-medium">Tool Configuration</span>
        <Badge variant="outline" className="ml-auto">
          {selectedTools.length} tools
        </Badge>
      </div>

      {selectedTools.map((toolId) => {
        const ConfigComponent = toolConfigs[toolId];
        const isOpen = openTools.has(toolId);

        return (
          <Collapsible key={toolId} open={isOpen} onOpenChange={() => toggleTool(toolId)}>
            <CollapsibleTrigger asChild>
              <button
                className={cn(
                  "flex items-center justify-between w-full p-3 rounded-lg text-left",
                  "bg-muted/50 hover:bg-muted transition-colors",
                  "border border-transparent hover:border-border",
                  disabled && "opacity-50 cursor-not-allowed"
                )}
                disabled={disabled}
              >
                <span className="font-medium text-sm">{toolNames[toolId]}</span>
                {isOpen ? (
                  <ChevronDown className="w-4 h-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                )}
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="p-4 border border-t-0 border-border rounded-b-lg bg-background/50">
                {ConfigComponent && (
                  <ConfigComponent
                    options={(options[toolId] || {}) as any}
                    onChange={(newOptions) => onOptionsChange(toolId, newOptions)}
                    disabled={disabled}
                  />
                )}
              </div>
            </CollapsibleContent>
          </Collapsible>
        );
      })}
    </div>
  );
}

export default ToolOptionsPanel;
