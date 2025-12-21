/**
 * ToolCard Component
 * Individual tool toggle card for the tool selection grid
 */

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import type { ReconTool } from "@/services/types/recon.types";
import {
  Network,
  Globe,
  Shield,
  FolderSearch,
  Search,
  GitBranch,
  Radar,
  Database,
  Zap,
  Mail,
  LucideIcon,
} from "lucide-react";

// Icon mapping
const iconMap: Record<string, LucideIcon> = {
  Network,
  Globe,
  Shield,
  FolderSearch,
  Search,
  GitBranch,
  Radar,
  Database,
  Zap,
  Mail,
};

interface ToolCardProps {
  tool: ReconTool;
  isSelected: boolean;
  onToggle: (toolId: string) => void;
  disabled?: boolean;
}

const categoryColors: Record<string, string> = {
  'port-scan': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  'web-analysis': 'bg-green-500/20 text-green-400 border-green-500/30',
  'dns': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  'subdomain': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  'directory': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  'vuln-scan': 'bg-red-500/20 text-red-400 border-red-500/30',
  'osint': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
};

export function ToolCard({ tool, isSelected, onToggle, disabled = false }: ToolCardProps) {
  const Icon = iconMap[tool.icon] || Globe;
  
  return (
    <motion.div
      whileHover={{ scale: disabled ? 1 : 1.02 }}
      whileTap={{ scale: disabled ? 1 : 0.98 }}
      className={cn(
        "relative p-4 rounded-lg border cursor-pointer transition-all duration-200",
        "bg-card/50 backdrop-blur-sm",
        isSelected 
          ? "border-primary/50 bg-primary/5 shadow-lg shadow-primary/10" 
          : "border-border hover:border-primary/30",
        disabled && "opacity-50 cursor-not-allowed"
      )}
      onClick={() => !disabled && onToggle(tool.id)}
    >
      {/* Selection checkbox */}
      <div className="absolute top-3 right-3">
        <Checkbox 
          checked={isSelected} 
          onCheckedChange={() => !disabled && onToggle(tool.id)}
          disabled={disabled}
        />
      </div>

      {/* Icon and title */}
      <div className="flex items-start gap-3 mb-2">
        <div className={cn(
          "p-2 rounded-lg",
          isSelected ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
        )}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="font-medium text-sm truncate">{tool.name}</h4>
          <p className="text-xs text-muted-foreground line-clamp-2 mt-0.5">
            {tool.description}
          </p>
        </div>
      </div>

      {/* Category and time */}
      <div className="flex items-center justify-between mt-3">
        <Badge 
          variant="outline" 
          className={cn("text-[10px] px-1.5 py-0", categoryColors[tool.category])}
        >
          {tool.category.replace('-', ' ')}
        </Badge>
        <span className="text-[10px] text-muted-foreground">
          ~{tool.estimatedTime}
        </span>
      </div>
    </motion.div>
  );
}

export default ToolCard;
