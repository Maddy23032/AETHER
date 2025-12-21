/**
 * ScanProgress Component
 * Progress indicator and controls during scan execution
 */

import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Square, Loader2, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import type { ScanStatus } from "@/services/types/recon.types";

interface ScanProgressProps {
  status: ScanStatus;
  progress: {
    current: number;
    total: number;
    currentTool: string;
  };
  onCancel: () => void;
  findingsCount?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export function ScanProgress({
  status,
  progress,
  onCancel,
  findingsCount,
}: ScanProgressProps) {
  const percentage = progress.total > 0 
    ? Math.round((progress.current / progress.total) * 100) 
    : 0;

  const getStatusIcon = () => {
    switch (status) {
      case 'running':
        return <Loader2 className="w-5 h-5 animate-spin text-primary" />;
      case 'completed':
        return <CheckCircle2 className="w-5 h-5 text-success" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-destructive" />;
      default:
        return null;
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'running':
        return `Scanning with ${progress.currentTool}...`;
      case 'completed':
        return 'Scan completed successfully';
      case 'error':
        return 'Scan encountered errors';
      default:
        return 'Ready to scan';
    }
  };

  if (status === 'idle') {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="p-4 rounded-lg border border-border bg-card/50"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          {getStatusIcon()}
          <div>
            <p className="font-medium text-sm">{getStatusText()}</p>
            {status === 'running' && (
              <p className="text-xs text-muted-foreground">
                Tool {progress.current} of {progress.total}
              </p>
            )}
          </div>
        </div>

        {status === 'running' && (
          <Button
            variant="destructive"
            size="sm"
            onClick={onCancel}
            className="gap-2"
          >
            <Square className="w-3 h-3" />
            Cancel
          </Button>
        )}
      </div>

      {status === 'running' && (
        <div className="space-y-2">
          <Progress value={percentage} className="h-2" />
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>{percentage}% complete</span>
            <span>{progress.current}/{progress.total} tools</span>
          </div>
        </div>
      )}

      {status === 'completed' && findingsCount && (
        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-border">
          <span className="text-xs text-muted-foreground">Findings:</span>
          {findingsCount.critical > 0 && (
            <Badge variant="destructive" className="gap-1">
              <AlertTriangle className="w-3 h-3" />
              {findingsCount.critical} Critical
            </Badge>
          )}
          {findingsCount.high > 0 && (
            <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 gap-1">
              {findingsCount.high} High
            </Badge>
          )}
          {findingsCount.medium > 0 && (
            <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 gap-1">
              {findingsCount.medium} Medium
            </Badge>
          )}
          {findingsCount.low > 0 && (
            <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 gap-1">
              {findingsCount.low} Low
            </Badge>
          )}
          {findingsCount.info > 0 && (
            <Badge variant="outline" className="gap-1">
              {findingsCount.info} Info
            </Badge>
          )}
        </div>
      )}
    </motion.div>
  );
}

export default ScanProgress;
