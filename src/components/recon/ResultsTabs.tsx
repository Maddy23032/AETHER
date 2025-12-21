/**
 * ResultsTabs Component
 * Tabbed view for raw results from each tool
 */

import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { 
  CheckCircle2, 
  XCircle, 
  Copy, 
  Check,
  FileJson,
  Terminal
} from "lucide-react";
import type { ReconResponse, ToolId } from "@/services/types/recon.types";

interface ResultsTabsProps {
  results: ReconResponse[];
}

function RawOutput({ content }: { content: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!content) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No raw output available
      </div>
    );
  }

  return (
    <div className="relative">
      <Button
        variant="ghost"
        size="sm"
        className="absolute top-2 right-2 gap-2"
        onClick={handleCopy}
      >
        {copied ? (
          <>
            <Check className="w-4 h-4" />
            Copied
          </>
        ) : (
          <>
            <Copy className="w-4 h-4" />
            Copy
          </>
        )}
      </Button>
      <ScrollArea className="h-[400px]">
        <pre className="p-4 text-xs font-mono whitespace-pre-wrap break-all">
          {content}
        </pre>
      </ScrollArea>
    </div>
  );
}

function ParsedOutput({ data }: { data: unknown }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!data || (typeof data === 'object' && Object.keys(data as object).length === 0)) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No parsed data available
      </div>
    );
  }

  return (
    <div className="relative">
      <Button
        variant="ghost"
        size="sm"
        className="absolute top-2 right-2 gap-2"
        onClick={handleCopy}
      >
        {copied ? (
          <>
            <Check className="w-4 h-4" />
            Copied
          </>
        ) : (
          <>
            <Copy className="w-4 h-4" />
            Copy
          </>
        )}
      </Button>
      <ScrollArea className="h-[400px]">
        <pre className="p-4 text-xs font-mono whitespace-pre-wrap">
          {JSON.stringify(data, null, 2)}
        </pre>
      </ScrollArea>
    </div>
  );
}

export function ResultsTabs({ results }: ResultsTabsProps) {
  const [activeResult, setActiveResult] = useState<string>(results[0]?.tool || "");
  const [viewMode, setViewMode] = useState<"raw" | "parsed">("parsed");

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Terminal className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p className="text-lg font-medium">No results yet</p>
        <p className="text-sm">Tool outputs will appear here after scanning</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* View mode toggle */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Tool Outputs</h3>
        <div className="flex items-center gap-2">
          <Button
            variant={viewMode === "raw" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setViewMode("raw")}
            className="gap-2"
          >
            <Terminal className="w-4 h-4" />
            Raw
          </Button>
          <Button
            variant={viewMode === "parsed" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setViewMode("parsed")}
            className="gap-2"
          >
            <FileJson className="w-4 h-4" />
            Parsed
          </Button>
        </div>
      </div>

      <Tabs value={activeResult} onValueChange={setActiveResult}>
        <TabsList className="flex flex-wrap h-auto gap-1 bg-muted/50 p-1">
          {results.map((result) => (
            <TabsTrigger
              key={result.tool}
              value={result.tool}
              className="gap-2 data-[state=active]:bg-background"
            >
              {result.status === "success" ? (
                <CheckCircle2 className="w-3 h-3 text-success" />
              ) : (
                <XCircle className="w-3 h-3 text-destructive" />
              )}
              {result.tool}
            </TabsTrigger>
          ))}
        </TabsList>

        {results.map((result) => (
          <TabsContent key={result.tool} value={result.tool} className="mt-4">
            <div className="rounded-lg border border-border bg-card/50">
              {/* Result header */}
              <div className="flex items-center justify-between p-3 border-b border-border">
                <div className="flex items-center gap-3">
                  <Badge variant={result.status === "success" ? "default" : "destructive"}>
                    {result.status}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    Target: <code className="text-foreground">{result.target}</code>
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">
                  Completed in {result.execution_time}
                </span>
              </div>

              {/* Result content */}
              <div className="bg-background/50 rounded-b-lg">
                {result.status === "error" && result.errors && (
                  <div className="p-4 bg-destructive/10 border-b border-destructive/20">
                    <p className="text-sm text-destructive font-medium">Error</p>
                    <p className="text-sm text-destructive/80">{result.errors}</p>
                  </div>
                )}

                {viewMode === "raw" ? (
                  <RawOutput content={result.results?.raw || ""} />
                ) : (
                  <ParsedOutput data={result.results?.parsed || {}} />
                )}
              </div>
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}

export default ResultsTabs;
