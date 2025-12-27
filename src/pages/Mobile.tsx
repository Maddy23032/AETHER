import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Upload,
  Smartphone,
  ShieldCheck,
  ShieldAlert,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Download,
  RefreshCw,
  Loader2,
  Server,
  AlertCircle,
  Clock,
  Shield,
  Bug,
  Link,
  Mail,
  Globe,
  Eye,
  Trash2,
  ExternalLink,
} from "lucide-react";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { useMobileScanContext } from "@/contexts/ScanContext";
import { saveMobileScan } from "@/services/supabaseService";
import {
  checkHealth,
  uploadFile,
  runScan,
  runFullAnalysis,
  getReport,
  getScorecard,
  getScrapedData,
  getScanHistory,
  deleteScan,
  refreshApiKey,
  getPdfUrl,
  getSecurityGrade,
  getGradeColor,
  getSeverityVariant,
  ingestMobileScanToRAG,
  type FullAnalysisResponse,
  type ScrapedData,
  type ScanHistoryItem,
} from "@/services/mobileService";

export default function Mobile() {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Use context for persistent state
  const {
    isAnalyzing,
    analysisProgress,
    progressMessage,
    report,
    scanHistory,
    selectedTab,
    error,
    filename,
    setIsAnalyzing,
    setAnalysisProgress,
    setProgressMessage,
    setReport,
    setScanHistory,
    setSelectedTab,
    setError,
    setFilename,
    resetScan,
  } = useMobileScanContext();

  // Local state (UI only, doesn't need persistence)
  const [isApiHealthy, setIsApiHealthy] = useState<boolean | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Check API health on mount
  useEffect(() => {
    const checkApiHealthStatus = async () => {
      try {
        const health = await checkHealth();
        setIsApiHealthy(health.mobsf_connected);
      } catch {
        setIsApiHealthy(false);
      }
    };
    checkApiHealthStatus();
    
    // Only load scan history if not already loaded
    if (scanHistory.length === 0) {
      loadScanHistoryFromApi();
    }
  }, []);

  // Load scan history from MobSF
  const loadScanHistoryFromApi = useCallback(async () => {
    try {
      const result = await getScanHistory(1, 20);
      setScanHistory(result.content || []);
    } catch (e) {
      console.error("Failed to load scan history:", e);
    }
  }, [setScanHistory]);

  // Simulate progress updates during analysis
  const simulateProgress = () => {
    const steps = [
      { progress: 10, message: "Uploading file to MobSF..." },
      { progress: 25, message: "Starting static analysis..." },
      { progress: 45, message: "Analyzing application..." },
      { progress: 60, message: "Fetching JSON report..." },
      { progress: 75, message: "Fetching scorecard..." },
      { progress: 85, message: "Scraping additional data..." },
      { progress: 95, message: "Generating PDF report..." },
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < steps.length) {
        setAnalysisProgress(steps[i].progress);
        setProgressMessage(steps[i].message);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 2000);

    return () => clearInterval(interval);
  };

  // Handle file selection - run full analysis pipeline
  const handleFileSelect = async (file: File) => {
    if (!file) return;

    const validExtensions = [".apk", ".ipa", ".xapk", ".aab", ".zip"];
    const ext = file.name.toLowerCase().slice(file.name.lastIndexOf("."));
    if (!validExtensions.includes(ext)) {
      toast({
        title: "Invalid File",
        description: "Please upload an APK, IPA, or ZIP file.",
        variant: "destructive",
      });
      return;
    }

    setError(null);
    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setProgressMessage("Preparing upload...");
    setReport(null);
    setFilename(file.name);
    setSelectedTab("progress");

    const cleanup = simulateProgress();

    try {
      // Run full analysis pipeline
      const result = await runFullAnalysis(file);
      
      setAnalysisProgress(100);
      setProgressMessage("Analysis complete!");
      setReport(result);
      setSelectedTab("results");
      
      // Ingest scan results into RAG for AI analysis
      try {
        await ingestMobileScanToRAG(result.file_hash, file.name, result);
      } catch (ragError) {
        console.warn("Failed to ingest mobile scan to RAG:", ragError);
        // Don't show error to user - RAG ingestion is non-critical
      }
      
      // Save to Supabase for persistence
      try {
        await saveMobileScan({
          file_hash: result.file_hash,
          filename: file.name,
          package_name: result.json_report?.package_name || null,
          app_name: result.json_report?.app_name || null,
          version: result.json_report?.version_name || null,
          platform: result.json_report?.app_type?.toLowerCase() === 'ios' ? 'ios' : 'android',
          security_score: result.scorecard?.security_score || null,
          grade: result.scorecard?.grade || null,
          scan_type: 'static',
          json_report: result.json_report || null,
          scorecard: result.scorecard || null,
          permissions: result.json_report?.permissions ? { list: result.json_report.permissions } : null,
          security_issues: result.scorecard?.security_issues || null,
        });
        console.log("Mobile scan saved to Supabase");
      } catch (dbError) {
        console.warn("Failed to save mobile scan to Supabase:", dbError);
        // Don't show error to user - Supabase save is non-critical
      }
      
      toast({
        title: "Analysis Complete",
        description: `${file.name} has been analyzed successfully.`,
      });

      loadScanHistoryFromApi();
    } catch (e: unknown) {
      const errorMsg = e instanceof Error ? e.message : "Analysis failed";
      setError(errorMsg);
      toast({
        title: "Error",
        description: errorMsg,
        variant: "destructive",
      });
    } finally {
      cleanup();
      setIsAnalyzing(false);
    }
  };

  // Drag and drop handlers
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFileSelect(file);
  };

  // View a historical scan
  const viewHistoricalScan = async (hash: string, filename: string) => {
    setIsAnalyzing(true);
    setProgressMessage("Loading report...");
    setSelectedTab("progress");

    try {
      const [jsonReport, scorecard, scrapedData] = await Promise.all([
        getReport(hash).catch(() => null),
        getScorecard(hash).catch(() => null),
        getScrapedData(hash).catch(() => null),
      ]);

      setReport({
        success: true,
        file_hash: hash,
        filename: filename,
        scan_completed_at: new Date().toISOString(),
        json_report: jsonReport,
        scorecard: scorecard,
        scan_logs: null,
        scraped_data: scrapedData,
        pdf_available: true,
        pdf_path: null,
      });
      setSelectedTab("results");
    } catch (e: unknown) {
      const errorMsg = e instanceof Error ? e.message : "Failed to load report";
      toast({ title: "Error", description: errorMsg, variant: "destructive" });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Delete a scan
  const handleDeleteScan = async (hash: string) => {
    try {
      await deleteScan(hash);
      setScanHistory(scanHistory.filter((s) => s.HASH !== hash));
      if (report?.file_hash === hash) {
        setReport(null);
        setSelectedTab("upload");
      }
      toast({ title: "Scan Deleted" });
    } catch (e: unknown) {
      const errorMsg = e instanceof Error ? e.message : "Failed to delete";
      toast({ title: "Error", description: errorMsg, variant: "destructive" });
    }
  };

  // Refresh API key
  const handleRefreshKey = async () => {
    try {
      const result = await refreshApiKey();
      if (result.success) {
        toast({ title: "API Key Refreshed", description: result.message });
        setIsApiHealthy(true);
      }
    } catch {
      toast({ title: "Failed to refresh API key", variant: "destructive" });
    }
  };

  // Get security score from report
  const getSecurityScore = (): number | null => {
    if (!report?.scorecard) return null;
    const sc = report.scorecard as Record<string, unknown>;
    return (sc.security_score as number) || null;
  };

  // Get app info from JSON report
  const getAppInfo = () => {
    if (!report?.json_report) return null;
    const jr = report.json_report as Record<string, unknown>;
    return {
      app_name: jr.app_name as string,
      package_name: jr.package_name as string,
      version: jr.version_name as string,
      min_sdk: jr.min_sdk as string,
      target_sdk: jr.target_sdk as string,
      size: jr.size as string,
    };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Smartphone className="w-6 h-6 text-primary" />
            Mobile Security
          </h1>
          <p className="text-muted-foreground">
            Static analysis for Android and iOS applications
          </p>
        </div>

        {/* API Status */}
        <div className="flex items-center gap-4">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefreshKey}
            className="gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh Key
          </Button>
          
          {isApiHealthy === null ? (
            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
          ) : isApiHealthy ? (
            <div className="flex items-center gap-2 text-sm text-green-500">
              <Server className="w-4 h-4" />
              <span>MobSF Connected</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm text-red-500">
              <AlertCircle className="w-4 h-4" />
              <span>MobSF Offline</span>
            </div>
          )}
        </div>
      </div>

      {/* API Error Banner */}
      {isApiHealthy === false && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-destructive/10 border border-destructive/30 rounded-lg p-4"
        >
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-destructive mt-0.5" />
            <div>
              <h3 className="font-semibold text-destructive">
                MobSF Not Connected
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                Start MobSF Docker container and the backend:
              </p>
              <code className="text-xs bg-muted px-2 py-1 rounded mt-2 block">
                docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
              </code>
              <code className="text-xs bg-muted px-2 py-1 rounded mt-1 block">
                cd backend(mobile) && python run.py
              </code>
            </div>
          </div>
        </motion.div>
      )}

      {/* Main Content */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-4 lg:w-[500px]">
          <TabsTrigger value="upload" className="gap-2">
            <Upload className="w-4 h-4" />
            Upload
          </TabsTrigger>
          <TabsTrigger value="progress" disabled={!isAnalyzing && !report} className="gap-2">
            <Loader2 className="w-4 h-4" />
            Progress
          </TabsTrigger>
          <TabsTrigger value="results" disabled={!report} className="gap-2">
            <ShieldCheck className="w-4 h-4" />
            Results
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-2">
            <Clock className="w-4 h-4" />
            History
          </TabsTrigger>
        </TabsList>

        {/* Upload Tab */}
        <TabsContent value="upload" className="mt-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="max-w-2xl mx-auto"
          >
            <GlassCard
              className={`relative border-2 border-dashed transition-all cursor-pointer ${
                isDragging
                  ? "border-primary bg-primary/5 scale-[1.02]"
                  : isAnalyzing
                  ? "border-primary/50 bg-primary/5"
                  : "border-border hover:border-primary/50"
              }`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => !isAnalyzing && fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk,.ipa,.xapk,.aab,.zip"
                onChange={handleFileInputChange}
                className="hidden"
              />

              <div className="flex flex-col items-center justify-center py-16 text-center">
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
                    <h3 className="text-lg font-semibold mb-2">Analyzing...</h3>
                    <p className="text-muted-foreground text-sm">
                      Please wait while we analyze your file
                    </p>
                  </>
                ) : (
                  <>
                    <motion.div
                      animate={{ y: isDragging ? -10 : 0 }}
                      className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-4"
                    >
                      <Upload className="w-8 h-8 text-primary" />
                    </motion.div>
                    <h3 className="text-lg font-semibold mb-2">
                      Drop APK/IPA file for analysis
                    </h3>
                    <p className="text-muted-foreground text-sm mb-4">
                      or click to browse files
                    </p>
                    <div className="flex gap-2 text-xs text-muted-foreground">
                      <span className="px-2 py-1 rounded bg-muted">.apk</span>
                      <span className="px-2 py-1 rounded bg-muted">.ipa</span>
                      <span className="px-2 py-1 rounded bg-muted">.zip</span>
                    </div>
                  </>
                )}
              </div>
            </GlassCard>

            {error && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="mt-4 p-4 bg-destructive/10 border border-destructive/30 rounded-lg"
              >
                <div className="flex items-center gap-2 text-destructive">
                  <XCircle className="w-5 h-5" />
                  <span>{error}</span>
                </div>
              </motion.div>
            )}
          </motion.div>
        </TabsContent>

        {/* Progress Tab */}
        <TabsContent value="progress" className="mt-6">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="max-w-2xl mx-auto"
          >
            <GlassCard>
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">Analysis Progress</h3>
                  <span className="text-2xl font-bold text-primary">
                    {analysisProgress}%
                  </span>
                </div>

                <Progress value={analysisProgress} className="h-3" />

                <p className="text-muted-foreground text-center">
                  {progressMessage}
                </p>

                <div className="grid grid-cols-4 gap-4 pt-4">
                  {[
                    { label: "Upload", threshold: 10 },
                    { label: "Scan", threshold: 40 },
                    { label: "Reports", threshold: 70 },
                    { label: "Complete", threshold: 100 },
                  ].map((step) => (
                    <div
                      key={step.label}
                      className={`flex flex-col items-center gap-2 ${
                        analysisProgress >= step.threshold
                          ? "text-primary"
                          : "text-muted-foreground"
                      }`}
                    >
                      <div
                        className={`w-10 h-10 rounded-full flex items-center justify-center ${
                          analysisProgress >= step.threshold
                            ? "bg-primary/20"
                            : "bg-muted"
                        }`}
                      >
                        {analysisProgress >= step.threshold ? (
                          <CheckCircle className="w-5 h-5" />
                        ) : (
                          <div className="w-3 h-3 rounded-full bg-muted-foreground/50" />
                        )}
                      </div>
                      <span className="text-xs font-medium">{step.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </GlassCard>
          </motion.div>
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="mt-6">
          {report && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="space-y-6"
            >
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* Security Score */}
                <GlassCard className="text-center">
                  <div className="flex flex-col items-center">
                    <Shield className="w-8 h-8 text-primary mb-2" />
                    <span className="text-sm text-muted-foreground">Security Grade</span>
                    <span className={`text-4xl font-bold ${getGradeColor(getSecurityScore())}`}>
                      {getSecurityGrade(getSecurityScore())}
                    </span>
                  </div>
                </GlassCard>

                {/* File Info */}
                <GlassCard>
                  <div className="flex flex-col">
                    <FileText className="w-6 h-6 text-primary mb-2" />
                    <span className="text-sm text-muted-foreground">File</span>
                    <span className="font-semibold truncate">{report.filename}</span>
                    <span className="text-xs text-muted-foreground font-mono">
                      {report.file_hash.substring(0, 16)}...
                    </span>
                  </div>
                </GlassCard>

                {/* App Info */}
                <GlassCard>
                  <div className="flex flex-col">
                    <Smartphone className="w-6 h-6 text-primary mb-2" />
                    <span className="text-sm text-muted-foreground">App</span>
                    <span className="font-semibold truncate">
                      {getAppInfo()?.app_name || "N/A"}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {getAppInfo()?.package_name || ""}
                    </span>
                  </div>
                </GlassCard>

                {/* Actions */}
                <GlassCard>
                  <div className="flex flex-col gap-2">
                    <span className="text-sm text-muted-foreground mb-1">Actions</span>
                    {report.pdf_available && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-2"
                        onClick={() => window.open(getPdfUrl(report.file_hash), "_blank")}
                      >
                        <Download className="w-4 h-4" />
                        Download PDF
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-2"
                      onClick={() => {
                        setReport(null);
                        setSelectedTab("upload");
                      }}
                    >
                      <Upload className="w-4 h-4" />
                      New Scan
                    </Button>
                  </div>
                </GlassCard>
              </div>

              {/* Scraped Data Section */}
              {report.scraped_data && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Malware Lookups */}
                  {Object.keys(report.scraped_data.malware_lookup).length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Bug className="w-5 h-5 text-primary" />
                        Malware Lookups
                      </h3>
                      <div className="space-y-2">
                        {Object.entries(report.scraped_data.malware_lookup).map(([name, url]) => (
                          <a
                            key={name}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 text-sm hover:text-primary transition-colors"
                          >
                            <ExternalLink className="w-4 h-4" />
                            <span className="capitalize">{name.replace("_", " ")}</span>
                          </a>
                        ))}
                      </div>
                    </GlassCard>
                  )}

                  {/* URLs Found */}
                  {report.scraped_data.urls.length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Link className="w-5 h-5 text-primary" />
                        URLs Found ({report.scraped_data.urls.length})
                      </h3>
                      <ScrollArea className="h-48">
                        <div className="space-y-1">
                          {report.scraped_data.urls.slice(0, 20).map((item, i) => (
                            <div key={i} className="text-xs font-mono text-muted-foreground truncate">
                              {Object.values(item)[0] || JSON.stringify(item)}
                            </div>
                          ))}
                          {report.scraped_data.urls.length > 20 && (
                            <div className="text-xs text-muted-foreground">
                              ... and {report.scraped_data.urls.length - 20} more
                            </div>
                          )}
                        </div>
                      </ScrollArea>
                    </GlassCard>
                  )}

                  {/* Emails Found */}
                  {report.scraped_data.emails.length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Mail className="w-5 h-5 text-primary" />
                        Emails Found ({report.scraped_data.emails.length})
                      </h3>
                      <ScrollArea className="h-48">
                        <div className="space-y-1">
                          {report.scraped_data.emails.map((item, i) => (
                            <div key={i} className="text-sm text-muted-foreground">
                              {Object.values(item)[0] || JSON.stringify(item)}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </GlassCard>
                  )}

                  {/* Behaviour Analysis */}
                  {report.scraped_data.behaviour_analysis.length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-primary" />
                        Behaviour Analysis
                      </h3>
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {report.scraped_data.behaviour_analysis.map((item, i) => (
                            <div key={i} className="text-sm p-2 bg-muted/50 rounded">
                              {Object.entries(item).map(([k, v]) => (
                                <div key={k}>
                                  <span className="text-muted-foreground capitalize">{k}: </span>
                                  <span>{v}</span>
                                </div>
                              ))}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </GlassCard>
                  )}

                  {/* APKiD Analysis */}
                  {report.scraped_data.apkid_analysis.length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-primary" />
                        APKiD Analysis
                      </h3>
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {report.scraped_data.apkid_analysis.map((item, i) => (
                            <div key={i} className="text-sm p-2 bg-muted/50 rounded">
                              {Object.entries(item).map(([k, v]) => (
                                <div key={k}>
                                  <span className="text-muted-foreground capitalize">{k}: </span>
                                  <span>{v}</span>
                                </div>
                              ))}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </GlassCard>
                  )}

                  {/* Domain Malware Check */}
                  {report.scraped_data.domain_malware_check.length > 0 && (
                    <GlassCard>
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                        <Globe className="w-5 h-5 text-primary" />
                        Domain Malware Check
                      </h3>
                      <ScrollArea className="h-48">
                        <div className="space-y-2">
                          {report.scraped_data.domain_malware_check.map((item, i) => (
                            <div key={i} className="text-sm p-2 bg-muted/50 rounded">
                              {Object.entries(item).map(([k, v]) => (
                                <div key={k}>
                                  <span className="text-muted-foreground capitalize">{k}: </span>
                                  <span>{v}</span>
                                </div>
                              ))}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </GlassCard>
                  )}
                </div>
              )}

              {/* Raw JSON Report Preview */}
              {report.json_report && (
                <GlassCard>
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <FileText className="w-5 h-5 text-primary" />
                    Full JSON Report
                  </h3>
                  <ScrollArea className="h-64">
                    <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                      {JSON.stringify(report.json_report, null, 2).substring(0, 5000)}
                      {JSON.stringify(report.json_report).length > 5000 && "\n... (truncated)"}
                    </pre>
                  </ScrollArea>
                </GlassCard>
              )}
            </motion.div>
          )}
        </TabsContent>

        {/* History Tab */}
        <TabsContent value="history" className="mt-6">
          <GlassCard>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Scan History</h3>
              <Button variant="outline" size="sm" onClick={loadScanHistoryFromApi}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>

            {scanHistory.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No scan history available</p>
              </div>
            ) : (
              <div className="space-y-2">
                {scanHistory.map((scan, index) => {
                  const hash = scan.HASH || scan.MD5 || scan.hash || "";
                  const fileName = scan.FILE_NAME || scan.APP_NAME || scan.file_name || "Unknown";
                  const timestamp = scan.TIMESTAMP || scan.timestamp || "";
                  
                  if (!hash) return null;
                  
                  return (
                    <div
                      key={hash || index}
                      className="flex items-center justify-between p-3 bg-muted/50 rounded-lg hover:bg-muted transition-colors"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="font-medium truncate">{fileName}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {hash.substring(0, 16)}...
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {timestamp}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => viewHistoricalScan(hash, fileName)}
                        >
                          <Eye className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          onClick={() => handleDeleteScan(hash)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </GlassCard>
        </TabsContent>
      </Tabs>
    </div>
  );
}
