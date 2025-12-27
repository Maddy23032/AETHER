import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  ShieldCheck,
  Activity,
  TrendingUp,
  Search,
  Smartphone,
  Globe,
  Target,
  Clock,
  RefreshCw,
  Loader2,
  Radar,
  FileSearch,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import {
  getDashboardStats,
  getScanTrendData,
  getSeverityDistribution,
  getScanTypeDistribution,
  getRecentActivity,
  getTopVulnerabilities,
  getTargetSummaries,
  getMobileAppSummaries,
  type DashboardStats,
  type ScanTrendData,
  type SeverityDistribution,
  type ScanTypeDistribution,
  type RecentActivity,
  type TopVulnerability,
  type TargetSummary,
  type MobileAppSummary,
} from "@/services/dashboardService";

// Animation variants
const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 },
  },
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0 },
};

// Severity color mapping
const severityColors: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-400",
  info: "text-gray-400",
};

const severityBgColors: Record<string, string> = {
  critical: "bg-red-500/10 border-red-500/30",
  high: "bg-orange-500/10 border-orange-500/30",
  medium: "bg-yellow-500/10 border-yellow-500/30",
  low: "bg-blue-400/10 border-blue-400/30",
  info: "bg-gray-400/10 border-gray-400/30",
};

const gradeColors: Record<string, string> = {
  A: "text-green-400",
  B: "text-green-500",
  C: "text-yellow-500",
  D: "text-orange-500",
  F: "text-red-500",
};

export default function Dashboard() {
  const navigate = useNavigate();
  
  // State
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [trendData, setTrendData] = useState<ScanTrendData[]>([]);
  const [severityDist, setSeverityDist] = useState<SeverityDistribution[]>([]);
  const [scanTypeDist, setScanTypeDist] = useState<ScanTypeDistribution[]>([]);
  const [recentActivity, setRecentActivity] = useState<RecentActivity[]>([]);
  const [topVulns, setTopVulns] = useState<TopVulnerability[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [mobileApps, setMobileApps] = useState<MobileAppSummary[]>([]);

  // Load all dashboard data
  const loadDashboardData = async (showRefreshing = false) => {
    if (showRefreshing) setIsRefreshing(true);
    
    try {
      const [
        statsData,
        trendDataResult,
        severityData,
        scanTypeData,
        activityData,
        vulnsData,
        targetsData,
        mobileData,
      ] = await Promise.all([
        getDashboardStats(),
        getScanTrendData(14), // Last 14 days
        getSeverityDistribution(),
        getScanTypeDistribution(),
        getRecentActivity(8),
        getTopVulnerabilities(5),
        getTargetSummaries(5),
        getMobileAppSummaries(5),
      ]);

      setStats(statsData);
      setTrendData(trendDataResult);
      setSeverityDist(severityData);
      setScanTypeDist(scanTypeData);
      setRecentActivity(activityData);
      setTopVulns(vulnsData);
      setTargets(targetsData);
      setMobileApps(mobileData);
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Calculate security score from vulnerability data
  const calculateSecurityScore = () => {
    if (!stats) return 0;
    const totalVulns = stats.totalVulnerabilities;
    if (totalVulns === 0) return 100;
    
    // Weighted score based on severity
    const weightedScore = 
      (stats.criticalVulns * 40) + 
      (stats.highVulns * 25) + 
      (stats.mediumVulns * 10) + 
      (stats.lowVulns * 3) + 
      (stats.infoVulns * 1);
    
    const maxPossibleScore = totalVulns * 40; // If all were critical
    const score = Math.max(0, Math.round(100 - (weightedScore / maxPossibleScore * 100)));
    return score;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-center space-y-4">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
          <p className="text-muted-foreground">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const securityScore = calculateSecurityScore();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time overview of your security posture
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => loadDashboardData(true)}
            disabled={isRefreshing}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isRefreshing ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button onClick={() => navigate("/recon")} className="gap-2">
            <Search className="w-4 h-4" />
            New Scan
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        {/* Total Scans */}
        <motion.div variants={item}>
          <GlassCard className="relative overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Total Scans</p>
                <p className="text-3xl font-bold">{stats?.totalScans || 0}</p>
                <div className="flex items-center gap-2 text-xs">
                  <Badge variant="outline" className="text-xs">
                    <Radar className="w-3 h-3 mr-1" />
                    {stats?.reconScans || 0} Recon
                  </Badge>
                  <Badge variant="outline" className="text-xs">
                    <FileSearch className="w-3 h-3 mr-1" />
                    {stats?.enumScans || 0} Enum
                  </Badge>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-primary/10">
                <Activity className="w-5 h-5 text-primary" />
              </div>
            </div>
          </GlassCard>
        </motion.div>

        {/* Critical Vulnerabilities */}
        <motion.div variants={item}>
          <GlassCard className="relative overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Critical Vulns</p>
                <p className="text-3xl font-bold text-destructive">
                  {stats?.criticalVulns || 0}
                </p>
                <div className="flex items-center gap-1 text-xs">
                  <span className="text-orange-500">{stats?.highVulns || 0} High</span>
                  <span className="text-muted-foreground">•</span>
                  <span className="text-yellow-500">{stats?.mediumVulns || 0} Medium</span>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-destructive/10">
                <AlertTriangle className="w-5 h-5 text-destructive" />
              </div>
            </div>
          </GlassCard>
        </motion.div>

        {/* Security Score */}
        <motion.div variants={item}>
          <GlassCard className="relative overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Security Score</p>
                <p className={`text-3xl font-bold ${
                  securityScore >= 80 ? "text-green-500" :
                  securityScore >= 60 ? "text-yellow-500" :
                  securityScore >= 40 ? "text-orange-500" : "text-red-500"
                }`}>
                  {securityScore}/100
                </p>
                <Progress 
                  value={securityScore} 
                  className="h-1.5"
                />
              </div>
              <div className={`p-3 rounded-lg ${
                securityScore >= 80 ? "bg-green-500/10" :
                securityScore >= 60 ? "bg-yellow-500/10" :
                securityScore >= 40 ? "bg-orange-500/10" : "bg-red-500/10"
              }`}>
                <ShieldCheck className={`w-5 h-5 ${
                  securityScore >= 80 ? "text-green-500" :
                  securityScore >= 60 ? "text-yellow-500" :
                  securityScore >= 40 ? "text-orange-500" : "text-red-500"
                }`} />
              </div>
            </div>
          </GlassCard>
        </motion.div>

        {/* Mobile Apps */}
        <motion.div variants={item}>
          <GlassCard className="relative overflow-hidden">
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Mobile Scans</p>
                <p className="text-3xl font-bold">{stats?.mobileScans || 0}</p>
                <div className="flex items-center gap-1 text-xs">
                  {stats?.averageSecurityScore ? (
                    <>
                      <span className="text-muted-foreground">Avg Score:</span>
                      <span className={
                        stats.averageSecurityScore >= 80 ? "text-green-500" :
                        stats.averageSecurityScore >= 60 ? "text-yellow-500" : "text-orange-500"
                      }>
                        {stats.averageSecurityScore}/100
                      </span>
                    </>
                  ) : (
                    <span className="text-muted-foreground">No scans yet</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-purple-500/10">
                <Smartphone className="w-5 h-5 text-purple-500" />
              </div>
            </div>
          </GlassCard>
        </motion.div>
      </motion.div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <GlassCard className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Scan Activity (14 Days)</h3>
            <Badge variant="outline">
              <TrendingUp className="w-3 h-3 mr-1" />
              {trendData.reduce((sum, d) => sum + d.scans, 0)} total scans
            </Badge>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(239, 84%, 67%)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="hsl(239, 84%, 67%)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="vulnGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="date"
                  stroke="hsl(240, 5%, 45%)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  stroke="hsl(240, 5%, 45%)"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(240, 6%, 10%)",
                    border: "1px solid hsl(240, 5%, 18%)",
                    borderRadius: "8px",
                    color: "hsl(0, 0%, 98%)",
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="scans"
                  name="Scans"
                  stroke="hsl(239, 84%, 67%)"
                  strokeWidth={2}
                  fill="url(#scanGradient)"
                />
                <Area
                  type="monotone"
                  dataKey="vulnerabilities"
                  name="Vulnerabilities"
                  stroke="hsl(0, 84%, 60%)"
                  strokeWidth={2}
                  fill="url(#vulnGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        {/* Distribution Charts */}
        <GlassCard>
          <Tabs defaultValue="severity" className="w-full">
            <TabsList className="grid w-full grid-cols-2 mb-4">
              <TabsTrigger value="severity">Severity</TabsTrigger>
              <TabsTrigger value="scanType">Scan Types</TabsTrigger>
            </TabsList>
            
            <TabsContent value="severity" className="mt-0">
              <div className="h-44">
                {severityDist.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityDist}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={65}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {severityDist.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "hsl(240, 6%, 10%)",
                          border: "1px solid hsl(240, 5%, 18%)",
                          borderRadius: "8px",
                          color: "hsl(0, 0%, 98%)",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    No vulnerability data
                  </div>
                )}
              </div>
              <div className="space-y-1.5 mt-2">
                {severityDist.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-muted-foreground">{item.name}</span>
                    </div>
                    <span className="font-medium">{item.value}</span>
                  </div>
                ))}
              </div>
            </TabsContent>
            
            <TabsContent value="scanType" className="mt-0">
              <div className="h-44">
                {scanTypeDist.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={scanTypeDist}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={65}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {scanTypeDist.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "hsl(240, 6%, 10%)",
                          border: "1px solid hsl(240, 5%, 18%)",
                          borderRadius: "8px",
                          color: "hsl(0, 0%, 98%)",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    No scan data
                  </div>
                )}
              </div>
              <div className="space-y-1.5 mt-2">
                {scanTypeDist.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-muted-foreground">{item.name}</span>
                    </div>
                    <span className="font-medium">{item.value}</span>
                  </div>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </GlassCard>
      </div>

      {/* Bottom Row - Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <GlassCard className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Recent Activity</h3>
            <Clock className="w-4 h-4 text-muted-foreground" />
          </div>
          <ScrollArea className="h-[320px] pr-4">
            <div className="space-y-3">
              {recentActivity.length > 0 ? (
                recentActivity.map((activity) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="flex items-start gap-3 p-2.5 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                  >
                    <StatusBadge
                      variant={
                        activity.type === "critical" ? "critical" :
                        activity.type === "warning" ? "warning" :
                        activity.type === "success" ? "safe" : "info"
                      }
                      dot
                      className="mt-0.5"
                    >
                      {activity.type}
                    </StatusBadge>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm truncate">{activity.event}</p>
                      <p className="text-xs text-muted-foreground">{activity.time}</p>
                    </div>
                  </motion.div>
                ))
              ) : (
                <p className="text-muted-foreground text-center py-8">No recent activity</p>
              )}
            </div>
          </ScrollArea>
        </GlassCard>

        {/* Top Vulnerabilities */}
        <GlassCard className="lg:col-span-1">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Top Vulnerabilities</h3>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={() => navigate("/malware")}
              className="text-xs"
            >
              View All
              <ChevronRight className="w-3 h-3 ml-1" />
            </Button>
          </div>
          <ScrollArea className="h-[320px] pr-4">
            <div className="space-y-3">
              {topVulns.length > 0 ? (
                topVulns.map((vuln) => (
                  <div
                    key={vuln.id}
                    className={`p-3 rounded-lg border ${severityBgColors[vuln.severity] || "bg-muted/30"}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{vuln.name}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge 
                            variant="outline" 
                            className={`text-xs ${severityColors[vuln.severity]}`}
                          >
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          {vuln.owaspCategory && (
                            <span className="text-xs text-muted-foreground truncate">
                              {vuln.owaspCategory}
                            </span>
                          )}
                        </div>
                      </div>
                      <Badge variant="secondary" className="shrink-0">
                        ×{vuln.count}
                      </Badge>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-muted-foreground text-center py-8">No vulnerabilities found</p>
              )}
            </div>
          </ScrollArea>
        </GlassCard>

        {/* Targets & Mobile Apps */}
        <GlassCard className="lg:col-span-1">
          <Tabs defaultValue="targets" className="w-full">
            <TabsList className="grid w-full grid-cols-2 mb-4">
              <TabsTrigger value="targets">
                <Globe className="w-3 h-3 mr-1" />
                Targets
              </TabsTrigger>
              <TabsTrigger value="mobile">
                <Smartphone className="w-3 h-3 mr-1" />
                Mobile
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="targets" className="mt-0">
              <ScrollArea className="h-[300px] pr-4">
                <div className="space-y-3">
                  {targets.length > 0 ? (
                    targets.map((target) => (
                      <div
                        key={target.target}
                        className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 min-w-0">
                            <Target className="w-4 h-4 text-primary shrink-0" />
                            <span className="text-sm font-medium truncate">{target.target}</span>
                          </div>
                          <Badge 
                            variant="outline" 
                            className={`shrink-0 ${severityColors[target.worstSeverity]}`}
                          >
                            {target.vulnCount} vulns
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                          <span>{target.scanCount} scans</span>
                          <span>•</span>
                          <span>Last: {new Date(target.lastScanned).toLocaleDateString()}</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground text-center py-8">No targets scanned</p>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>
            
            <TabsContent value="mobile" className="mt-0">
              <ScrollArea className="h-[300px] pr-4">
                <div className="space-y-3">
                  {mobileApps.length > 0 ? (
                    mobileApps.map((app) => (
                      <div
                        key={app.id}
                        className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
                        onClick={() => navigate("/mobile")}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 min-w-0">
                            <Smartphone className="w-4 h-4 text-purple-500 shrink-0" />
                            <span className="text-sm font-medium truncate">
                              {app.appName || app.filename}
                            </span>
                          </div>
                          {app.grade && (
                            <span className={`text-lg font-bold ${gradeColors[app.grade] || "text-gray-400"}`}>
                              {app.grade}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                          <Badge variant="outline" className="text-xs">
                            {app.platform === "ios" ? "iOS" : "Android"}
                          </Badge>
                          {app.securityScore !== null && (
                            <span>Score: {app.securityScore}/100</span>
                          )}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-muted-foreground text-center py-8">No mobile apps scanned</p>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </GlassCard>
      </div>

      {/* Quick Actions */}
      <GlassCard>
        <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Button
            variant="outline"
            className="h-auto py-4 flex flex-col gap-2"
            onClick={() => navigate("/recon")}
          >
            <Radar className="w-5 h-5 text-primary" />
            <span>Reconnaissance</span>
          </Button>
          <Button
            variant="outline"
            className="h-auto py-4 flex flex-col gap-2"
            onClick={() => navigate("/malware")}
          >
            <AlertTriangle className="w-5 h-5 text-orange-500" />
            <span>Vuln Scanner</span>
          </Button>
          <Button
            variant="outline"
            className="h-auto py-4 flex flex-col gap-2"
            onClick={() => navigate("/mobile")}
          >
            <Smartphone className="w-5 h-5 text-purple-500" />
            <span>Mobile Analysis</span>
          </Button>
          <Button
            variant="outline"
            className="h-auto py-4 flex flex-col gap-2"
            onClick={() => navigate("/intelligence")}
          >
            <Shield className="w-5 h-5 text-green-500" />
            <span>AI Assistant</span>
          </Button>
        </div>
      </GlassCard>
    </div>
  );
}