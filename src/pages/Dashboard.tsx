import { motion } from "framer-motion";
import {
  Server,
  AlertTriangle,
  ShieldCheck,
  Activity,
  TrendingUp,
  TrendingDown,
  Plus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
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
} from "recharts";

// Mock data
const kpiData = [
  {
    title: "Total Assets",
    value: "1,240",
    trend: "+12%",
    trendUp: true,
    icon: Server,
    color: "primary",
  },
  {
    title: "Critical Vulns",
    value: "14",
    trend: "+2",
    trendUp: true,
    icon: AlertTriangle,
    color: "destructive",
  },
  {
    title: "Security Score",
    value: "78/100",
    trend: "+5",
    trendUp: true,
    icon: ShieldCheck,
    color: "warning",
  },
  {
    title: "Active Scans",
    value: "3",
    trend: "Running",
    trendUp: true,
    icon: Activity,
    color: "success",
    pulse: true,
  },
];

const trendData = [
  { day: "Day 1", vulns: 8 },
  { day: "Day 5", vulns: 12 },
  { day: "Day 10", vulns: 10 },
  { day: "Day 15", vulns: 18 },
  { day: "Day 20", vulns: 15 },
  { day: "Day 25", vulns: 14 },
  { day: "Day 30", vulns: 14 },
];

const assetDistribution = [
  { name: "Web Apps", value: 45, color: "hsl(239, 84%, 67%)" },
  { name: "Mobile", value: 25, color: "hsl(160, 84%, 39%)" },
  { name: "Network", value: 30, color: "hsl(280, 65%, 60%)" },
];

const recentActivity = [
  { id: 1, event: "Scan #402 completed", time: "2 min ago", type: "success" },
  { id: 2, event: "Critical alert on /api/v1/users", time: "15 min ago", type: "critical" },
  { id: 3, event: "New asset discovered: api.example.com", time: "1 hour ago", type: "info" },
  { id: 4, event: "Mobile scan initiated for app v2.3", time: "2 hours ago", type: "info" },
  { id: 5, event: "SQL injection patched on login endpoint", time: "4 hours ago", type: "success" },
];

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.1 },
  },
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0 },
};

export default function Dashboard() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Welcome back, Operator.</h1>
          <p className="text-muted-foreground">Here's your security overview</p>
        </div>
        <Button className="gap-2">
          <Plus className="w-4 h-4" />
          New Scan
        </Button>
      </div>

      {/* KPI Grid */}
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        {kpiData.map((kpi) => (
          <motion.div key={kpi.title} variants={item}>
            <GlassCard className="relative overflow-hidden">
              <div className="flex items-start justify-between">
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">{kpi.title}</p>
                  <p
                    className={`text-3xl font-bold ${
                      kpi.color === "destructive" ? "text-destructive" : "text-foreground"
                    }`}
                  >
                    {kpi.value}
                  </p>
                  <div className="flex items-center gap-1 text-xs">
                    {kpi.trendUp ? (
                      <TrendingUp className="w-3 h-3 text-success" />
                    ) : (
                      <TrendingDown className="w-3 h-3 text-destructive" />
                    )}
                    <span
                      className={
                        kpi.color === "destructive"
                          ? "text-destructive"
                          : "text-success"
                      }
                    >
                      {kpi.trend}
                    </span>
                  </div>
                </div>
                <div
                  className={`p-3 rounded-lg ${
                    kpi.color === "destructive"
                      ? "bg-destructive/10"
                      : kpi.color === "success"
                      ? "bg-success/10"
                      : kpi.color === "warning"
                      ? "bg-warning/10"
                      : "bg-primary/10"
                  } ${kpi.pulse ? "animate-pulse-glow" : ""}`}
                >
                  <kpi.icon
                    className={`w-5 h-5 ${
                      kpi.color === "destructive"
                        ? "text-destructive"
                        : kpi.color === "success"
                        ? "text-success"
                        : kpi.color === "warning"
                        ? "text-warning"
                        : "text-primary"
                    }`}
                  />
                </div>
              </div>
            </GlassCard>
          </motion.div>
        ))}
      </motion.div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <GlassCard className="lg:col-span-2">
          <h3 className="text-lg font-semibold mb-4">Vulnerability Trend (30 Days)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="vulnGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="hsl(239, 84%, 67%)" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="hsl(239, 84%, 67%)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="day"
                  stroke="hsl(240, 5%, 65%)"
                  fontSize={12}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  stroke="hsl(240, 5%, 65%)"
                  fontSize={12}
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
                <Area
                  type="monotone"
                  dataKey="vulns"
                  stroke="hsl(239, 84%, 67%)"
                  strokeWidth={2}
                  fill="url(#vulnGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>

        {/* Asset Distribution */}
        <GlassCard>
          <h3 className="text-lg font-semibold mb-4">Asset Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={assetDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {assetDistribution.map((entry, index) => (
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
          </div>
          <div className="space-y-2 mt-4">
            {assetDistribution.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-muted-foreground">{item.name}</span>
                </div>
                <span className="font-medium">{item.value}%</span>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      {/* Activity Feed */}
      <GlassCard>
        <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
        <div className="space-y-3">
          {recentActivity.map((activity) => (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <StatusBadge
                  variant={
                    activity.type === "critical"
                      ? "critical"
                      : activity.type === "success"
                      ? "safe"
                      : "info"
                  }
                  dot
                >
                  {activity.type}
                </StatusBadge>
                <span className="text-sm">{activity.event}</span>
              </div>
              <span className="text-xs text-muted-foreground">{activity.time}</span>
            </motion.div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}