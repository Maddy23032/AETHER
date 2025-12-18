import { useState } from "react";
import { motion } from "framer-motion";
import {
  Upload,
  Smartphone,
  ShieldCheck,
  FileText,
  AlertTriangle,
  CheckCircle,
  MapPin,
  MessageSquare,
  Camera,
  Mic,
  Phone,
  Wifi,
} from "lucide-react";
import { GlassCard } from "@/components/ui/glass-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";

const mockMetadata = {
  appName: "SecureChat Pro",
  packageId: "com.securechat.pro",
  version: "2.3.1",
  minSdk: "21 (Android 5.0)",
  targetSdk: "34 (Android 14)",
  md5: "a1b2c3d4e5f6789012345678",
};

const mockPermissions = [
  { name: "READ_SMS", icon: MessageSquare, risk: "high", description: "Read text messages" },
  { name: "ACCESS_FINE_LOCATION", icon: MapPin, risk: "high", description: "Precise location access" },
  { name: "CAMERA", icon: Camera, risk: "medium", description: "Access camera" },
  { name: "RECORD_AUDIO", icon: Mic, risk: "medium", description: "Record audio" },
  { name: "READ_PHONE_STATE", icon: Phone, risk: "low", description: "Read phone status" },
  { name: "ACCESS_WIFI_STATE", icon: Wifi, risk: "low", description: "View Wi-Fi connections" },
];

export default function Mobile() {
  const [isAnalyzed, setIsAnalyzed] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    // Simulate analysis
    setTimeout(() => setIsAnalyzed(true), 1500);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const simulateUpload = () => {
    setTimeout(() => setIsAnalyzed(true), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Mobile Security</h1>
        <p className="text-muted-foreground">Static analysis for Android and iOS applications</p>
      </div>

      {!isAnalyzed ? (
        /* Upload Zone */
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-2xl mx-auto"
        >
          <GlassCard
            className={`relative border-2 border-dashed transition-colors cursor-pointer ${
              isDragging
                ? "border-primary bg-primary/5"
                : "border-border hover:border-primary/50"
            }`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={simulateUpload}
          >
            <div className="flex flex-col items-center justify-center py-16 text-center">
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
                <span className="px-2 py-1 rounded bg-muted">.aab</span>
              </div>
            </div>
          </GlassCard>
        </motion.div>
      ) : (
        /* Analysis Results */
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="space-y-6"
        >
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Security Score */}
            <GlassCard className="flex flex-col items-center justify-center py-8">
              <div className="relative w-32 h-32 mb-4">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="hsl(var(--muted))"
                    strokeWidth="8"
                    fill="none"
                  />
                  <motion.circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="hsl(38, 92%, 50%)"
                    strokeWidth="8"
                    fill="none"
                    strokeLinecap="round"
                    initial={{ strokeDasharray: "0 352" }}
                    animate={{ strokeDasharray: "264 352" }}
                    transition={{ duration: 1, ease: "easeOut" }}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-4xl font-bold text-warning">B-</span>
                </div>
              </div>
              <h3 className="text-lg font-semibold">Security Score</h3>
              <p className="text-sm text-muted-foreground">75/100 Points</p>
            </GlassCard>

            {/* App Metadata */}
            <GlassCard className="lg:col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <Smartphone className="w-5 h-5 text-primary" />
                <h3 className="text-lg font-semibold">Application Metadata</h3>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {Object.entries(mockMetadata).map(([key, value]) => (
                  <div key={key} className="space-y-1">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider">
                      {key.replace(/([A-Z])/g, " $1").trim()}
                    </p>
                    <p className={`text-sm font-medium ${key === "md5" ? "font-mono" : ""}`}>
                      {value}
                    </p>
                  </div>
                ))}
              </div>

              <div className="mt-4 pt-4 border-t border-border flex gap-2">
                <Button variant="outline" size="sm">
                  <FileText className="w-4 h-4 mr-2" />
                  View Manifest
                </Button>
                <Button variant="outline" size="sm">
                  <ShieldCheck className="w-4 h-4 mr-2" />
                  Full Report
                </Button>
              </div>
            </GlassCard>
          </div>

          {/* Permissions Grid */}
          <GlassCard>
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-5 h-5 text-warning" />
              <h3 className="text-lg font-semibold">Permission Analysis</h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {mockPermissions.map((perm) => (
                <motion.div
                  key={perm.name}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-4 rounded-lg border ${
                    perm.risk === "high"
                      ? "border-destructive/30 bg-destructive/5"
                      : perm.risk === "medium"
                      ? "border-warning/30 bg-warning/5"
                      : "border-border bg-muted/20"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className={`p-2 rounded-lg ${
                          perm.risk === "high"
                            ? "bg-destructive/10"
                            : perm.risk === "medium"
                            ? "bg-warning/10"
                            : "bg-muted"
                        }`}
                      >
                        <perm.icon
                          className={`w-4 h-4 ${
                            perm.risk === "high"
                              ? "text-destructive"
                              : perm.risk === "medium"
                              ? "text-warning"
                              : "text-muted-foreground"
                          }`}
                        />
                      </div>
                      <div>
                        <p className="text-sm font-mono font-medium">{perm.name}</p>
                        <p className="text-xs text-muted-foreground">{perm.description}</p>
                      </div>
                    </div>
                    <StatusBadge
                      variant={
                        perm.risk === "high"
                          ? "critical"
                          : perm.risk === "medium"
                          ? "high"
                          : "low"
                      }
                    >
                      {perm.risk}
                    </StatusBadge>
                  </div>
                </motion.div>
              ))}
            </div>
          </GlassCard>

          <Button variant="outline" onClick={() => setIsAnalyzed(false)}>
            Analyze Another File
          </Button>
        </motion.div>
      )}
    </div>
  );
}