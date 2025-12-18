import { motion } from "framer-motion";
import {
  User,
  Bell,
  Shield,
  Palette,
  Key,
  Globe,
  Database,
  Mail,
} from "lucide-react";
import { GlassCard } from "@/components/ui/glass-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

const settingsSections = [
  { id: "profile", label: "Profile", icon: User },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "security", label: "Security", icon: Shield },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "api", label: "API Keys", icon: Key },
  { id: "integrations", label: "Integrations", icon: Globe },
];

export default function Settings() {
  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Settings</h1>
        <p className="text-muted-foreground">Manage your account and preferences</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Settings Navigation */}
        <div className="lg:col-span-1">
          <GlassCard className="p-2">
            <nav className="space-y-1">
              {settingsSections.map((section, index) => (
                <motion.button
                  key={section.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                    index === 0
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                  }`}
                >
                  <section.icon className="w-4 h-4" />
                  {section.label}
                </motion.button>
              ))}
            </nav>
          </GlassCard>
        </div>

        {/* Settings Content */}
        <div className="lg:col-span-3 space-y-6">
          {/* Profile Section */}
          <GlassCard>
            <h3 className="text-lg font-semibold mb-4">Profile Settings</h3>
            
            <div className="flex items-start gap-6 mb-6">
              <Avatar className="w-20 h-20 border-2 border-primary/30">
                <AvatarImage src="/placeholder.svg" />
                <AvatarFallback className="bg-primary/20 text-primary text-xl">
                  OP
                </AvatarFallback>
              </Avatar>
              <div className="space-y-2">
                <h4 className="font-medium">Operator Alpha</h4>
                <p className="text-sm text-muted-foreground">operator@aether.security</p>
                <Button variant="outline" size="sm">
                  Change Avatar
                </Button>
              </div>
            </div>

            <Separator className="my-6" />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="name">Display Name</Label>
                <Input id="name" defaultValue="Operator Alpha" className="bg-muted/50" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  defaultValue="operator@aether.security"
                  className="bg-muted/50"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="role">Role</Label>
                <Input id="role" defaultValue="Security Analyst" className="bg-muted/50" disabled />
              </div>
              <div className="space-y-2">
                <Label htmlFor="team">Team</Label>
                <Input id="team" defaultValue="Red Team Alpha" className="bg-muted/50" />
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <Button>Save Changes</Button>
            </div>
          </GlassCard>

          {/* Notifications Section */}
          <GlassCard>
            <h3 className="text-lg font-semibold mb-4">Notification Preferences</h3>

            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                <div className="flex items-center gap-3">
                  <Mail className="w-5 h-5 text-muted-foreground" />
                  <div>
                    <p className="font-medium">Email Alerts</p>
                    <p className="text-sm text-muted-foreground">
                      Receive critical findings via email
                    </p>
                  </div>
                </div>
                <Switch defaultChecked />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                <div className="flex items-center gap-3">
                  <Bell className="w-5 h-5 text-muted-foreground" />
                  <div>
                    <p className="font-medium">Push Notifications</p>
                    <p className="text-sm text-muted-foreground">
                      Get notified when scans complete
                    </p>
                  </div>
                </div>
                <Switch defaultChecked />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
                <div className="flex items-center gap-3">
                  <Database className="w-5 h-5 text-muted-foreground" />
                  <div>
                    <p className="font-medium">Weekly Reports</p>
                    <p className="text-sm text-muted-foreground">
                      Receive weekly security summaries
                    </p>
                  </div>
                </div>
                <Switch />
              </div>
            </div>
          </GlassCard>

          {/* API Keys Section */}
          <GlassCard>
            <h3 className="text-lg font-semibold mb-4">API Access</h3>
            
            <div className="space-y-4">
              <div className="p-4 rounded-lg border border-border bg-muted/20">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Production API Key</span>
                  <Button variant="outline" size="sm">
                    Regenerate
                  </Button>
                </div>
                <code className="block p-2 rounded bg-background font-mono text-xs text-muted-foreground">
                  aether_live_••••••••••••••••••••••••••••
                </code>
              </div>

              <div className="p-4 rounded-lg border border-border bg-muted/20">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Development API Key</span>
                  <Button variant="outline" size="sm">
                    Regenerate
                  </Button>
                </div>
                <code className="block p-2 rounded bg-background font-mono text-xs text-muted-foreground">
                  aether_test_••••••••••••••••••••••••••••
                </code>
              </div>
            </div>

            <p className="mt-4 text-xs text-muted-foreground">
              Keep your API keys secure. Do not share them publicly.
            </p>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}