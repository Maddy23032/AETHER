import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import {
  LayoutDashboard,
  Globe,
  Smartphone,
  Bug,
  Bot,
  Settings,
  Shield,
  Search,
  Network,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
  useSidebar,
} from "@/components/ui/sidebar";
import { cn } from "@/lib/utils";

const navItems = [
  { title: "Mission Control", href: "/dashboard", icon: LayoutDashboard },
  { title: "Web Recon", href: "/recon", icon: Globe },
  { title: "Enumeration", href: "/enumeration", icon: Search },
  { title: "Mobile Security", href: "/mobile", icon: Smartphone },
  { title: "Malware Lab", href: "/malware", icon: Bug },
  { title: "Graph Sitemap", href: "/sitemap", icon: Network },
  { title: "Intelligence", href: "/chat", icon: Bot },
  { title: "Settings", href: "/settings", icon: Settings },
];

export function AppSidebar() {
  const location = useLocation();
  const { state } = useSidebar();
  const isCollapsed = state === "collapsed";

  return (
    <Sidebar className="border-r border-sidebar-border bg-sidebar">
      <SidebarHeader className="p-4 border-b border-sidebar-border">
        <Link to="/dashboard" className="flex items-center gap-3">
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center glow-indigo"
          >
            <Shield className="w-6 h-6 text-primary" />
          </motion.div>
          {!isCollapsed && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex flex-col"
            >
              <span className="font-bold text-lg text-foreground tracking-tight">
                AETHER
              </span>
              <span className="text-xs text-muted-foreground">
                Security Platform
              </span>
            </motion.div>
          )}
        </Link>
      </SidebarHeader>

      <SidebarContent className="p-2">
        <SidebarMenu>
          {navItems.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <SidebarMenuItem key={item.href}>
                <SidebarMenuButton asChild>
                  <Link
                    to={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 relative group",
                      isActive
                        ? "bg-primary/10 text-primary"
                        : "text-sidebar-foreground hover:text-foreground hover:bg-muted/50"
                    )}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="activeTab"
                        className="absolute right-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-primary rounded-full"
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                      />
                    )}
                    <item.icon className={cn("w-5 h-5 shrink-0", isActive && "text-primary")} />
                    {!isCollapsed && (
                      <span className={cn("font-medium", isActive && "text-primary")}>
                        {item.title}
                      </span>
                    )}
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            );
          })}
        </SidebarMenu>
      </SidebarContent>

      <SidebarFooter className="p-4 border-t border-sidebar-border">
        {!isCollapsed && (
          <div className="glass-card p-3 rounded-lg">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <div className="w-2 h-2 rounded-full bg-success pulse-dot" />
              <span>All systems operational</span>
            </div>
          </div>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}