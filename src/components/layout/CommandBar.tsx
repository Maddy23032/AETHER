import { useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { Search, Command, ChevronRight, Bell, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

const routeNames: Record<string, string> = {
  "/dashboard": "Mission Control",
  "/recon": "Web Recon",
  "/mobile": "Mobile Security",
  "/malware": "Malware Lab",
  "/chat": "Intelligence",
  "/settings": "Settings",
};

export function CommandBar() {
  const location = useLocation();
  const currentRoute = routeNames[location.pathname] || "Dashboard";

  return (
    <header className="sticky top-0 z-40 h-16 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="flex items-center justify-between h-full px-4">
        {/* Left: Sidebar Trigger + Breadcrumbs */}
        <div className="flex items-center gap-4">
          <SidebarTrigger className="text-muted-foreground hover:text-foreground" />
          
          <nav className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Home</span>
            <ChevronRight className="w-4 h-4 text-muted-foreground/50" />
            <motion.span
              key={currentRoute}
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              className="font-medium text-foreground"
            >
              {currentRoute}
            </motion.span>
          </nav>
        </div>

        {/* Right: Search + Actions */}
        <div className="flex items-center gap-3">
          {/* Search */}
          <Button
            variant="outline"
            className="hidden md:flex items-center gap-2 px-3 py-2 h-9 bg-muted/50 border-border hover:bg-muted text-muted-foreground"
          >
            <Search className="w-4 h-4" />
            <span className="text-sm">Search assets...</span>
            <kbd className="ml-4 flex items-center gap-1 px-1.5 py-0.5 text-xs bg-background rounded border border-border">
              <Command className="w-3 h-3" />K
            </kbd>
          </Button>

          {/* Status */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full bg-success/10 text-success text-xs font-medium">
            <div className="w-2 h-2 rounded-full bg-success pulse-dot" />
            System Online
          </div>

          {/* Notifications */}
          <Button variant="ghost" size="icon" className="relative text-muted-foreground hover:text-foreground">
            <Bell className="w-5 h-5" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-destructive" />
          </Button>

          {/* Profile */}
          <Avatar className="w-9 h-9 border-2 border-primary/30">
            <AvatarImage src="/placeholder.svg" />
            <AvatarFallback className="bg-primary/20 text-primary text-sm font-medium">
              OP
            </AvatarFallback>
          </Avatar>
        </div>
      </div>
    </header>
  );
}