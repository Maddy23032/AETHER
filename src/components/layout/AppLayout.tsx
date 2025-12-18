import { Outlet } from "react-router-dom";
import { AppSidebar } from "./AppSidebar";
import { CommandBar } from "./CommandBar";
import { SidebarProvider } from "@/components/ui/sidebar";

export function AppLayout() {
  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-background grid-pattern">
        <AppSidebar />
        <div className="flex-1 flex flex-col min-h-screen">
          <CommandBar />
          <main className="flex-1 p-6 overflow-auto scrollbar-thin">
            <Outlet />
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}