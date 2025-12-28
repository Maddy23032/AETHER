import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { ScanProvider } from "@/contexts/ScanContext";
import Dashboard from "@/pages/Dashboard";
import Recon from "@/pages/Recon";
import Enumeration from "@/pages/Enumeration";
import Mobile from "@/pages/Mobile";
import Malware from "@/pages/Malware";
import Chat from "@/pages/Chat";
import Sitemap from "@/pages/Sitemap";
import Settings from "@/pages/Settings";
import NotFound from "@/pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ScanProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route element={<AppLayout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/recon" element={<Recon />} />
              <Route path="/enumeration" element={<Enumeration />} />
              <Route path="/mobile" element={<Mobile />} />
              <Route path="/malware" element={<Malware />} />
              <Route path="/chat" element={<Chat />} />
              <Route path="/sitemap" element={<Sitemap />} />
              <Route path="/settings" element={<Settings />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ScanProvider>
  </QueryClientProvider>
);

export default App;