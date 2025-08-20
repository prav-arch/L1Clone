import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Dashboard from "@/pages/dashboard";
import Anomalies from "@/pages/anomalies";
import Sidebar from "@/components/sidebar";
import Header from "@/components/header";
import { useState } from "react";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/anomalies" component={Anomalies} />
      <Route component={Dashboard} />
    </Switch>
  );
}

function App() {
  const [currentPage, setCurrentPage] = useState("Dashboard");

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="min-h-screen bg-slate-50">
          <Sidebar setCurrentPage={setCurrentPage} />
          <div className="main-content-ml">
            <Header currentPage={currentPage} />
            <Router />
          </div>
        </div>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
