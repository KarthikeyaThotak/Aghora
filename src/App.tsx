import { Component, ErrorInfo, ReactNode } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AnalysisSessionProvider } from "@/contexts/AnalysisSessionContext";
import { Workspace } from "@/components/Workspace";
import NotFound from "./pages/NotFound";
import { ShieldAlert, RefreshCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

// ── Error Boundary ────────────────────────────────────────────────────────────
interface EBState { hasError: boolean; error: Error | null }

class ErrorBoundary extends Component<{ children: ReactNode }, EBState> {
  state: EBState = { hasError: false, error: null };
  static getDerivedStateFromError(error: Error): EBState { return { hasError: true, error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("[ErrorBoundary]", error, info); }
  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-6">
        <div className="max-w-md text-center space-y-5">
          <div className="w-16 h-16 rounded-2xl bg-destructive/10 flex items-center justify-center mx-auto">
            <ShieldAlert className="h-8 w-8 text-destructive" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-foreground mb-1">Something crashed</h2>
            <p className="text-sm text-muted-foreground mb-3">An unexpected error occurred. Reload to try again.</p>
            {this.state.error && (
              <pre className="text-xs text-left bg-muted rounded-lg p-3 overflow-auto max-h-40 text-destructive">
                {this.state.error.message}
              </pre>
            )}
          </div>
          <Button onClick={() => window.location.reload()} className="gap-2">
            <RefreshCcw className="h-4 w-4" /> Reload app
          </Button>
        </div>
      </div>
    );
  }
}

// ── App ───────────────────────────────────────────────────────────────────────
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 30_000 } } });

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <AnalysisSessionProvider>
            <Routes>
              <Route path="/" element={<Workspace />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </AnalysisSessionProvider>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
