import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { AnalyzeFormProvider } from "./state/AnalyzeForm";

import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/utilities.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The artifacts are files written by long CLI runs — they do not change
      // while you are looking at them. Refetching on every window focus would
      // be pure noise, so refreshing is an explicit act.
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {/* Above the router: the Analyze form must outlive the page that
            renders it, or navigating away discards what you typed. */}
        <AnalyzeFormProvider>
          <App />
        </AnalyzeFormProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
