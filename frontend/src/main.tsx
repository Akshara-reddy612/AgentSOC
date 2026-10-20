import "@mantine/core/styles.css";
import "./soc.css";
import { MantineProvider, createTheme } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./auth";

// Navy "SOC console" dark palette (Mantine reads dark[7] as the body, dark[6] for inputs, dark[4] for borders).
const theme = createTheme({
  primaryColor: "cyan",
  fontFamily: "Inter, 'Segoe UI Variable Text', 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', 'Cascadia Mono', Consolas, monospace",
  defaultRadius: "md",
  colors: {
    dark: ["#e6ebf2", "#c4ccd8", "#a8b3c4", "#7b8798", "#33435e", "#22314c", "#16223a", "#111a2b", "#0b1220", "#070c16"],
  },
  headings: { fontWeight: "650" },
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <App />
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>,
);
