import "@mantine/core/styles.css";
import "./soc.css";
import { MantineProvider, createTheme } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./auth";

// Neutral graphite palette (Mantine reads dark[7] as the body, dark[6] for inputs, dark[4] for borders).
// The primary colour is a mid gray: neutral primary buttons; red / green / yellow keep their usual strength.
const theme = createTheme({
  primaryColor: "graphite",
  primaryShade: { light: 7, dark: 7 },
  autoContrast: true,
  fontFamily: "Inter, 'Segoe UI Variable Text', 'Segoe UI', system-ui, -apple-system, Roboto, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', 'Cascadia Mono', Consolas, monospace",
  defaultRadius: "sm",
  colors: {
    dark: ["#ececec", "#c8c8c8", "#a6a6a6", "#767676", "#3d3d3d", "#303030", "#262626", "#1c1c1c", "#141414", "#0d0d0d"],
    graphite: ["#f5f5f5", "#ececec", "#d9d9d9", "#bfbfbf", "#a6a6a6", "#8c8c8c", "#737373", "#595959", "#404040", "#262626"],
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
