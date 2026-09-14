import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import App from "./App.tsx";
import "./index.css";

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
    <QueryClientProvider client={queryClient}>
      <div style={{ position: "relative", minHeight: "100vh" }}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </div>
    </QueryClientProvider>
  </ThemeProvider>
);
