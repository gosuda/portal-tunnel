import { Ssgoi } from "@ssgoi/react";
import { hero } from "@ssgoi/react/view-transitions";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { WagmiProvider } from "wagmi";
import { ThemeProvider } from "@/components/ThemeProvider";
import { wagmiConfig } from "@/lib/wagmi";
import App from "./App.tsx";
import "./index.css";

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <Ssgoi
          config={{
            transitions: [
              {
                from: "/",
                to: "/server/*",
                transition: hero(),
                symmetric: true,
              },
            ],
          }}
        >
          <div style={{ position: "relative", minHeight: "100vh" }}>
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </div>
        </Ssgoi>
      </QueryClientProvider>
    </WagmiProvider>
  </ThemeProvider>
);
