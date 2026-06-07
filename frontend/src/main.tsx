import { Ssgoi } from "@ssgoi/react";
import { hero } from "@ssgoi/react/view-transitions";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createNetworkConfig, SuiClientProvider, WalletProvider } from "@mysten/dapp-kit";
import { getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import App from "./App.tsx";
import "@mysten/dapp-kit/dist/index.css";
import "./index.css";

const queryClient = new QueryClient();
const { networkConfig } = createNetworkConfig({
  mainnet: { url: getJsonRpcFullnodeUrl("mainnet") },
  testnet: { url: getJsonRpcFullnodeUrl("testnet") },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
    <QueryClientProvider client={queryClient}>
      <SuiClientProvider networks={networkConfig} defaultNetwork="mainnet">
        <WalletProvider autoConnect>
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
        </WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  </ThemeProvider>
);
