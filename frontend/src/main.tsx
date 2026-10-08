import { Ssgoi } from "@ssgoi/react";
import { hero } from "@ssgoi/react/view-transitions";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import App from "./App.tsx";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
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
  </ThemeProvider>
);
