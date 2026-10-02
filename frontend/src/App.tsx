import { Admin } from "@/pages/Admin";
import { ServerDetail } from "@/pages/ServerDetail";
import { ServerList } from "@/pages/ServerList";
import { ROUTE_PATHS } from "@/lib/apiPaths";
import { Navigate, Route, Routes } from "react-router-dom";

function App() {
  return (
    <Routes>
      <Route path={ROUTE_PATHS.home} element={<ServerList />} />
      <Route path={ROUTE_PATHS.serverDetail} element={<ServerDetail />} />
      <Route path={ROUTE_PATHS.admin} element={<Admin />} />
      <Route
        path={ROUTE_PATHS.browserTunnel}
        element={<Navigate to="/?platform=browser#quick-start" replace />}
      />
    </Routes>
  );
}

export default App;
