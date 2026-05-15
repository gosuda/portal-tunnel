import { Admin } from "@/pages/Admin";
import { ServerDetail } from "@/pages/ServerDetail";
import { ServerList } from "@/pages/ServerList";
import { ROUTE_PATHS } from "@/lib/apiPaths";
import { Route, Routes } from "react-router-dom";

function App() {
  return (
    <Routes>
      <Route path={ROUTE_PATHS.home} element={<ServerList />} />
      <Route path={ROUTE_PATHS.serverDetail} element={<ServerDetail />} />
      <Route path={ROUTE_PATHS.admin} element={<Admin />} />
    </Routes>
  );
}

export default App;
