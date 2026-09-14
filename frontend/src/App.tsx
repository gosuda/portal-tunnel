import { Admin } from "@/pages/Admin";
import { ServerList } from "@/pages/ServerList";
import { ROUTE_PATHS } from "@/lib/apiPaths";
import { Route, Routes } from "react-router-dom";

function App() {
  return (
    <Routes>
      <Route path={ROUTE_PATHS.home} element={<ServerList />} />
      <Route path={ROUTE_PATHS.admin} element={<Admin />} />
    </Routes>
  );
}

export default App;
