import type { ReactNode } from "react";
import { AlertCircle, Home, LogOut, ShieldCheck } from "lucide-react";
import { AdminConsole } from "@/components/admin/AdminConsole";
import { AdminSkeleton, StateMessage } from "@/components/admin/AdminStates";
import { RelayVersion } from "@/components/admin/RelayVersion";
import { SignInCard } from "@/components/admin/SignInCard";
import { AppShell, SidebarItem, SidebarSection } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/button";
import { useAdmin } from "@/hooks/useAdmin";
import { useAuth } from "@/hooks/useAuth";
import { ROUTE_PATHS } from "@/lib/apiPaths";

export function Admin() {
  const { isAuthenticated, isLoading, login, logout } = useAuth();
  const admin = useAdmin(isAuthenticated);
  const empty = admin.servers.length === 0;

  let body: ReactNode;
  if (isLoading || (isAuthenticated && admin.loading && empty)) {
    body = <AdminSkeleton />;
  } else if (!isAuthenticated) {
    body = <SignInCard login={login} />;
  } else if (admin.error && empty) {
    body = (
      <StateMessage icon={<AlertCircle />} title="Couldn't load admin data">
        {admin.error}
      </StateMessage>
    );
  } else {
    body = <AdminConsole {...admin} />;
  }

  return (
    <AppShell
      actions={
        isAuthenticated ? (
          <Button variant="ghost" aria-label="Sign out" onClick={() => void logout()}>
            <LogOut className="size-5" aria-hidden />
            <span className="hidden sm:inline">Sign out</span>
          </Button>
        ) : undefined
      }
      sidebar={
        <>
          <SidebarSection>
            <SidebarItem icon={<Home />} label="Directory" href={ROUTE_PATHS.home} />
            <SidebarItem icon={<ShieldCheck />} label="Admin" current />
          </SidebarSection>
          <RelayVersion />
        </>
      }
    >
      <div className="mx-auto w-full max-w-[2400px] px-4 pb-12 md:px-6">{body}</div>
    </AppShell>
  );
}
