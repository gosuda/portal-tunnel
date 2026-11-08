import { useEffect, useState } from "react";
import { SidebarSection } from "@/components/shell/AppShell";
import { Badge } from "@/components/ui/chip";
import { apiClient } from "@/lib/apiClient";
import { RELAY_API_PATHS } from "@/lib/apiPaths";
import type { DomainResponse } from "@/types/api";

export function RelayVersion() {
  const [version, setVersion] = useState("");
  const [ensVerified, setENSVerified] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const status = await apiClient.get<DomainResponse>(RELAY_API_PATHS.sdk.domain);
        if (cancelled) return;
        setVersion(typeof status?.release_version === "string" ? status.release_version.trim() : "");
        setENSVerified(status?.ens?.verified === true);
      } catch {
        if (cancelled) return;
        setVersion("");
        setENSVerified(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!version && !ensVerified) return null;
  return (
    <SidebarSection title="Relay">
      <div className="flex flex-wrap items-center gap-2 px-3 py-1">
        {version && <Badge className="font-mono">{version}</Badge>}
        {ensVerified && <Badge tone="success">ENS verified</Badge>}
      </div>
    </SidebarSection>
  );
}
