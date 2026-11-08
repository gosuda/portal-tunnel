import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Input } from "@/components/ui/input";
import type { AdminState, PortSettings } from "@/hooks/useAdmin";
import { useBusy } from "./useBusy";

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-lg border border-stroke bg-surface-100 p-4">
      <h2 className="text-base font-bold text-content-emphasis">{title}</h2>
      {children}
    </section>
  );
}

function TransportCard({
  label,
  settings,
  disabled,
  onChange,
}: {
  label: string;
  settings: PortSettings;
  disabled: boolean;
  onChange: (settings: PortSettings) => Promise<void>;
}) {
  const { run } = useBusy();
  const [maxLeasesInput, setMaxLeasesInput] = useState(String(settings.maxLeases));
  const [lastSeenMaxLeases, setLastSeenMaxLeases] = useState(settings.maxLeases);
  if (lastSeenMaxLeases !== settings.maxLeases) {
    setLastSeenMaxLeases(settings.maxLeases);
    setMaxLeasesInput(String(settings.maxLeases));
  }

  const saveMaxLeases = () => {
    const value = Math.max(0, parseInt(maxLeasesInput, 10) || 0);
    setMaxLeasesInput(String(value));
    void run(() => onChange({ ...settings, maxLeases: value }));
  };

  return (
    <Card title={`${label} policy`}>
      <div role="group" aria-label={`${label} policy`} className="flex gap-2">
        {[true, false].map((enabled) => (
          <Chip
            key={String(enabled)}
            selected={settings.enabled === enabled}
            disabled={disabled}
            onClick={() => void run(() => onChange({ ...settings, enabled }))}
          >
            {enabled ? "Enabled" : "Disabled"}
          </Chip>
        ))}
      </div>
      <form
        className="flex items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          saveMaxLeases();
        }}
      >
        <span className="text-sm text-content-muted">Max leases</span>
        <Input
          name={`max-${label}`}
          type="number"
          min="0"
          aria-label={`Max ${label} leases`}
          disabled={disabled}
          value={maxLeasesInput}
          onChange={(event) => setMaxLeasesInput(event.target.value)}
          className="w-24"
        />
        <Button type="submit" variant="primary" disabled={disabled}>
          Save
        </Button>
      </form>
    </Card>
  );
}

type PolicyCardsProps = Pick<
  AdminState,
  | "approvalMode"
  | "udpSettings"
  | "tcpPortSettings"
  | "policySaving"
  | "handleApprovalModeChange"
  | "handleUDPSettingsChange"
  | "handleTCPPortSettingsChange"
>;

export function PolicyCards({
  approvalMode,
  udpSettings,
  tcpPortSettings,
  policySaving,
  handleApprovalModeChange,
  handleUDPSettingsChange,
  handleTCPPortSettingsChange,
}: PolicyCardsProps) {
  const { run } = useBusy();
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card title="Approval mode">
        <div role="group" aria-label="Approval mode" className="flex gap-2">
          {(["auto", "manual"] as const).map((mode) => (
            <Chip
              key={mode}
              selected={approvalMode === mode}
              disabled={policySaving}
              onClick={() => void run(() => handleApprovalModeChange(mode))}
            >
              {mode === "auto" ? "Auto" : "Manual"}
            </Chip>
          ))}
        </div>
        <p className="text-sm text-content-muted">
          {approvalMode === "auto" ? "New apps go live without review." : "New apps wait for approval before going live."}
        </p>
      </Card>
      <TransportCard label="UDP" settings={udpSettings} disabled={policySaving} onChange={handleUDPSettingsChange} />
      <TransportCard label="TCP" settings={tcpPortSettings} disabled={policySaving} onChange={handleTCPPortSettingsChange} />
    </div>
  );
}
