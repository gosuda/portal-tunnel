import { useState } from "react";
import type { PortSettings } from "@/hooks/useAdmin";

interface TransportPolicyControlProps {
  /** Short transport name shown in the labels, such as "UDP". */
  label: string;
  settings: PortSettings;
  disabled: boolean;
  onChange: (settings: PortSettings) => void | Promise<void>;
}

const SEGMENT_CLASS =
  "cursor-pointer disabled:cursor-wait disabled:opacity-50 px-4 h-10 text-sm font-medium transition-colors";
const SELECTED_CLASS = "bg-primary text-primary-foreground";
const UNSELECTED_CLASS = "bg-secondary text-secondary-foreground hover:bg-secondary/80";

/** The on/off switch and lease limit of one relay transport. */
export function TransportPolicyControl({ label, settings, disabled, onChange }: TransportPolicyControlProps) {
  const [maxLeasesInput, setMaxLeasesInput] = useState(String(settings.maxLeases));
  // A saved or refreshed limit replaces what is typed.
  const [savedMaxLeases, setSavedMaxLeases] = useState(settings.maxLeases);
  if (savedMaxLeases !== settings.maxLeases) {
    setSavedMaxLeases(settings.maxLeases);
    setMaxLeasesInput(String(settings.maxLeases));
  }

  const saveMaxLeases = () => {
    const value = Math.max(0, parseInt(maxLeasesInput, 10) || 0);
    setMaxLeasesInput(String(value));
    void onChange({ ...settings, maxLeases: value });
  };

  return (
    <>
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-text-muted">{label}</span>
        <div className="flex rounded-lg overflow-hidden border border-foreground/20">
          {[false, true].map((enabled) => (
            <button
              key={String(enabled)}
              disabled={disabled}
              onClick={() => void onChange({ ...settings, enabled })}
              className={`${SEGMENT_CLASS} ${enabled ? "border-l border-foreground/20" : ""} ${settings.enabled === enabled ? SELECTED_CLASS : UNSELECTED_CLASS}`}
            >
              {enabled ? "Enabled" : "Disabled"}
            </button>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-text-muted">Max {label}</span>
        <div className="flex items-center gap-2">
          <input
            type="number"
            min="0"
            aria-label={`Max ${label} leases`}
            disabled={disabled}
            value={maxLeasesInput}
            onChange={(e) => setMaxLeasesInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") saveMaxLeases();
            }}
            className="disabled:opacity-50 w-20 h-10 px-3 text-sm border border-foreground/20 rounded-lg bg-secondary text-foreground"
            placeholder="0"
          />
          <button
            disabled={disabled}
            onClick={saveMaxLeases}
            className="cursor-pointer disabled:cursor-wait disabled:opacity-50 h-10 px-4 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Save
          </button>
        </div>
      </div>
    </>
  );
}
