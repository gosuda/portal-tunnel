import { useState } from "react";
import { Gauge } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/ui/chip";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

const STEPS = [0, 10, 100, 1000, 10000, 100000, 1000000, 10000000];

function formatBPS(value: number): string {
  if (value === 0) return "Unlimited";
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB/s`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB/s`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB/s`;
  return `${value} B/s`;
}

function formatStep(value: number): string {
  if (value === 0) return "No cap";
  if (value >= 1000000) return `${value / 1000000}M`;
  if (value >= 1000) return `${value / 1000}K`;
  return String(value);
}

function stepIndex(value: number): number {
  if (value === 0) return 0;
  const index = STEPS.findIndex((step) => step >= value);
  return index === -1 ? STEPS.length - 1 : index;
}

interface BpsEditorProps {
  bps: number;
  disabled?: boolean;
  onSave: (bps: number) => void;
}

export function BpsEditor({ bps, disabled, onSave }: BpsEditorProps) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const value = Math.max(0, parseInt(input, 10) || 0);

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        disabled={disabled}
        aria-label={`Speed limit ${formatBPS(bps)}, edit`}
        onClick={() => {
          setInput(String(bps));
          setOpen(true);
        }}
        className="max-w-full justify-start px-2 font-normal"
      >
        <Gauge className="size-4 shrink-0 text-content-muted" aria-hidden />
        <span className="truncate">{formatBPS(bps)}</span>
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="min-[600px]:w-[min(420px,calc(100vw-2rem))]">
          <div className="flex flex-col gap-1 pr-10">
            <DialogTitle>Speed limit</DialogTitle>
            <DialogDescription className="text-sm text-content-muted">
              Set the bytes-per-second limit (0 = unlimited).
            </DialogDescription>
          </div>
          <p className="text-center text-2xl font-bold text-content-emphasis">{formatBPS(value)}</p>
          <input
            type="range"
            min={0}
            max={STEPS.length - 1}
            value={stepIndex(value)}
            aria-label="Speed limit step"
            onChange={(event) => setInput(String(STEPS[Number(event.target.value)]))}
            className="w-full accent-primary"
          />
          <div className="flex flex-wrap gap-2">
            {STEPS.map((step) => (
              <Chip key={step} selected={value === step} onClick={() => setInput(String(step))}>
                {formatStep(step)}
              </Chip>
            ))}
          </div>
          <label className="flex flex-col gap-1 text-sm text-content-muted">
            Custom value (B/s)
            <Input type="number" min="0" value={input} onChange={(event) => setInput(event.target.value)} placeholder="Enter BPS limit" />
          </label>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              variant="primary"
              onClick={() => {
                setOpen(false);
                onSave(value);
              }}
            >
              Save
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
