import type { ReactNode } from "react";
import { TriangleAlert, X } from "lucide-react";
import { cn } from "@/lib/utils";

export const TUNNEL_FORM_STYLES = {
  help: "text-xs leading-5 text-muted-foreground dark:text-zinc-500",
  section: "text-sm font-medium text-foreground dark:text-zinc-100",
  label: "text-xs font-medium text-foreground dark:text-zinc-200",
  strong: "text-foreground dark:text-zinc-100",
  input:
    "h-10 rounded-md border border-border bg-background text-foreground placeholder:text-muted-foreground shadow-sm dark:border-white/10 dark:bg-background dark:text-zinc-100 dark:placeholder:text-zinc-500",
  chipField:
    "flex min-h-10 flex-wrap items-center gap-2 rounded-md border border-border bg-background px-2 py-2 shadow-sm focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/25 dark:border-white/10 dark:bg-transparent",
  chipInput:
    "text-foreground placeholder:text-muted-foreground dark:text-zinc-100 dark:placeholder:text-zinc-500",
  chip: "inline-flex items-center gap-1 rounded-md bg-secondary px-2.5 py-1 text-xs font-semibold text-secondary-foreground dark:bg-primary/14 dark:text-primary",
  chipRemove:
    "text-text-muted hover:bg-background/80 dark:text-primary dark:hover:bg-black/20",
  card: "border-border bg-background hover:border-primary/50 dark:border-white/10 dark:bg-transparent",
  panel: "border-border bg-muted/45 dark:border-white/8 dark:bg-background/70",
  note: "bg-muted text-muted-foreground dark:bg-white/5 dark:text-zinc-400",
  code: "bg-secondary/55 text-foreground ring-1 ring-border/70 dark:bg-secondary/60 dark:text-zinc-100 dark:ring-transparent",
  copy: "text-text-muted hover:bg-background/70 dark:text-zinc-500 dark:hover:bg-black/20",
  preview: "border-border bg-card dark:border-white/10",
  error: "text-destructive",
  warn: "text-amber-700 dark:text-amber-400",
} as const;

const s = TUNNEL_FORM_STYLES;

export function Notice({
  tone,
  children,
}: {
  tone: "error" | "warn";
  children: ReactNode;
}) {
  return (
    <p
      className={cn(
        "flex items-start gap-1.5 text-xs leading-5",
        tone === "error" ? s.error : s.warn
      )}
    >
      <TriangleAlert aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>{children}</span>
    </p>
  );
}

export function Chip({
  text,
  kind,
  invalid = false,
  removeLabel,
  removeDisabled = false,
  onRemove,
}: {
  text: string;
  kind?: string;
  invalid?: boolean;
  removeLabel: string;
  removeDisabled?: boolean;
  onRemove: () => void;
}) {
  return (
    <span className={cn(s.chip, invalid && "ring-1 ring-destructive")}>
      {kind && (
        <span
          className={cn(
            "text-[10px] font-semibold uppercase",
            invalid ? s.error : "text-primary"
          )}
        >
          {kind}
        </span>
      )}
      <span className="break-all">{text}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={removeLabel}
        disabled={removeDisabled}
        className={cn(
          "ml-1 rounded-sm p-0.5",
          removeDisabled ? "cursor-not-allowed opacity-40" : s.chipRemove
        )}
      >
        <X className="h-3 w-3" />
      </button>
    </span>
  );
}

export function ChipField({
  id,
  chips,
  draft,
  placeholder,
  commitKeys = ["Enter"],
  commitOnBlur = false,
  onDraftChange,
  onCommit,
  onRemoveLast,
}: {
  id?: string;
  chips: ReactNode;
  draft: string;
  placeholder: string;
  commitKeys?: string[];
  commitOnBlur?: boolean;
  onDraftChange: (draft: string) => void;
  onCommit: () => void;
  onRemoveLast: () => void;
}) {
  return (
    <div className={s.chipField}>
      {chips}
      <input
        id={id}
        type="text"
        value={draft}
        onChange={(event) => onDraftChange(event.target.value)}
        onKeyDown={(event) => {
          if (commitKeys.includes(event.key)) {
            event.preventDefault();
            onCommit();
          } else if (event.key === "Backspace" && draft === "") {
            onRemoveLast();
          }
        }}
        onBlur={commitOnBlur ? onCommit : undefined}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        className={cn(
          "min-w-[140px] flex-1 bg-transparent text-sm outline-none",
          s.chipInput
        )}
      />
    </div>
  );
}
