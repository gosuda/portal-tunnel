import type { ButtonHTMLAttributes, HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface ChipProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  selected?: boolean;
}

export function Chip({ selected = false, className, type = "button", ...props }: ChipProps) {
  return (
    <button
      type={type}
      aria-pressed={selected}
      className={cn(
        "interactive inline-flex h-8 shrink-0 items-center rounded-full px-3 text-sm font-semibold whitespace-nowrap",
        selected ? "bg-content-emphasis text-surface-0" : "bg-surface-300 text-content-emphasis",
        className
      )}
      {...props}
    />
  );
}

const TONES = {
  neutral: "bg-surface-300 text-content-emphasis",
  overlay: "bg-black/80 text-white backdrop-blur-xs",
  success: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  danger: "bg-danger/15 text-danger",
} as const;

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: keyof typeof TONES;
}

export function Badge({ tone = "neutral", className, ...props }: BadgeProps) {
  return (
    <span
      className={cn("inline-flex h-5 items-center gap-1 rounded-sm px-1.5 text-xs font-semibold", TONES[tone], className)}
      {...props}
    />
  );
}
