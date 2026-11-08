import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const VARIANTS = {
  primary: "bg-primary text-primary-content font-semibold",
  secondary: "bg-surface-300 text-content-emphasis font-semibold",
  ghost: "bg-transparent text-content-emphasis",
  danger: "bg-danger text-white font-semibold",
} as const;

const SIZES = {
  sm: "h-8 gap-1.5 px-3 text-sm rounded-md",
  md: "h-10 gap-2 px-4 text-sm rounded-md",
  lg: "h-12 gap-2 px-6 text-base rounded-lg",
} as const;

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof VARIANTS;
  size?: keyof typeof SIZES;
}

export function Button({ variant = "secondary", size = "md", className, type = "button", ...props }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn("interactive inline-flex shrink-0 items-center justify-center whitespace-nowrap", VARIANTS[variant], SIZES[size], className)}
      {...props}
    />
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  "aria-label": string;
}

export function IconButton({ className, type = "button", ...props }: IconButtonProps) {
  return (
    <button
      type={type}
      className={cn("interactive inline-flex size-8 shrink-0 items-center justify-center rounded-full text-content-emphasis", className)}
      {...props}
    />
  );
}
