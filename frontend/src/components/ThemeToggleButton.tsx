import { MoonStar, Sun } from "lucide-react";
import clsx from "clsx";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";

interface ThemeToggleButtonProps {
  className?: string;
}

export function ThemeToggleButton({ className }: ThemeToggleButtonProps) {
  const { theme, toggleTheme } = useTheme();
  const nextTheme = theme === "dark" ? "light" : "dark";

  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      onClick={toggleTheme}
      className={clsx(
        "h-[38px] w-[38px] cursor-pointer rounded-[9px] border border-border bg-card/80 text-foreground shadow-sm transition-colors hover:border-primary/45 hover:text-primary",
        className
      )}
      aria-label={`Switch to ${nextTheme} theme`}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
    >
      {theme === "dark" ? (
        <MoonStar className="h-[18px] w-[18px]" />
      ) : (
        <Sun className="h-[18px] w-[18px]" />
      )}
    </Button>
  );
}
