import { Moon, Sun } from "lucide-react";
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
        "h-12 w-12 cursor-pointer rounded-full border-border/70 bg-background/90 text-foreground shadow-sm transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:bg-background hover:text-primary",
        className
      )}
      aria-label={`Switch to ${nextTheme} theme`}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
    >
      {theme === "dark" ? (
        <Sun className="h-5.5 w-5.5" />
      ) : (
        <Moon className="h-5.5 w-5.5" />
      )}
    </Button>
  );
}
