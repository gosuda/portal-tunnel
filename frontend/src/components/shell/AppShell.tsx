import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Menu, Moon, Sun } from "lucide-react";
import { IconButton } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";
import { cn } from "@/lib/utils";
import { ROUTE_PATHS } from "@/lib/apiPaths";

const DOCS_URL = "https://gosuda.github.io/portal-tunnel";
const REPOSITORY_URL = "https://github.com/gosuda/portal-tunnel";
const CLOSES_DRAWER = "data-nav-close";
const closesDrawer = { [CLOSES_DRAWER]: "" };

interface AppShellProps {
  search?: ReactNode;
  actions?: ReactNode;
  sidebar: ReactNode;
  children: ReactNode;
}

export function AppShell({ search, actions, sidebar, children }: AppShellProps) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { theme, toggleTheme } = useTheme();

  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setDrawerOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  return (
    <div className="min-h-screen bg-surface-0">
      <header className="fixed inset-x-0 top-0 z-40 flex h-header items-center gap-1 bg-surface-100 px-1 md:gap-2 md:px-2">
        <IconButton
          aria-label={drawerOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={drawerOpen}
          aria-controls="app-navigation"
          onClick={() => setDrawerOpen((open) => !open)}
          className="nav:hidden"
        >
          <Menu className="size-6" />
        </IconButton>
        <Link to={ROUTE_PATHS.home} aria-label="Portal home" className="flex shrink-0 items-center gap-1.5 rounded-md px-1 text-content-emphasis nav:ml-1">
          <img src="/favicon.svg" alt="" className="size-6" />
          <span className="hidden text-base font-extrabold tracking-tight sm:inline">PORTAL</span>
        </Link>
        <nav aria-label="Primary" className="hidden shrink-0 items-stretch self-stretch lg:flex">
          <HeaderLink to={ROUTE_PATHS.admin}>Admin</HeaderLink>
          <HeaderLink href={DOCS_URL}>Docs</HeaderLink>
          <HeaderLink href={REPOSITORY_URL}>GitHub</HeaderLink>
        </nav>
        <div className="flex min-w-0 max-w-[640px] flex-1 lg:ml-2">{search}</div>
        <div className="ml-auto flex shrink-0 items-center gap-1">
          {actions}
          <IconButton aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} onClick={toggleTheme}>
            {theme === "dark" ? <Sun className="size-5" /> : <Moon className="size-5" />}
          </IconButton>
        </div>
      </header>

      {drawerOpen && (
        <button type="button" aria-label="Close navigation" onClick={() => setDrawerOpen(false)} className="fixed inset-x-0 bottom-0 top-header z-40 bg-scrim nav:hidden" />
      )}
      <aside
        id="app-navigation"
        aria-label="Navigation"
        onClick={(event) => {
          if ((event.target as HTMLElement).closest(`[${CLOSES_DRAWER}]`)) setDrawerOpen(false);
        }}
        className={cn(
          "fixed bottom-0 left-0 top-header z-50 w-sidebar max-w-[calc(100vw-3rem)] overflow-y-auto border-r border-stroke bg-surface-0 p-4",
          "transition-[transform,visibility] duration-100 ease-standard nav:visible nav:translate-x-0 nav:z-30",
          drawerOpen ? "visible translate-x-0" : "invisible -translate-x-full"
        )}
      >
        <nav className="flex flex-col gap-2">{sidebar}</nav>
      </aside>

      <main id="main" tabIndex={-1} className="min-w-0 pt-header outline-none nav:pl-sidebar">
        {children}
      </main>
    </div>
  );
}

function HeaderLink({ to, href, children }: { to?: string; href?: string; children: ReactNode }) {
  const className =
    "flex items-center border-b-2 border-transparent px-4 type-label-large text-content-emphasis hover:border-content-emphasis";
  return to ? (
    <Link to={to} className={className}>
      {children}
    </Link>
  ) : (
    <a href={href} target="_blank" rel="noreferrer" className={className}>
      {children}
    </a>
  );
}

interface SidebarItemProps {
  icon: ReactNode;
  label: string;
  badge?: ReactNode;
  current?: boolean;
  href?: string;
  external?: boolean;
  onClick?: () => void;
}

export function SidebarItem({ icon, label, badge, current, href, external, onClick }: SidebarItemProps) {
  const className = cn(
    "interactive flex h-10 w-full items-center gap-2 rounded-md pl-2 pr-1 text-left type-title-large text-content-emphasis",
    current && "bg-state-hover"
  );
  const body = (
    <>
      <span className="flex size-6 shrink-0 items-center justify-center [&>svg]:size-6">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {badge}
    </>
  );
  if (href && external) {
    return (
      <a href={href} target="_blank" rel="noreferrer" {...closesDrawer} className={className}>
        {body}
      </a>
    );
  }
  if (href) {
    return (
      <Link to={href} aria-current={current ? "page" : undefined} {...closesDrawer} className={className}>
        {body}
      </Link>
    );
  }
  return (
    <button type="button" aria-current={current ? "page" : undefined} onClick={onClick} {...closesDrawer} className={className}>
      {body}
    </button>
  );
}

export function SidebarSection({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      {title && <h2 className="px-2 type-title-small uppercase tracking-wider text-content-muted">{title}</h2>}
      {children}
    </div>
  );
}
