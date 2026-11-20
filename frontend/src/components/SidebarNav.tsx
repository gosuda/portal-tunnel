import type { JSX } from "react";
import type { ReactNode } from "react";
import { BookOpen, Globe, Home, ShieldCheck, Star, Terminal, ThumbsUp, type LucideIcon } from "lucide-react";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";
import { ROUTE_PATHS } from "@/lib/apiPaths";
import { DEFAULT_SORT, type BrowseView, type SortOption } from "@/types/filters";

const REPOSITORY_URL = "https://github.com/gosuda/portal-tunnel";
const DOCS_URL = "https://gosuda.github.io/portal-tunnel";

function GithubMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

export type SidebarVariant = "full" | "mini";

export interface SidebarNavProps {
  variant: SidebarVariant;
  browseView: BrowseView;
  sortBy: SortOption;
  favorites: number;
  onBrowseViewChange: (view: BrowseView) => void;
  onSortByChange: (value: SortOption) => void;
}

interface NavEntry {
  icon: LucideIcon;
  label: string;
  shortLabel?: string;
  current?: boolean;
  badge?: number;
  onClick?: () => void;
  href?: string;
}

const MINI_ITEM_CLASS =
  "flex w-full flex-col items-center justify-center gap-1 rounded-lg px-1 py-2.5 text-[10px] font-medium text-foreground hover:bg-secondary aria-[current=page]:bg-secondary aria-[current=page]:font-semibold";

function NavItem({ entry, variant }: { entry: NavEntry; variant: SidebarVariant }) {
  const Icon = entry.icon;
  const mini = variant === "mini";
  const content: ReactNode = mini ? (
    <>
      <span className="relative">
        <Icon className="size-5 shrink-0" aria-hidden="true" />
        {entry.badge !== undefined && entry.badge > 0 && (
          <span className="absolute -top-1 -right-2 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-primary px-0.5 text-[9px] font-bold leading-none text-primary-foreground">
            {entry.badge}
          </span>
        )}
      </span>
      <span className="max-w-full truncate text-center">{entry.shortLabel ?? entry.label}</span>
    </>
  ) : (
    <>
      <Icon className="size-5" aria-hidden="true" />
      <span>{entry.label}</span>
      {entry.badge !== undefined && <span className="ml-auto text-xs text-muted-foreground">{entry.badge}</span>}
    </>
  );
  const shared = {
    className: mini ? MINI_ITEM_CLASS : "portal-nav-item",
    title: mini ? entry.label : undefined,
    "aria-label": mini ? entry.label : undefined,
  };

  if (entry.href) {
    return (
      <a {...shared} href={entry.href} target="_blank" rel="noopener noreferrer">
        {content}
      </a>
    );
  }
  return (
    <button {...shared} type="button" aria-current={entry.current ? "page" : undefined} onClick={entry.onClick}>
      {content}
    </button>
  );
}

function NavGroup({
  label,
  heading,
  variant,
  first = false,
  children,
}: {
  label: string;
  heading?: string;
  variant: SidebarVariant;
  first?: boolean;
  children: ReactNode;
}) {
  const mini = variant === "mini";
  const divider = first ? "" : mini ? "mt-2 border-t border-border pt-2" : "mt-3 border-t border-border pt-3";
  const layout = mini ? "flex w-full flex-col items-center space-y-1" : "shrink-0 space-y-1";
  return (
    <nav aria-label={label} className={`${layout} ${divider}`}>
      {!mini && heading && <p className="px-3 py-2 text-base font-semibold">{heading}</p>}
      {children}
    </nav>
  );
}

export function SidebarNav({
  variant,
  browseView,
  sortBy,
  favorites,
  onBrowseViewChange,
  onSortByChange,
}: SidebarNavProps): JSX.Element {
  const mini = variant === "mini";
  const browse: NavEntry[] = [
    {
      icon: Home,
      label: "Home",
      current: browseView === "home" && sortBy === DEFAULT_SORT,
      onClick: () => onBrowseViewChange("home"),
    },
    {
      icon: ThumbsUp,
      label: "Most recommended",
      shortLabel: "Top",
      current: browseView === "home" && sortBy === "recommended",
      onClick: () => {
        onBrowseViewChange("home");
        onSortByChange("recommended");
      },
    },
    {
      icon: Star,
      label: "Favorites",
      badge: favorites,
      current: browseView === "favorites",
      onClick: () => onBrowseViewChange("favorites"),
    },
  ];
  const resources: NavEntry[] = [
    {
      icon: Globe,
      label: "Public relays",
      shortLabel: "Relays",
      current: browseView === "relays",
      onClick: () => onBrowseViewChange("relays"),
    },
    { icon: BookOpen, label: "Documentation", shortLabel: "Docs", href: DOCS_URL },
  ];
  const footerLinkClass = mini
    ? "flex size-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-secondary hover:text-foreground"
    : "inline-flex items-center gap-1.5 hover:text-foreground";

  return (
    <>
      <NavGroup label="Browse apps" variant={variant} first>
        {browse.map((entry) => <NavItem key={entry.label} entry={entry} variant={variant} />)}
      </NavGroup>
      <NavGroup label="Host" heading="Host" variant={variant}>
        <TunnelCommandModal
          trigger={
            <button
              type="button"
              aria-label="Launch App"
              title={mini ? "Launch App" : undefined}
              className={mini ? MINI_ITEM_CLASS : "portal-nav-item"}
            >
              <Terminal className="size-5 shrink-0" aria-hidden="true" />
              <span className={mini ? "max-w-full truncate text-center" : undefined}>{mini ? "Host" : "Launch App"}</span>
            </button>
          }
        />
      </NavGroup>
      <NavGroup label="Portal resources" heading="Explore Portal" variant={variant}>
        {resources.map((entry) => <NavItem key={entry.label} entry={entry} variant={variant} />)}
      </NavGroup>
      <div className={mini ? "mt-auto flex w-full flex-col items-center space-y-1 border-t border-border pt-3" : "mt-auto shrink-0 pt-4"}>
        <div className={mini ? "contents" : "flex items-center gap-4 border-t border-border px-3 pt-5 text-xs text-muted-foreground"}>
          <a href={REPOSITORY_URL} target="_blank" rel="noopener noreferrer" title={mini ? "GitHub" : undefined} aria-label={mini ? "GitHub" : undefined} className={footerLinkClass}>
            <GithubMark className="size-4 shrink-0" />
            {!mini && "GitHub"}
          </a>
          <a href={ROUTE_PATHS.admin} title={mini ? "Admin" : undefined} aria-label={mini ? "Admin" : undefined} className={footerLinkClass}>
            <ShieldCheck className="size-4 shrink-0" aria-hidden="true" />
            {!mini && "Admin"}
          </a>
        </div>
      </div>
    </>
  );
}
