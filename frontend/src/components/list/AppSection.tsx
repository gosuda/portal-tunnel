import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowRight, ChevronLeft, ChevronRight } from "lucide-react";
import { AppTile, type TileHandlers, type TileVariant } from "@/components/list/AppTile";
import { cn } from "@/lib/utils";
import type { BaseServer } from "@/lib/server";

type Layout = "grid" | "carousel";

const GRID_CLASS: Record<TileVariant, string> = {
  wide: "grid-cols-2 @[740px]:grid-cols-3 @[1000px]:grid-cols-4 @[1205px]:grid-cols-5 @[1490px]:grid-cols-6",
  small: "grid-cols-[repeat(auto-fill,minmax(150px,1fr))]",
};

const GRID_VARIANT: Record<Layout, TileVariant> = { grid: "wide", carousel: "small" };

const CENTER_ON_SQUARE_THUMBNAIL = "top-[55px]";
const FOCUS_RING_ROOM = "-m-1 p-1 scroll-px-1";

interface AppSectionProps extends TileHandlers {
  title: string;
  servers: BaseServer[];
  layout: Layout;
  headingTrailing?: ReactNode;
}

export function AppSection({ title, servers, layout, headingTrailing, ...handlers }: AppSectionProps) {
  const [expanded, setExpanded] = useState(false);
  const expandable = layout === "carousel";

  return (
    <section aria-label={title}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="min-w-0 type-heading-small text-content-emphasis">
          {expandable ? (
            <button
              type="button"
              aria-expanded={expanded}
              onClick={() => setExpanded(!expanded)}
              className="group/see flex max-w-full items-center gap-1 rounded-md text-left"
            >
              <span className="truncate group-hover/see:underline">{title}</span>
              <ArrowRight className={cn("size-5 shrink-0", expanded && "rotate-90")} />
            </button>
          ) : (
            title
          )}
        </h2>
        {headingTrailing}
      </div>
      {expandable && !expanded ? (
        <Carousel count={servers.length} label={title}>
          {servers.map((server) => (
            <li key={server.id} className="w-[150px] shrink-0 snap-start">
              <AppTile server={server} variant="small" {...handlers} />
            </li>
          ))}
        </Carousel>
      ) : (
        <TileGrid servers={servers} variant={GRID_VARIANT[layout]} {...handlers} />
      )}
    </section>
  );
}

export function TileGrid({ servers, variant, ...handlers }: TileHandlers & { servers: BaseServer[]; variant: TileVariant }) {
  return (
    <ul className={cn("grid gap-x-4 gap-y-6", GRID_CLASS[variant])}>
      {servers.map((server) => (
        <li key={server.id} className="min-w-0">
          <AppTile server={server} variant={variant} {...handlers} />
        </li>
      ))}
    </ul>
  );
}

export function TileSkeletons({ count = 12 }: { count?: number }) {
  return (
    <ul aria-hidden="true" className={cn("grid gap-x-4 gap-y-6", GRID_CLASS.wide)}>
      {Array.from({ length: count }, (_, index) => (
        <li key={index} className="min-w-0">
          <div className="aspect-video rounded-md bg-surface-200 motion-safe:animate-pulse" />
          <div className="mt-2 h-[22px] w-3/4 rounded-sm bg-surface-200 motion-safe:animate-pulse" />
          <div className="mt-1 h-5 w-1/3 rounded-sm bg-surface-200 motion-safe:animate-pulse" />
        </li>
      ))}
    </ul>
  );
}

function Carousel({ label, count, children }: { label: string; count: number; children: ReactNode }) {
  const scroller = useRef<HTMLUListElement>(null);
  const [canPrev, setCanPrev] = useState(false);
  const [canNext, setCanNext] = useState(false);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const update = () => {
      setCanPrev(el.scrollLeft > 1);
      setCanNext(el.scrollLeft + el.clientWidth < el.scrollWidth - 1);
    };
    update();
    el.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => {
      el.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, [count]);

  const scrollBy = (direction: 1 | -1) =>
    scroller.current?.scrollBy({ left: direction * scroller.current.clientWidth * 0.8, behavior: "smooth" });

  const arrow = cn(
    "absolute z-30 hidden size-10 items-center justify-center rounded-full bg-surface-100/90 text-content-emphasis opacity-0 transition-opacity motion-reduce:transition-none [@media(hover:hover)]:flex group-hover/carousel:opacity-100 group-focus-within/carousel:opacity-100 focus-visible:opacity-100",
    CENTER_ON_SQUARE_THUMBNAIL
  );

  return (
    <div className="group/carousel relative">
      <ul
        ref={scroller}
        aria-label={label}
        className={cn("no-scrollbar flex snap-x gap-3 overflow-x-auto", FOCUS_RING_ROOM)}
      >
        {children}
      </ul>
      {canPrev && (
        <button type="button" aria-label="Previous" onClick={() => scrollBy(-1)} className={cn(arrow, "left-2")}>
          <ChevronLeft className="size-6" />
        </button>
      )}
      {canNext && (
        <button type="button" aria-label="Next" onClick={() => scrollBy(1)} className={cn(arrow, "right-2")}>
          <ChevronRight className="size-6" />
        </button>
      )}
    </div>
  );
}
