import {
  startTransition,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";
import { TunnelCommandForm } from "@/components/TunnelCommandForm";

const heroDifferentiatorCards = [
  {
    key: "login",
    title: "No Login",
    description: "Run the command immediately without accounts or auth flows.",
  },
  {
    key: "billing",
    title: "No Billing",
    description: "No credit card, no plan gate, and no billing step before go-live.",
  },
  {
    key: "cloud",
    title: "No Cloud SaaS",
    description: "No dashboard, region picker, or managed cloud setup to get started.",
  },
  {
    key: "permissionless",
    title: "Permissionless",
    description: "Use the public registry or attach your own relay. No approval required.",
  },
] as const;

const heroFeatures = [
  {
    eyebrow: "HTTPS",
    title: "Public HTTPS for localhost",
    description:
      "Publish local apps through TCP passthrough without opening inbound ports.",
  },
  {
    eyebrow: "TLS",
    title: "End-to-end TLS on your side",
    description:
      "Tenant TLS terminates locally with MITM detection, so relays cannot access plaintext.",
  },
  {
    eyebrow: "Setup",
    title: "One-command setup",
    description:
      "Start relays and tunnels with minimal setup and a short copy-paste path.",
  },
  {
    eyebrow: "Relay",
    title: "Self-hosted relays and pools",
    description:
      "Connect to public relays, use discovered relays as a pool with failover, or run your own.",
  },
  {
    eyebrow: "Transport",
    title: "Raw TCP with optional UDP",
    description:
      "Carry web traffic and arbitrary protocols without SSH or WebSocket overlays.",
  },
  {
    eyebrow: "Identity",
    title: "Sui ownership with ENS support",
    description:
      "Authenticate ownership with Sui signatures and keep ENS import as a compact naming hint.",
  },
] as const;

export function LandingHero() {
  const carouselCardCount = heroDifferentiatorCards.length;
  const carouselLoopBoundaryIndex = carouselCardCount + 1;
  const carouselTransitionDurationMs = 700;
  const [reduceMotion, setReduceMotion] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [trackIndex, setTrackIndex] = useState(1);
  const [transitionEnabled, setTransitionEnabled] = useState(true);
  const [slideSize, setSlideSize] = useState(328);
  const [dragOffset, setDragOffset] = useState(0);
  const dragStartXRef = useRef<number | null>(null);
  const dragOffsetRef = useRef(0);
  const pointerIdRef = useRef<number | null>(null);

  const slideGap = 16;
  const carouselSlides = useMemo(
    () => [
      heroDifferentiatorCards[carouselCardCount - 1],
      ...heroDifferentiatorCards,
      heroDifferentiatorCards[0],
    ],
    [carouselCardCount]
  );
  const renderedTrackIndex = Math.min(
    Math.max(trackIndex, 0),
    carouselSlides.length - 1
  );
  const trackTranslateX = `calc(50% - ${slideSize / 2}px - ${
    renderedTrackIndex * (slideSize + slideGap)
  }px ${dragOffset >= 0 ? "+" : "-"} ${Math.abs(dragOffset)}px)`;

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }

    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const syncReduceMotion = () => {
      setReduceMotion(media.matches);
    };

    syncReduceMotion();

    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", syncReduceMotion);
      return () => media.removeEventListener("change", syncReduceMotion);
    }

    media.addListener(syncReduceMotion);
    return () => media.removeListener(syncReduceMotion);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const updateSlideSize = () => {
      if (window.innerWidth >= 1024) {
        setSlideSize(560);
        return;
      }

      if (window.innerWidth >= 640) {
        setSlideSize(472);
        return;
      }

      const maxMobileWidth = Math.min(window.innerWidth - 48, 368);
      setSlideSize(Math.max(maxMobileWidth, 288));
    };

    updateSlideSize();
    window.addEventListener("resize", updateSlideSize);

    return () => {
      window.removeEventListener("resize", updateSlideSize);
    };
  }, []);

  useEffect(() => {
    if (reduceMotion || isDragging) {
      return;
    }

    const interval = window.setInterval(() => {
      startTransition(() => {
        setTransitionEnabled(true);
        setTrackIndex((current) =>
          current >= carouselLoopBoundaryIndex
            ? carouselLoopBoundaryIndex
            : current + 1
        );
      });
    }, 2200);

    return () => {
      window.clearInterval(interval);
    };
  }, [carouselLoopBoundaryIndex, isDragging, reduceMotion]);

  useEffect(() => {
    if (transitionEnabled) {
      return;
    }

    if (typeof window === "undefined") {
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        setTransitionEnabled(true);
      });
    });

    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [transitionEnabled]);

  useEffect(() => {
    if (isDragging) {
      return;
    }

    if (trackIndex !== 0 && trackIndex !== carouselLoopBoundaryIndex) {
      return;
    }

    const timer = window.setTimeout(() => {
      setTransitionEnabled(false);
      setTrackIndex(trackIndex === 0 ? carouselCardCount : 1);
    }, carouselTransitionDurationMs);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    carouselCardCount,
    carouselLoopBoundaryIndex,
    carouselTransitionDurationMs,
    isDragging,
    trackIndex,
  ]);

  const finishDrag = (shouldAdvance: boolean, direction: "next" | "prev" | null) => {
    dragStartXRef.current = null;
    dragOffsetRef.current = 0;
    pointerIdRef.current = null;
    setIsDragging(false);
    setTransitionEnabled(true);
    setDragOffset(0);

    if (!shouldAdvance || !direction) {
      return;
    }

    setTrackIndex((current) => {
      if (direction === "next") {
        return current >= carouselLoopBoundaryIndex
          ? carouselLoopBoundaryIndex
          : current + 1;
      }

      return current <= 0 ? 0 : current - 1;
    });
  };

  const handlePointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.pointerType === "mouse" && event.button !== 0) {
      return;
    }

    dragStartXRef.current = event.clientX;
    dragOffsetRef.current = 0;
    pointerIdRef.current = event.pointerId;
    setIsDragging(true);
    setTransitionEnabled(false);
    setDragOffset(0);
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (
      !isDragging ||
      dragStartXRef.current === null ||
      pointerIdRef.current !== event.pointerId
    ) {
      return;
    }

    const nextOffset = event.clientX - dragStartXRef.current;
    dragOffsetRef.current = nextOffset;
    setDragOffset(nextOffset);
  };

  const handlePointerEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!isDragging || pointerIdRef.current !== event.pointerId) {
      return;
    }

    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }

    const threshold = Math.min(88, slideSize * 0.16);
    const shouldAdvance = Math.abs(dragOffsetRef.current) > threshold;
    const direction =
      dragOffsetRef.current < 0
        ? "next"
        : dragOffsetRef.current > 0
          ? "prev"
          : null;

    finishDrag(shouldAdvance, direction);
  };

  return (
    <section
      aria-labelledby="landing-title"
      className="relative pt-10 sm:pt-12 lg:pt-16"
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
      >
        <div
          className="absolute inset-0 opacity-45 bg-size-[14px_14px] mask-[linear-gradient(to_bottom,white,transparent_82%)]"
          style={{
            backgroundImage:
              "radial-gradient(var(--hero-grid-dot) 0.8px, transparent 0.8px)",
          }}
        />
      </div>

      <a
        href="#live-servers"
        className="sr-only focus:not-sr-only focus:absolute focus:left-6 focus:top-6 focus:z-20 focus:rounded-full focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground"
      >
        Skip to live servers
      </a>

      <div className="relative mx-auto max-w-4xl px-2 text-center sm:px-4">
        <h1
          id="landing-title"
          className="text-4xl font-extrabold tracking-tight text-foreground sm:text-5xl lg:text-7xl"
          style={{ lineHeight: 0.96 }}
        >
          <span className="block">Expose Local Apps</span>
          <span
            className="mt-2 block bg-clip-text text-transparent"
            style={{
              backgroundImage:
                "linear-gradient(90deg, var(--hero-gradient-start) 0%, var(--hero-gradient-mid) 46%, var(--hero-gradient-end) 100%)",
            }}
          >
            To The Public Internet
          </span>
        </h1>
      </div>

      <div className="relative mt-10 -mx-4 w-auto sm:-mx-6 md:-mx-8">
        <div className="overflow-hidden border-b border-border/80 bg-transparent">
          <div className="relative mx-auto max-w-7xl px-3 py-6 sm:px-6 sm:py-8">
            <div className="pointer-events-none absolute inset-x-0 top-6 flex justify-center sm:top-8">
              <div className="h-28 w-28 rounded-full bg-primary/16 blur-3xl dark:bg-primary/22" />
            </div>
            <div className="pointer-events-none absolute inset-y-0 left-0 z-40 w-12 bg-linear-to-r from-background via-background/74 to-transparent dark:from-background dark:via-background/60 sm:w-24" />
            <div className="pointer-events-none absolute inset-y-0 right-0 z-40 w-12 bg-linear-to-l from-background via-background/74 to-transparent dark:from-background dark:via-background/60 sm:w-24" />

            <div className="relative h-82 sm:h-90">
              <div
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerEnd}
                onPointerCancel={handlePointerEnd}
                className={`flex h-full items-start gap-4 px-1 pt-6 sm:px-4 sm:pt-8 ${
                  transitionEnabled && !isDragging
                    ? "transition-transform duration-700 ease-[cubic-bezier(0.22,1,0.36,1)]"
                    : "transition-none"
                } ${isDragging ? "cursor-grabbing" : "cursor-grab"}`}
                style={{
                  transform: `translateX(${trackTranslateX})`,
                  touchAction: "pan-y",
                }}
              >
                {carouselSlides.map((card, index) => {
                  const distance = Math.abs(index - trackIndex);
                  const isActive = index === trackIndex;

                  return (
                    <article
                      key={`${card.key}-${index}`}
                      className={`relative h-61 shrink-0 overflow-hidden rounded-[1.65rem] border px-5 py-5 text-left transition-[opacity,transform,box-shadow] duration-700 ease-[cubic-bezier(0.22,1,0.36,1)] sm:h-67 sm:px-7 sm:py-6 ${
                        isActive
                          ? "border-primary/24 bg-white/92 opacity-100 shadow-[0_24px_54px_rgba(15,23,42,0.08)] dark:bg-white/8 dark:shadow-[0_26px_60px_rgba(0,0,0,0.22)]"
                          : distance === 1
                            ? "border-border/70 bg-background/78 opacity-62 shadow-[0_14px_32px_rgba(15,23,42,0.04)] dark:bg-white/4"
                            : "border-border/60 bg-background/70 opacity-30 shadow-none dark:bg-white/3"
                      } ${isActive ? "translate-y-0 scale-100" : "translate-y-5 scale-[0.95]"}`}
                      style={{ width: `${slideSize}px` }}
                      aria-hidden={!isActive}
                    >
                      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(75,195,230,0.12),transparent_36%)] dark:bg-[radial-gradient(circle_at_top_right,rgba(75,195,230,0.14),transparent_36%)]" />
                      <div className="relative flex h-full flex-col">
                        <div className="flex items-center gap-4">
                          <span className="inline-flex rounded-full bg-primary/12 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-primary">
                            Portal
                          </span>
                        </div>
                        <div className="mt-10 space-y-3">
                          <h3 className="max-w-[12ch] text-[1.9rem] leading-[0.92] font-semibold tracking-tight text-foreground sm:text-[2.2rem]">
                            {card.title}
                          </h3>
                          <p className="max-w-[34ch] text-[0.98rem] leading-6 text-text-muted sm:text-[1rem]">
                            {card.description}
                          </p>
                        </div>
                        <div className="mt-auto pt-8">
                          <div className="h-px w-16 bg-linear-to-r from-primary/55 to-transparent" />
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="relative -mx-4 w-auto sm:-mx-6 md:-mx-8">
        <div className="mx-auto max-w-6xl px-4 pb-5 text-left sm:px-6">
          <div className="space-y-2">
            <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">
              Core features
            </p>
            <h2 className="text-3xl font-semibold tracking-tight text-foreground">
              Built for real localhost publishing
            </h2>
          </div>
        </div>
        <div className="overflow-hidden border-t border-border/80 bg-border/70">
          <div className="grid gap-px sm:grid-cols-2 lg:grid-cols-3">
            {heroFeatures.map(({ eyebrow, title, description }) => (
              <article
                key={title}
                className="flex min-h-52 bg-background/88 p-6 text-left transition-colors duration-200 hover:bg-background/92 sm:min-h-56 sm:p-7"
              >
                <div className="flex h-full flex-col space-y-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary/80">
                    {eyebrow}
                  </p>
                  <h3 className="text-[1.2rem] font-semibold tracking-tight text-foreground sm:text-[1.32rem] sm:leading-tight">
                    {title}
                  </h3>
                  <p className="max-w-[28ch] text-[0.95rem] leading-6 text-text-muted">
                    {description}
                  </p>
                  <div className="mt-auto pt-4">
                    <div className="h-px w-12 bg-linear-to-r from-primary/55 to-transparent" />
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>
      </div>

      <div id="quick-start" className="relative mt-8 scroll-mt-24 sm:mt-10">
        <div className="mx-auto w-full max-w-6xl text-left">
          <div className="space-y-2">
            <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">
              Quick Start
            </p>
            <h2 className="text-3xl font-semibold tracking-tight text-foreground">
              Expose service
            </h2>
          </div>

          <div
            className="relative mx-auto mt-4 w-full max-w-130 rounded-xl border px-4 py-5 sm:px-5 sm:py-6"
            style={{
              background: "var(--hero-terminal-bg)",
              borderColor: "var(--hero-terminal-border)",
              color: "var(--hero-terminal-foreground)",
              boxShadow: "0 30px 72px var(--hero-terminal-shadow)",
            }}
          >
            <div className="mb-5 flex min-w-0 items-center gap-3">
              <span
                aria-hidden="true"
                className="shrink-0 font-mono text-lg leading-none"
                style={{ color: "var(--hero-terminal-accent)" }}
              >
                {">"}
              </span>
              <h3
                id="tunnel-preview"
                className="min-w-0 text-xl font-bold tracking-tight sm:text-2xl"
              >
                Run this command
              </h3>
            </div>
            <TunnelCommandForm theme="terminal" mode="hero" />
          </div>
        </div>
      </div>
    </section>
  );
}
