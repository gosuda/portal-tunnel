import type { Lease } from "@/types/api";
import { TunnelCommandForm } from "@/components/TunnelCommandForm";

const relayDocsLinks = [
  {
    eyebrow: "Documentation",
    title: "Feature Inventory",
    description:
      "Explore the canonical matrix of supported capabilities across CLI, Agent, SDK, and Relay.",
    href: "https://gosuda.github.io/portal-tunnel/features",
  },
  {
    eyebrow: "Operations",
    title: "Self-Hosting Relays",
    description:
      "Run your own MIT-licensed relay server with single-command Docker Compose and zero telemetry.",
    href: "https://gosuda.github.io/portal-tunnel/self-hosting",
  },
  {
    eyebrow: "Architecture",
    title: "Security & Transport",
    description:
      "Understand client-side tenant TLS, keyless signing, MITM self-probe, and relay ownership.",
    href: "https://gosuda.github.io/portal-tunnel/security-model",
  },
] as const;

export function LandingHero({ leases }: { leases: Lease[] | null }) {
  return (
    <section
      aria-labelledby="landing-title"
      className="relative pt-10 sm:pt-12 lg:pt-14"
    >
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        <div
          className="absolute inset-0 opacity-45 bg-size-[14px_14px] mask-[linear-gradient(to_bottom,white,transparent_80%)]"
          style={{
            backgroundImage:
              "radial-gradient(var(--hero-grid-dot) 0.8px, transparent 0.8px)",
          }}
        />
      </div>

      <a
        href="#live-servers"
        className="sr-only focus:not-sr-only focus:absolute focus:left-6 focus:top-6 focus:z-20 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground"
      >
        Skip to live servers
      </a>

      <div className="relative mx-auto max-w-6xl">
        <div className="mx-auto max-w-4xl text-center">
          <h1
            id="landing-title"
            className="text-4xl font-extrabold tracking-normal text-foreground sm:text-5xl lg:text-7xl"
            style={{ lineHeight: 0.96 }}
          >
            <span className="block">Expose Local Apps</span>
            <span className="mt-2 block text-primary">
              To The Public Internet
            </span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-text-muted sm:text-lg">
            Use relays as the public edge while your tunnel remains the app
            endpoint and owns routing behavior.
          </p>
        </div>

        <div id="quick-start" className="relative mt-9 scroll-mt-24 sm:mt-10">
          <div
            className="relative mx-auto w-full max-w-150 rounded-lg border px-4 py-5 sm:px-5 sm:py-6"
            style={{
              background: "var(--hero-terminal-bg)",
              borderColor: "var(--hero-terminal-border)",
              color: "var(--hero-terminal-foreground)",
              boxShadow: "0 18px 44px var(--hero-terminal-shadow)",
            }}
          >
            <div className="mb-5 flex min-w-0 items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-3">
                <span
                  aria-hidden="true"
                  className="shrink-0 font-mono text-lg leading-none"
                  style={{ color: "var(--hero-terminal-accent)" }}
                >
                  {">"}
                </span>
                <h2
                  id="tunnel-preview"
                  className="min-w-0 text-xl font-bold tracking-normal sm:text-2xl"
                >
                  Start a tunnel
                </h2>
              </div>
            </div>
            <TunnelCommandForm
              theme="terminal"
              mode="hero"
              leases={leases}
            />
          </div>
        </div>
      </div>

      <div className="relative mt-10 -mx-4 w-auto sm:-mx-6 md:-mx-8">
        <div className="overflow-hidden border-y border-border/80 bg-border/80">
          <div className="grid gap-px sm:grid-cols-3">
            {relayDocsLinks.map(({ eyebrow, title, description, href }) => (
              <a
                key={title}
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex min-h-44 bg-background p-6 text-left transition-colors duration-200 hover:bg-secondary/35 sm:min-h-48 sm:p-7"
              >
                <div className="flex h-full flex-col space-y-3">
                  <p className="text-[11px] font-semibold uppercase tracking-normal text-primary/80">
                    {eyebrow}
                  </p>
                  <h3 className="flex items-center justify-between text-[1.15rem] font-semibold tracking-normal text-foreground group-hover:text-primary sm:text-[1.25rem] sm:leading-tight">
                    <span>{title}</span>
                    <span className="text-xs text-text-muted transition-transform group-hover:translate-x-0.5">
                      &rarr;
                    </span>
                  </h3>
                  <p className="max-w-[32ch] text-[0.92rem] leading-6 text-text-muted">
                    {description}
                  </p>
                  <div className="mt-auto pt-4">
                    <div className="h-px w-10 bg-primary/45 transition-all group-hover:w-16 group-hover:bg-primary" />
                  </div>
                </div>
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
