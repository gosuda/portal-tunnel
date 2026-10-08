import { useState } from "react";
import {
  ArrowLeftRight,
  ChevronRight,
  CircleDollarSign,
  Globe,
  LockKeyhole,
  Network,
  RotateCw,
} from "lucide-react";
import type { Lease } from "@/types/api";
import { TunnelCommandForm } from "@/components/TunnelCommandForm";

const capabilities = [
  {
    label: "Ingress",
    icon: Globe,
    title: "Public HTTPS for localhost",
    description:
      "Publish local services through public relays without opening inbound ports.",
    href: "https://gosuda.github.io/portal-tunnel/getting-started",
  },
  {
    label: "TLS",
    icon: LockKeyhole,
    title: "Keyless end-to-end tenant TLS",
    description:
      "Relays sign handshakes without session keys, so uncached HTTPS stays end to end. Opt-in static caching trusts the selected relays.",
    href: "https://gosuda.github.io/portal-tunnel/security-model",
  },
  {
    label: "Relays",
    icon: Network,
    title: "Self-hosted anonymous relays",
    description:
      "Use discovered public relays or run your own without a central account or operator.",
    href: "https://gosuda.github.io/portal-tunnel/self-hosting",
  },
  {
    label: "Failover",
    icon: RotateCw,
    title: "Resilient relay pools",
    description:
      "Keep connections to discovered or explicit relays so services survive relay failures.",
    href: "https://gosuda.github.io/portal-tunnel/concepts#multi-relay-selection",
  },
  {
    label: "Payments",
    icon: CircleDollarSign,
    title: "x402 for the agentic web",
    description:
      "Agents and browsers pay with Sui USDC in-flow; the tunnel enforces access to protected routes.",
    href: "https://gosuda.github.io/portal-tunnel/features",
  },
  {
    label: "Transport",
    icon: ArrowLeftRight,
    title: "Web traffic and raw protocols",
    description:
      "Carry HTTPS, raw TCP, and UDP workloads without SSH or WebSocket overlays.",
    href: "https://gosuda.github.io/portal-tunnel/tcp-udp-tunneling",
  },
] as const;

export function LandingHero({ leases }: { leases: Lease[] | null }) {
  const [active, setActive] = useState<(typeof capabilities)[number]>(
    capabilities[0],
  );

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

      <div className="relative mx-auto mt-20 max-w-5xl sm:mt-24">
        <div className="flex flex-wrap items-end justify-between gap-x-12 gap-y-6">
          <h2
            className="max-w-2xl text-3xl font-bold tracking-normal text-foreground sm:text-4xl lg:text-5xl"
            style={{ lineHeight: 1.08 }}
          >
            Everything a tunnel needs.{" "}
            <span className="text-text-muted">Nothing to sign up for.</span>
          </h2>
          <p className="flex flex-col text-sm leading-6 text-text-muted">
            Want the full matrix?
            <a
              href="https://gosuda.github.io/portal-tunnel/features"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-11 items-center gap-1 font-semibold text-primary underline-offset-4 hover:underline"
            >
              Feature inventory
              <ChevronRight aria-hidden="true" className="size-4" />
            </a>
          </p>
        </div>

        <div
          role="radiogroup"
          aria-label="Capabilities"
          className="mt-16 grid grid-cols-3 gap-y-6 sm:mt-20 sm:grid-cols-6"
        >
          {capabilities.map((capability) => (
            <label
              key={capability.label}
              className="group flex cursor-pointer flex-col items-center gap-3.5 rounded-xl py-2 text-sm font-semibold text-text-muted transition-colors hover:text-foreground has-checked:text-foreground has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-ring"
            >
              <input
                type="radio"
                name="capability"
                checked={capability === active}
                onChange={() => setActive(capability)}
                className="sr-only"
              />
              <capability.icon
                aria-hidden="true"
                strokeWidth={1.25}
                className="size-11 transition-[color,translate] duration-300 group-hover:-translate-y-0.5 group-has-checked:text-primary motion-reduce:transition-none motion-reduce:group-hover:translate-y-0"
              />
              {capability.label}
              <span
                aria-hidden="true"
                className="size-1 rounded-full bg-primary opacity-0 transition-opacity group-has-checked:opacity-100"
              />
            </label>
          ))}
        </div>

        <div
          aria-live="polite"
          className="mx-auto mt-12 min-h-56 max-w-2xl text-center"
        >
          {/* Keyed so each pick mounts fresh and fades in from its starting style. */}
          <div
            key={active.label}
            className="duration-500 starting:translate-y-2 starting:opacity-0 motion-safe:transition-[opacity,translate]"
          >
            <h3 className="text-2xl font-bold tracking-normal text-foreground sm:text-3xl">
              {active.title}
            </h3>
            <p className="mx-auto mt-3.5 max-w-[46ch] text-base leading-7 text-text-muted sm:text-lg">
              {active.description}
            </p>
            <a
              href={active.href}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex min-h-11 items-center gap-1 text-primary underline-offset-4 hover:underline"
            >
              Learn more
              <ChevronRight aria-hidden="true" className="size-4" />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
