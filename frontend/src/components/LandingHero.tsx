import { ArrowRight, BookOpen, Zap } from "lucide-react";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";

export function LandingHero() {
  return (
    <section
      aria-labelledby="landing-title"
      className="relative"
    >
      <a
        href="#live-servers"
        className="sr-only focus:not-sr-only focus:absolute focus:left-6 focus:top-6 focus:z-20 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground"
      >
        Skip to live servers
      </a>

      <div className="relative z-10 flex flex-col lg:block">
        <div className="w-full min-w-0 max-w-[785px]">
          <div className="inline-flex h-[31px] max-w-full items-center gap-[9px] rounded-full border border-[#283c54] bg-[#071525]/85 px-[12px] backdrop-blur-sm sm:px-[14px]">
            <span
              aria-hidden="true"
              className="h-[7px] w-[7px] shrink-0 rounded-full bg-[#22e58b] shadow-[0_0_8px_#22e58b]"
            />
            <span className="truncate font-mono text-[9.5px] font-medium uppercase tracking-[0.06em] text-[#cbd5e1] sm:text-[10.5px] sm:tracking-[0.09em]">
              OPEN SOURCE &nbsp;·&nbsp; SELF-HOSTABLE &nbsp;·&nbsp; GLOBAL ACCESS
            </span>
          </div>

          <h1
            id="landing-title"
            className="mt-[11px] font-display text-[30px] font-extrabold leading-[1.08] tracking-[-0.025em] text-white sm:text-[44px] lg:text-[55px] lg:whitespace-nowrap"
          >
            <span>Ship locally. </span>
            <span className="bg-linear-to-r from-[#5bf7ea] via-[#3dddf4] to-[#26bae8] bg-clip-text text-transparent">
              Share globally.
            </span>
          </h1>

          <p className="mt-[9px] max-w-[575px] text-[14px] leading-[22px] font-normal text-[#b4c4d8] sm:text-[15.5px] sm:leading-[24px]">
            Expose your local projects to the internet through a global network
            <br className="hidden sm:inline" /> of public relays. Simple, fast, and open source.
          </p>

          <div
            id="quick-start"
            className="mt-[19px] flex flex-col gap-[14px] sm:flex-row sm:items-center"
          >
            <TunnelCommandModal
              trigger={
                <button
                  type="button"
                  className="inline-flex h-[48px] w-full cursor-pointer items-center justify-center gap-[10px] rounded-[10px] bg-linear-to-r from-[#58f9e4] to-[#41d8f5] px-6 text-[14px] font-bold text-[#031322] shadow-[0_0_26px_rgba(72,240,232,0.45)] transition-all hover:brightness-105 sm:w-[231px]"
                >
                  <Zap className="h-[16px] w-[16px] fill-current stroke-[2.2]" />
                  <span>Launch a tunnel</span>
                </button>
              }
            />

            <a
              href="https://gosuda.github.io/portal-tunnel"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-[48px] w-full items-center justify-center gap-[11px] rounded-[10px] border border-[#243b56] bg-[#081629]/80 px-6 text-[14px] font-semibold text-[#e2e8f0] backdrop-blur-sm transition-colors hover:border-[#38bdf8]/50 hover:text-white sm:w-[260px]"
            >
              <BookOpen className="h-[16px] w-[16px] text-[#94a3b8]" />
              <span>View documentation</span>
              <ArrowRight className="ml-0.5 h-[15px] w-[15px] text-[#94a3b8]" />
            </a>
          </div>
        </div>

        <div className="mt-6 flex justify-center lg:hidden">
          <img
            src="/hero-visual.png"
            alt="Your machine (localhost) connected through Portal to global relays worldwide for public access"
            className="w-full max-w-[600px] rounded-xl object-contain"
          />
        </div>
      </div>
    </section>
  );
}
