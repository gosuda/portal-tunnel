import { useId } from "react";
import { ArrowRight, BookOpen, Zap } from "lucide-react";
import { TunnelCommandModal } from "@/components/TunnelCommandModal";

const STARS: ReadonlyArray<{ cx: number; cy: number; r: number; o: number }> = [
  { cx: 68, cy: 42, r: 0.9, o: 0.45 },
  { cx: 142, cy: 76, r: 0.7, o: 0.35 },
  { cx: 295, cy: 38, r: 0.8, o: 0.4 },
  { cx: 468, cy: 62, r: 0.9, o: 0.45 },
  { cx: 582, cy: 28, r: 0.7, o: 0.35 },
  { cx: 695, cy: 84, r: 1.0, o: 0.5 },
  { cx: 786, cy: 46, r: 0.8, o: 0.4 },
  { cx: 862, cy: 112, r: 0.9, o: 0.45 },
  { cx: 914, cy: 152, r: 1.1, o: 0.65 },
  { cx: 954, cy: 68, r: 0.8, o: 0.5 },
  { cx: 1012, cy: 124, r: 1.2, o: 0.7 },
  { cx: 1048, cy: 82, r: 0.9, o: 0.55 },
  { cx: 1082, cy: 44, r: 1.0, o: 0.6 },
  { cx: 1384, cy: 52, r: 1.1, o: 0.65 },
  { cx: 1446, cy: 78, r: 0.8, o: 0.45 },
  { cx: 1518, cy: 192, r: 1.0, o: 0.55 },
  { cx: 1564, cy: 128, r: 0.8, o: 0.4 },
  { cx: 1612, cy: 224, r: 0.9, o: 0.5 },
  { cx: 966, cy: 298, r: 0.8, o: 0.45 },
  { cx: 1054, cy: 318, r: 1.0, o: 0.55 },
];

const OUTGOING_BEAMS: ReadonlyArray<{
  d: string;
  nx: number;
  ny: number;
  color: string;
}> = [
  { d: "M 1166,180 Q 1206,120 1264,95", nx: 1264, ny: 95, color: "#67f9f0" },
  { d: "M 1170,185 Q 1264,112 1388,128", nx: 1388, ny: 128, color: "#7dd3fc" },
  { d: "M 1172,191 Q 1252,148 1330,174", nx: 1330, ny: 174, color: "#5eead4" },
  { d: "M 1172,198 Q 1295,192 1418,278", nx: 1418, ny: 278, color: "#67e8f9" },
  { d: "M 1170,204 Q 1258,216 1338,286", nx: 1338, ny: 286, color: "#5eead4" },
  { d: "M 1166,210 Q 1206,224 1246,252", nx: 1246, ny: 252, color: "#67f9f0" },
];

function HeroSceneSVG({
  viewBox = "0 0 1672 360",
  className = "h-full w-full",
}: {
  viewBox?: string;
  className?: string;
}) {
  const uid = useId().replace(/:/g, "");

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={viewBox}
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      className={className}
    >
      <defs>
        <radialGradient id={`${uid}-cta-glow`} cx="265" cy="292" r="220" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.28" />
          <stop offset="55%" stopColor="#0ea5e9" stopOpacity="0.09" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-portal-halo`} cx="1155" cy="196" r="230" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38f9f0" stopOpacity="0.46" />
          <stop offset="38%" stopColor="#0ea5e9" stopOpacity="0.24" />
          <stop offset="72%" stopColor="#3b82f6" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-globe-nebula`} cx="1256" cy="188" r="250" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4f46e5" stopOpacity="0.38" />
          <stop offset="45%" stopColor="#2563eb" stopOpacity="0.24" />
          <stop offset="78%" stopColor="#0ea5e9" stopOpacity="0.09" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-corner-flare`} cx="1578" cy="352" r="130" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5efce8" stopOpacity="0.52" />
          <stop offset="42%" stopColor="#22d3ee" stopOpacity="0.2" />
          <stop offset="100%" stopColor="#020c1b" stopOpacity="0" />
        </radialGradient>

        <radialGradient id={`${uid}-sphere-fill`} cx="1185" cy="142" r="210" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0d3b6e" />
          <stop offset="42%" stopColor="#112255" />
          <stop offset="78%" stopColor="#091336" />
          <stop offset="100%" stopColor="#030a1c" />
        </radialGradient>

        <linearGradient id={`${uid}-sphere-rim`} x1="1090" y1="60" x2="1385" y2="310" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5efce8" stopOpacity="0.95" />
          <stop offset="36%" stopColor="#38bdf8" stopOpacity="0.75" />
          <stop offset="72%" stopColor="#818cf8" stopOpacity="0.65" />
          <stop offset="100%" stopColor="#1e1b4b" stopOpacity="0.15" />
        </linearGradient>

        <linearGradient id={`${uid}-continent-tint`} x1="1090" y1="70" x2="1390" y2="300" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#67f9f0" />
          <stop offset="45%" stopColor="#60a5fa" />
          <stop offset="100%" stopColor="#a78bfa" />
        </linearGradient>

        <linearGradient id={`${uid}-ring-stroke`} x1="1134" y1="130" x2="1177" y2="262" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#5efce8" />
          <stop offset="32%" stopColor="#ffffff" />
          <stop offset="68%" stopColor="#60a5fa" />
          <stop offset="100%" stopColor="#a5b4fc" />
        </linearGradient>

        <linearGradient id={`${uid}-beam-grad`} x1="1155" y1="196" x2="1420" y2="210" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
          <stop offset="30%" stopColor="#5efce8" stopOpacity="0.9" />
          <stop offset="75%" stopColor="#38bdf8" stopOpacity="0.75" />
          <stop offset="100%" stopColor="#818cf8" stopOpacity="0.85" />
        </linearGradient>

        <linearGradient id={`${uid}-left-trail`} x1="680" y1="305" x2="1152" y2="202" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0" />
          <stop offset="45%" stopColor="#22d3ee" stopOpacity="0.38" />
          <stop offset="85%" stopColor="#5efce8" stopOpacity="0.85" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="0.98" />
        </linearGradient>

        <pattern
          id={`${uid}-dots`}
          x="0"
          y="0"
          width="4.2"
          height="4.2"
          patternUnits="userSpaceOnUse"
        >
          <circle cx="2.1" cy="2.1" r="1.2" fill="#ffffff" />
        </pattern>

        <mask id={`${uid}-continent-mask`}>
          <rect x="1070" y="30" width="340" height="330" fill="black" />
          <g fill={`url(#${uid}-dots)`}>
            {/* North & Central America */}
            <path d="M1102,115 C1112,92 1138,76 1168,78 C1184,82 1192,98 1182,116 C1172,134 1154,142 1146,158 C1138,172 1152,186 1164,196 L1152,204 C1134,192 1118,174 1108,154 Z" />
            {/* Greenland & Northern Islands */}
            <path d="M1176,54 C1194,48 1218,52 1228,64 C1222,76 1204,82 1186,76 Z" />
            {/* South America */}
            <path d="M1168,208 C1186,206 1208,218 1216,238 C1224,258 1214,288 1198,318 C1186,332 1176,326 1174,304 C1172,276 1162,242 1168,208 Z" />
            {/* Europe & Scandinavia */}
            <path d="M1238,72 C1262,62 1294,68 1312,84 C1318,102 1304,122 1286,134 C1266,142 1244,138 1236,122 C1230,106 1232,86 1238,72 Z" />
            {/* Africa */}
            <path d="M1238,152 C1264,146 1296,156 1316,178 C1332,202 1328,242 1308,278 C1294,298 1276,296 1268,274 C1258,244 1232,192 1238,152 Z" />
            {/* Asia */}
            <path d="M1308,82 C1338,78 1368,96 1384,128 C1394,158 1386,196 1364,222 C1346,216 1328,194 1318,166 C1308,138 1302,104 1308,82 Z" />
          </g>
        </mask>

        <clipPath id={`${uid}-globe-clip`}>
          <circle cx="1236" cy="195" r="154" />
        </clipPath>

        <filter id={`${uid}-glow-strong`} x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="8" result="blur1" />
          <feGaussianBlur stdDeviation="3" result="blur2" />
          <feMerge>
            <feMergeNode in="blur1" />
            <feMergeNode in="blur2" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        <filter id={`${uid}-glow-soft`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Cosmic Background Glows */}
      <rect width="1672" height="360" fill="#020c1b" />
      <circle cx="265" cy="292" r="220" fill={`url(#${uid}-cta-glow)`} />
      <circle cx="1256" cy="188" r="250" fill={`url(#${uid}-globe-nebula)`} />
      <circle cx="1155" cy="196" r="230" fill={`url(#${uid}-portal-halo)`} />
      <circle cx="1578" cy="352" r="130" fill={`url(#${uid}-corner-flare)`} />

      {/* Bottom-Right Lens Flare Rays */}
      <g stroke="#5efce8" strokeOpacity="0.28" strokeWidth="1">
        <line x1="1510" y1="360" x2="1625" y2="318" />
        <line x1="1548" y1="360" x2="1604" y2="305" />
      </g>

      {/* Starfield */}
      <g fill="#e0f2fe">
        {STARS.map((star, idx) => (
          <circle
            key={idx}
            cx={star.cx}
            cy={star.cy}
            r={star.r}
            opacity={star.o}
          />
        ))}
      </g>

      {/* 3D Globe */}
      <g clipPath={`url(#${uid}-globe-clip)`}>
        <circle cx="1236" cy="195" r="154" fill={`url(#${uid}-sphere-fill)`} />

        {/* Subtle Graticule Lines */}
        <g fill="none" stroke="#38bdf8" strokeOpacity="0.11" strokeWidth="0.9">
          <ellipse cx="1236" cy="195" rx="154" ry="52" />
          <ellipse cx="1236" cy="195" rx="154" ry="108" />
          <ellipse cx="1236" cy="195" rx="56" ry="154" />
          <ellipse cx="1236" cy="195" rx="112" ry="154" />
          <line x1="1082" y1="195" x2="1390" y2="195" />
          <line x1="1236" y1="41" x2="1236" y2="349" />
        </g>

        {/* Dotted World Continents */}
        <rect
          x="1080"
          y="40"
          width="315"
          height="310"
          fill={`url(#${uid}-continent-tint)`}
          mask={`url(#${uid}-continent-mask)`}
          opacity="0.88"
        />

        {/* Inner Atmospheric Horizon Glow */}
        <circle
          cx="1236"
          cy="195"
          r="153"
          fill="none"
          stroke={`url(#${uid}-sphere-rim)`}
          strokeWidth="4.5"
          opacity="0.7"
        />
      </g>

      {/* Outer Globe Rim Highlight Arc */}
      <path
        d="M 1104,116 A 154,154 0 0,1 1378,136"
        fill="none"
        stroke="#5efce8"
        strokeWidth="2.2"
        strokeLinecap="round"
        filter={`url(#${uid}-glow-soft)`}
        opacity="0.85"
      />

      {/* Sweeping Left Incoming Light Trails */}
      <path
        d="M 650,304 Q 930,300 1148,206"
        fill="none"
        stroke={`url(#${uid}-left-trail)`}
        strokeWidth="2.4"
        filter={`url(#${uid}-glow-soft)`}
      />
      <path
        d="M 900,152 Q 1045,156 1146,192"
        fill="none"
        stroke={`url(#${uid}-left-trail)`}
        strokeWidth="1.3"
        opacity="0.55"
      />
      <path
        d="M 1075,220 C 1104,220 1124,212 1146,200"
        fill="none"
        stroke="#5efce8"
        strokeWidth="2.6"
        filter={`url(#${uid}-glow-soft)`}
      />

      {/* Outgoing Relay Beams & Glowing Nodes */}
      <g filter={`url(#${uid}-glow-soft)`}>
        {OUTGOING_BEAMS.map((beam, idx) => (
          <g key={idx}>
            <path
              d={beam.d}
              fill="none"
              stroke={`url(#${uid}-beam-grad)`}
              strokeWidth="2.1"
              strokeLinecap="round"
            />
            <circle cx={beam.nx} cy={beam.ny} r="5.5" fill={beam.color} opacity="0.38" />
            <circle cx={beam.nx} cy={beam.ny} r="2.7" fill="#ffffff" />
          </g>
        ))}
      </g>

      {/* Glowing Portal Ring */}
      <g transform="rotate(5 1155 196)">
        {/* Outer Neon Bloom */}
        <ellipse
          cx="1155"
          cy="196"
          rx="22"
          ry="64.5"
          fill="none"
          stroke="#22d3ee"
          strokeWidth="10"
          opacity="0.65"
          filter={`url(#${uid}-glow-strong)`}
        />
        {/* Portal Void Interior */}
        <ellipse
          cx="1155"
          cy="196"
          rx="17.5"
          ry="59.5"
          fill="#030d1e"
          fillOpacity="0.94"
        />
        {/* Main Beveled Ring */}
        <ellipse
          cx="1155"
          cy="196"
          rx="20.5"
          ry="63.5"
          fill="none"
          stroke={`url(#${uid}-ring-stroke)`}
          strokeWidth="5.5"
          filter={`url(#${uid}-glow-soft)`}
        />
        {/* Crisp White Inner Core */}
        <ellipse
          cx="1155"
          cy="196"
          rx="20.5"
          ry="63.5"
          fill="none"
          stroke="#ffffff"
          strokeWidth="1.8"
          opacity="0.92"
        />
      </g>
    </svg>
  );
}

function CalloutLaptopIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[26px] w-[26px] shrink-0" aria-hidden="true">
      <rect
        x="4"
        y="5"
        width="20"
        height="13.5"
        rx="2.2"
        fill="#1e3a8a"
        stroke="#93c5fd"
        strokeWidth="1.6"
      />
      <rect x="6.2" y="7.2" width="15.6" height="9" rx="1" fill="#3b82f6" fillOpacity="0.35" />
      <path
        d="M2,20.2 L26,20.2 L24.2,23 L3.8,23 Z"
        fill="#60a5fa"
        stroke="#bae6fd"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CalloutRelaysIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[25px] w-[25px] shrink-0" aria-hidden="true">
      {[5, 11.5, 18].map((y, idx) => (
        <g key={idx}>
          <rect
            x="4"
            y={y}
            width="20"
            height="5"
            rx="1.5"
            fill="#312e81"
            stroke="#a5b4fc"
            strokeWidth="1.4"
          />
          <circle cx="7.5" cy={y + 2.5} r="1" fill="#67e8f9" />
          <circle cx="10.8" cy={y + 2.5} r="1" fill="#a5b4fc" />
          <line
            x1="15"
            y1={y + 2.5}
            x2="21"
            y2={y + 2.5}
            stroke="#c7d2fe"
            strokeWidth="1.3"
            strokeLinecap="round"
          />
        </g>
      ))}
    </svg>
  );
}

function CalloutPublicAccessIcon() {
  return (
    <svg viewBox="0 0 28 28" className="h-[25px] w-[25px] shrink-0" aria-hidden="true">
      <circle cx="9" cy="11.5" r="3" fill="#6366f1" stroke="#a5b4fc" strokeWidth="1.2" />
      <path
        d="M3.5,21 C3.5,17.8 6,15.8 9,15.8 C12,15.8 14.5,17.8 14.5,21"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <circle cx="19.5" cy="11.5" r="2.8" fill="#6366f1" stroke="#a5b4fc" strokeWidth="1.2" />
      <path
        d="M14.5,21 C14.5,18 16.8,16 19.5,16 C22.2,16 24.5,18 24.5,21"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="1.2"
        strokeLinecap="round"
      />
      <circle cx="14.2" cy="9.5" r="3.4" fill="#818cf8" stroke="#e0e7ff" strokeWidth="1.3" />
      <path
        d="M8,22 C8,18.2 10.8,15.8 14.2,15.8 C17.6,15.8 20.4,18.2 20.4,22"
        fill="#6366f1"
        stroke="#e0e7ff"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function HeroBackdropGraphic() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 hidden justify-center overflow-hidden lg:flex"
    >
      <div className="relative h-[360px] w-[1672px] shrink-0">
        <HeroSceneSVG viewBox="0 0 1672 360" className="h-full w-full" />

        {/* Callout 1: Your machine (localhost) */}
        <div className="absolute top-[192px] left-[918px] flex h-[57px] w-[157px] items-center gap-[11px] whitespace-nowrap rounded-[12px] border border-[#38bdf8]/40 bg-[#07162c]/85 px-[13px] shadow-[0_0_24px_rgba(34,211,238,0.18)] backdrop-blur-md">
          <CalloutLaptopIcon />
          <div className="leading-[1.25]">
            <p className="text-[12.5px] font-bold text-white">Your machine</p>
            <p className="text-[11.5px] font-medium text-[#94a3b8]">(localhost)</p>
          </div>
        </div>

        {/* Callout 2: Global relays worldwide */}
        <div className="absolute top-[102px] left-[1389px] flex h-[57px] w-[144px] items-center gap-[10px] whitespace-nowrap rounded-[12px] border border-[#818cf8]/40 bg-[#0b152e]/85 px-[12px] shadow-[0_0_22px_rgba(99,102,241,0.2)] backdrop-blur-md">
          <CalloutRelaysIcon />
          <div className="leading-[1.25]">
            <p className="text-[12.5px] font-bold text-white">Global relays</p>
            <p className="text-[11.5px] font-medium text-[#94a3b8]">worldwide</p>
          </div>
        </div>

        {/* Callout 3: Public access for everyone */}
        <div className="absolute top-[260px] left-[1430px] flex h-[55px] w-[144px] items-center gap-[10px] whitespace-nowrap rounded-[12px] border border-[#818cf8]/40 bg-[#0b152e]/85 px-[12px] shadow-[0_0_22px_rgba(99,102,241,0.2)] backdrop-blur-md">
          <CalloutPublicAccessIcon />
          <div className="leading-[1.25]">
            <p className="text-[12.5px] font-bold text-white">Public access</p>
            <p className="text-[11.5px] font-medium text-[#94a3b8]">for everyone</p>
          </div>
        </div>
      </div>
    </div>
  );
}

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

        {/* Responsive Vector Graphic Stage for Tablet & Mobile (< lg) */}
        <div className="mt-6 flex justify-center lg:hidden">
          <div className="relative aspect-[710/320] w-full max-w-[620px] overflow-hidden rounded-xl border border-white/10 bg-[#020c1b]">
            <HeroSceneSVG viewBox="890 30 710 320" className="h-full w-full" />

            <div className="absolute top-[50%] left-[4%] flex items-center gap-2 rounded-lg border border-[#38bdf8]/40 bg-[#07162c]/85 px-2.5 py-1.5 shadow-[0_0_18px_rgba(34,211,238,0.18)] backdrop-blur-md sm:gap-2.5 sm:px-3 sm:py-2">
              <CalloutLaptopIcon />
              <div className="leading-tight">
                <p className="text-[10px] font-bold text-white sm:text-xs">Your machine</p>
                <p className="text-[9px] font-medium text-[#94a3b8] sm:text-[11px]">(localhost)</p>
              </div>
            </div>

            <div className="absolute top-[22%] right-[3%] flex items-center gap-2 rounded-lg border border-[#818cf8]/40 bg-[#0b152e]/85 px-2.5 py-1.5 shadow-[0_0_18px_rgba(99,102,241,0.2)] backdrop-blur-md sm:gap-2.5 sm:px-3 sm:py-2">
              <CalloutRelaysIcon />
              <div className="leading-tight">
                <p className="text-[10px] font-bold text-white sm:text-xs">Global relays</p>
                <p className="text-[9px] font-medium text-[#94a3b8] sm:text-[11px]">worldwide</p>
              </div>
            </div>

            <div className="absolute right-[2%] bottom-[6%] flex items-center gap-2 rounded-lg border border-[#818cf8]/40 bg-[#0b152e]/85 px-2.5 py-1.5 shadow-[0_0_18px_rgba(99,102,241,0.2)] backdrop-blur-md sm:gap-2.5 sm:px-3 sm:py-2">
              <CalloutPublicAccessIcon />
              <div className="leading-tight">
                <p className="text-[10px] font-bold text-white sm:text-xs">Public access</p>
                <p className="text-[9px] font-medium text-[#94a3b8] sm:text-[11px]">for everyone</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
