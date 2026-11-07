import { useId } from "react";

// Stars sit in the full-width backdrop; coordinates use the 1672x520 viewBox.
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

// rgb(var(--stage-<token>) / alpha), for SVG styles and Tailwind arbitrary values.
const stage = (token: string, alpha = 1) => `rgb(var(--stage-${token}) / ${alpha})`;

// Glows and stars for the directory background.
export function HeroBackdropSVG() {
  const uid = useId().replace(/:/g, "");
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1672 520"
      aria-hidden="true"
      className="h-[520px] w-[1672px] shrink-0"
    >
      <defs>
        <radialGradient id={`${uid}-cta-glow`} cx="265" cy="292" r="220" gradientUnits="userSpaceOnUse">
          <stop offset="0%" style={{ stopColor: stage("accent", 0.28) }} />
          <stop offset="55%" style={{ stopColor: stage("accent-2", 0.09) }} />
          <stop offset="100%" style={{ stopColor: stage("accent-2", 0) }} />
        </radialGradient>
      </defs>
      <circle cx="265" cy="292" r="220" fill={`url(#${uid}-cta-glow)`} style={{ opacity: "var(--stage-glow)" }} />
      <g style={{ fill: stage("star") }}>
        {STARS.map((star, idx) => (
          <circle key={idx} cx={star.cx} cy={star.cy} r={star.r} opacity={star.o} />
        ))}
      </g>
    </svg>
  );
}

