import { useId, useMemo, type JSX } from "react";
import type { BaseServer } from "@/lib/server";
import { createConstellationData } from "./constellation";

export function DefaultServerThumbnail({ server }: { server: BaseServer }): JSX.Element {
  const seed = (server.address || server.name || server.id || "portal").trim();
  const data = useMemo(() => createConstellationData(seed), [seed]);
  const nebulaId = useId();
  const skyGradId = useId();
  const starGlowId = useId();

  return (
    <div
      className="absolute inset-0 select-none overflow-hidden bg-[#040711] transition-transform duration-300 ease-out motion-safe:group-hover:scale-[1.02]"
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 320 180"
        className="h-full w-full object-cover"
        preserveAspectRatio="xMidYMid slice"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id={skyGradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#040711" />
            <stop offset="48%" stopColor="#081020" />
            <stop offset="100%" stopColor="#0c172e" />
          </linearGradient>

          <radialGradient id={nebulaId} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={`hsl(${data.nebulaHue}, 50%, 28%)`} stopOpacity="0.32" />
            <stop offset="60%" stopColor={`hsl(${data.nebulaHue}, 45%, 16%)`} stopOpacity="0.12" />
            <stop offset="100%" stopColor="#040711" stopOpacity="0" />
          </radialGradient>

          <radialGradient id={starGlowId} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
            <stop offset="35%" stopColor="#bae6fd" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </radialGradient>
        </defs>

        <rect width="320" height="180" fill={`url(#${skyGradId})`} />

        <ellipse
          cx={data.nebulaCx}
          cy={data.nebulaCy}
          rx={150}
          ry={95}
          fill={`url(#${nebulaId})`}
        />

        <g fill="#f8fafc">
          {data.bgStars.map((s, idx) => (
            <circle
              key={`bg-${idx}`}
              cx={s.cx}
              cy={s.cy}
              r={s.r}
              opacity={s.opacity}
            />
          ))}
        </g>

        <g stroke="#bae6fd" strokeWidth="1" strokeLinecap="round">
          {data.lines.map((line, idx) => (
            <line
              key={`line-${idx}`}
              x1={line.x1}
              y1={line.y1}
              x2={line.x2}
              y2={line.y2}
              strokeOpacity={line.opacity}
            />
          ))}
        </g>

        {data.stars.map((star, idx) => (
          <g key={`star-${idx}`}>
            {star.isPrimary && (
              <>
                <circle
                  cx={star.x}
                  cy={star.y}
                  r={star.r * 2.8}
                  fill={`url(#${starGlowId})`}
                  opacity="0.4"
                />
                <line
                  x1={star.x - star.r * 3.5}
                  y1={star.y}
                  x2={star.x + star.r * 3.5}
                  y2={star.y}
                  stroke="#ffffff"
                  strokeWidth="0.65"
                  strokeOpacity="0.65"
                />
                <line
                  x1={star.x}
                  y1={star.y - star.r * 3.5}
                  x2={star.x}
                  y2={star.y + star.r * 3.5}
                  stroke="#ffffff"
                  strokeWidth="0.65"
                  strokeOpacity="0.65"
                />
              </>
            )}

            <circle
              cx={star.x}
              cy={star.y}
              r={star.r + 0.6}
              fill="#bae6fd"
              opacity="0.35"
            />

            <circle
              cx={star.x}
              cy={star.y}
              r={star.r}
              fill="#ffffff"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}
