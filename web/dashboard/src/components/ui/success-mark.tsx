import { type CSSProperties, useId } from "react";

import { cn } from "./cn";

// A four-pointed sparkle, 8 units across.
const sparkle = "M0 4C2.4 4 4 2.4 4 0C4 2.4 5.6 4 8 4C5.6 4 4 5.6 4 8C4 5.6 2.4 4 0 4Z";

// Each sparkle leaves the circle along its own ray: angle in degrees, distance
// from the centre where it appears, how far it drifts, its scale at the start
// and at the end, and when in the cycle it shows.
const sparkles: [number, number, number, number, number, number][] = [
  [-60, 28, 14, 0.6, 1.2, 0.2],
  [20, 27, 16, 1.1, 0.5, 1.1],
  [140, 28, 13, 0.9, 1.3, 1.9],
  [210, 27, 15, 1.2, 0.4, 2.6],
  [-110, 28, 12, 0.5, 1, 3.3],
  [70, 28, 14, 1, 0.6, 4],
  [-20, 27, 17, 0.8, 1.4, 4.8],
  [175, 28, 15, 0.7, 1.1, 5.5],
  [110, 27, 13, 1.3, 0.7, 6.2],
  [-150, 27, 16, 0.9, 0.5, 0.7],
  [40, 28, 12, 0.6, 1.2, 3],
  [250, 27, 14, 1.1, 0.9, 5],
];

// The sparkles start once the circle and the check are drawn.
const drawn = 0.9;

// Good news as a mark that draws itself and gives off a few sparkles. Colours
// come from the ok token, so it suits both themes; with reduced motion asked
// for, it is a still circle with a check.
export function SuccessMark({ className }: { className?: string }) {
  const gradient = `success-${useId()}`;
  return (
    <svg aria-hidden viewBox="0 0 100 100" className={cn("overflow-visible", className)}>
      <defs>
        <linearGradient id={gradient} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" style={{ stopColor: "color-mix(in srgb, var(--ok) 60%, white)" }} />
          <stop offset="100%" style={{ stopColor: "var(--ok)" }} />
        </linearGradient>
      </defs>
      <circle cx="50" cy="50" r="25" style={{ fill: "var(--ok-bg)" }} />
      <circle
        cx="50" cy="50" r="25" pathLength={1} transform="rotate(-90 50 50)"
        fill="none" stroke={`url(#${gradient})`} strokeWidth="2.2" strokeLinecap="round"
        className="mark-draw"
      />
      <path
        d="M41.5 50.8 47.3 56.5 59.8 44" pathLength={1}
        fill="none" stroke={`url(#${gradient})`} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"
        className="mark-draw [animation-delay:0.45s]"
      />
      {sparkles.map(([angle, from, travel, scaleFrom, scaleTo, delay]) => {
        const radians = (angle * Math.PI) / 180;
        const x = 50 + from * Math.cos(radians) - 4;
        const y = 50 + from * Math.sin(radians) - 4;
        const style = {
          fill: "color-mix(in srgb, var(--ok) 85%, white)",
          "--dx": `${(travel * Math.cos(radians)).toFixed(2)}px`,
          "--dy": `${(travel * Math.sin(radians)).toFixed(2)}px`,
          "--from": scaleFrom,
          "--to": scaleTo,
          animationDelay: `${drawn + delay}s`,
        } as CSSProperties;
        return (
          <g key={angle} transform={`translate(${x.toFixed(2)} ${y.toFixed(2)})`}>
            <path d={sparkle} className="success-sparkle" style={style} />
          </g>
        );
      })}
    </svg>
  );
}
