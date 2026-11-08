import { cn } from "./cn";

const line = { stroke: "var(--text-3)", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" } as const;

// Nothing here yet, said calmly: an empty tray that draws itself, into which a
// sheet now and then sinks out of sight, the way things will arrive once there
// are any. Neutral greys from the tokens; with reduced motion asked for, it is
// a still tray.
export function EmptyMark({ className }: { className?: string }) {
  return (
    <svg aria-hidden viewBox="0 0 100 100" className={cn("overflow-visible", className)}>
      <circle cx="50" cy="50" r="25" style={{ fill: "var(--surface-2)", stroke: "var(--border)", strokeWidth: 1 }} />
      <g className="empty-sheet">
        <rect x="44.5" y="31" width="11" height="14" rx="1.5" style={{ fill: "var(--surface)", ...line, strokeWidth: 1.6, strokeDasharray: "2.2 2" }} />
        <path d="M47.2 35.5h5.6M47.2 38.5h3.8" style={{ ...line, strokeWidth: 1.4 }} />
      </g>
      <g className="empty-tray">
        <path d="M37 53 41.5 43.5C42 42.6 42.7 42 43.8 42H56.2C57.3 42 58 42.6 58.5 43.5L63 53" pathLength={1} fill="none" style={line} className="mark-draw" />
        <path
          d="M37 53H44.5L46.5 56.5H53.5L55.5 53H63V60C63 61.1 62.1 62 61 62H39C37.9 62 37 61.1 37 60Z"
          pathLength={1}
          style={{ ...line, fill: "var(--surface-2)" }}
          className="mark-draw [animation-delay:0.2s]"
        />
      </g>
    </svg>
  );
}
