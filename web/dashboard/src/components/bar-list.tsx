import type { ReactNode } from "react";

import { count } from "../labels";

// A ranked list with proportional bars: who or what leads, at a glance, with
// the exact number beside each bar.
export function BarList({ items, empty }: { items: { key: string; label: ReactNode; value: number; hint?: ReactNode }[]; empty: ReactNode }) {
  if (items.length === 0) return <>{empty}</>;
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <ul className="flex flex-col gap-2.5">
      {items.map((item) => (
        <li key={item.key} className="flex flex-col gap-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate">{item.label}</span>
            <span className="shrink-0 font-medium text-fg tabular-nums">{count(item.value)}</span>
          </div>
          <div aria-hidden className="h-1.5 overflow-hidden rounded-full bg-neutral-bg">
            <div className="h-full rounded-full bg-chart-1" style={{ width: `${Math.max(2, (item.value / max) * 100)}%` }} />
          </div>
          {item.hint && <div className="text-xs text-fg-3">{item.hint}</div>}
        </li>
      ))}
    </ul>
  );
}
