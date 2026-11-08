import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { cn } from "./cn";

// A titled block of a page. The body has no padding of its own when it holds a
// table, so rows run edge to edge like in a list.
export function Panel({
  title,
  description,
  actions,
  flush,
  className,
  children,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  flush?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("min-w-0 rounded-lg border border-border bg-surface", className)}>
      {(title || actions) && (
        <header className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border px-4 py-2">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-fg">{title}</h2>}
            {description && <p className="text-xs text-fg-2">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={flush ? undefined : "p-4"}>{children}</div>
    </section>
  );
}

// A headline number. It links to the list it summarises when there is one, so a
// figure is always a way into its detail.
export function Stat({ label, value, hint, to, tone }: { label: string; value: ReactNode; hint?: ReactNode; to?: string; tone?: "bad" | "warn" }) {
  const body = (
    <>
      <span className="text-xs font-medium text-fg-2">{label}</span>
      <span className={cn("text-2xl font-semibold tracking-tight text-fg", tone === "bad" && "text-bad", tone === "warn" && "text-warn")}>{value}</span>
      {hint && <span className="text-xs text-fg-2">{hint}</span>}
    </>
  );
  const frame = "flex min-w-0 flex-col gap-0.5 rounded-lg border border-border bg-surface px-4 py-3";
  if (!to) return <div className={frame}>{body}</div>;
  return (
    <Link to={to} className={cn(frame, "transition-colors hover:border-border-strong hover:bg-surface-2/50")}>
      {body}
    </Link>
  );
}

export function Facts({ items, className }: { items: [string, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(8rem,max-content)_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm", className)}>
      {items.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="text-fg-2">{term}</dt>
          <dd className="min-w-0 break-words text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
