import type { ReactNode } from "react";
import { Link } from "react-router";

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
        <header className="flex min-h-14 flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-border px-5 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-base font-semibold text-fg">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-fg-2">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={flush ? undefined : "p-5"}>{children}</div>
    </section>
  );
}

// The small capitals over a group: a drawer section, a fieldset, a menu group.
export const groupLabel = "text-xs font-semibold tracking-wide text-fg-3 uppercase";

// A headline number. It links to the list it summarises when there is one, so a
// figure is always a way into its detail.
export function Stat({ label, value, hint, to, tone }: { label: string; value: ReactNode; hint?: ReactNode; to?: string; tone?: "bad" | "warn" }) {
  const body = (
    <>
      <span className="text-xs font-medium text-fg-2">{label}</span>
      <span className={cn("mt-1 text-[1.75rem] leading-9 font-semibold tracking-tight text-fg", tone === "bad" && "text-bad", tone === "warn" && "text-warn")}>{value}</span>
      {hint && <span className="mt-0.5 text-xs text-fg-2">{hint}</span>}
    </>
  );
  const frame = "flex min-w-0 flex-col rounded-lg border border-border bg-surface px-5 py-4";
  if (!to) return <div className={frame}>{body}</div>;
  return (
    <Link to={to} className={cn(frame, "transition-colors hover:border-border-strong hover:bg-surface-2/50")}>
      {body}
    </Link>
  );
}

export function Facts({ items, className }: { items: [string, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(9rem,max-content)_minmax(0,1fr)] gap-x-8 gap-y-3 text-sm", className)}>
      {items.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="text-fg-2">{term}</dt>
          <dd className="min-w-0 break-words text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
