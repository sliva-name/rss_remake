import { ArrowUpRight, ChevronRight, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";

import { Button } from "./button";
import { cn } from "./cn";

// The card every block of a page sits on.
export const card = "rounded-xl border border-border bg-surface shadow-card";

// A titled block of a page. The body has no padding of its own when it holds a
// table, so rows run edge to edge like in a list; only then a rule separates
// the title from the rows.
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
    <section className={cn("flex min-w-0 flex-col overflow-hidden", card, className)}>
      {(title || actions) && (
        <header className={cn("flex min-h-14 flex-wrap items-center justify-between gap-x-4 gap-y-2 px-5", flush ? "border-b border-border py-3.5" : "pt-4 pb-1")}>
          <div className="min-w-48 flex-1">
            {title && <h2 className="text-[15px] font-semibold tracking-tight text-fg">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-fg-2">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("flex min-h-0 flex-1 flex-col", !flush && (title || actions ? "px-5 pt-3 pb-5" : "p-5"))}>{children}</div>
    </section>
  );
}

// The way from a block to the whole list it previews, the same in every block.
export function PanelLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Button size="sm" variant="ghost" asChild className="gap-1 pr-2 text-accent hover:bg-accent-bg hover:text-accent">
      <Link to={to}>
        {children}
        <ChevronRight />
      </Link>
    </Button>
  );
}

// The small capitals over a group: a drawer section, a fieldset, a menu group.
export const groupLabel = "text-[11px] font-semibold tracking-[0.08em] text-fg-3 uppercase";

const statTones = {
  plain: { icon: "bg-accent-bg text-accent", value: "text-fg" },
  warn: { icon: "bg-warn-bg text-warn", value: "text-warn" },
  bad: { icon: "bg-bad-bg text-bad", value: "text-bad" },
};

// A headline number. It links to the list it summarises when there is one, so a
// figure is always a way into its detail.
export function Stat({ label, value, hint, to, tone, icon: Icon }: { label: string; value: ReactNode; hint?: ReactNode; to?: string; tone?: "bad" | "warn"; icon?: LucideIcon }) {
  const colors = statTones[tone ?? "plain"];
  const body = (
    <>
      <span className="text-[13px] font-medium text-fg-2">{label}</span>
      <span className="mt-1.5 flex items-center justify-between gap-3">
        <span className={cn("min-w-0 text-[1.875rem] leading-9 font-semibold tracking-tight", colors.value)}>{value}</span>
        {Icon && (
          <span aria-hidden className={cn("grid size-9 shrink-0 place-items-center rounded-lg", colors.icon)}>
            <Icon className="size-[18px]" />
          </span>
        )}
      </span>
      {hint && <span className="mt-1.5 text-xs text-fg-2">{hint}</span>}
      {to && <ArrowUpRight aria-hidden className="absolute top-3 right-3 size-4 text-fg-3 opacity-0 transition-opacity group-hover:opacity-100" />}
    </>
  );
  const frame = cn("group relative flex min-w-0 flex-col px-5 py-4", card);
  if (!to) return <div className={frame}>{body}</div>;
  return (
    <Link to={to} className={cn(frame, "transition-[border-color,box-shadow] hover:border-border-strong hover:shadow-raised")}>
      {body}
    </Link>
  );
}

// Terms and their values. Where the block is wide, terms form a column of one
// width on every block, so values line up from one block to the next; in a
// narrow block, a side panel or a phone, each term stands over its value.
export function Facts({ items, className }: { items: [string, ReactNode][]; className?: string }) {
  return (
    <div className={cn("@container", className)}>
      <dl className="grid gap-y-3 text-sm @sm:grid-cols-[minmax(8rem,13rem)_minmax(0,1fr)] @sm:gap-x-6">
        {items.map(([term, value]) => (
          <div key={term} className="flex min-w-0 flex-col gap-0.5 @sm:contents">
            <dt className="text-fg-2">{term}</dt>
            <dd className="min-w-0 break-words text-fg">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
