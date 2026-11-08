import { ChevronRight } from "lucide-react";
import { Fragment, type ReactNode } from "react";
import { useLocation } from "react-router";

import { sections } from "../../sections";
import { cn } from "./cn";

export function Breadcrumbs({ items }: { items: ReactNode[] }) {
  if (items.length === 0) return null;
  return (
    <nav aria-label="Где вы" className="flex min-w-0 flex-wrap items-center gap-1.5 text-[13px] text-fg-2">
      {items.map((item, index) => (
        <Fragment key={index}>
          {index > 0 && <ChevronRight aria-hidden className="size-3.5 text-fg-3" />}
          <span className="min-w-0 truncate [&_a]:text-fg-2 [&_a]:transition-colors [&_a:hover]:text-accent">{item}</span>
        </Fragment>
      ))}
    </nav>
  );
}

// The top of every page: where it is, what it is, what can be done on it. A
// section's own page carries the section's icon, as in the navigation.
export function PageHeader({
  title,
  description,
  breadcrumbs = [],
  actions,
  meta,
  mono,
}: {
  title: ReactNode;
  description?: ReactNode;
  breadcrumbs?: ReactNode[];
  actions?: ReactNode;
  meta?: ReactNode;
  mono?: boolean;
}) {
  const { pathname } = useLocation();
  const Icon = breadcrumbs.length === 0 ? sections.find((section) => section.path === pathname)?.icon : undefined;
  return (
    <header className="mb-7 flex flex-col gap-3">
      <Breadcrumbs items={breadcrumbs} />
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-4">
          {Icon && (
            <span aria-hidden className="mt-0.5 hidden size-11 shrink-0 place-items-center rounded-xl border border-border bg-surface text-accent shadow-card sm:grid">
              <Icon className="size-5" />
            </span>
          )}
          <div className="min-w-0">
            <h1 className={cn("text-2xl font-semibold tracking-tight break-words text-fg", mono && "font-mono text-xl")}>{title}</h1>
            {description && <p className="mt-1 max-w-3xl text-sm text-fg-2">{description}</p>}
            {meta && <div className="mt-3 flex flex-wrap items-center gap-2">{meta}</div>}
          </div>
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </header>
  );
}
