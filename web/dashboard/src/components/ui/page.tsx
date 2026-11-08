import { ChevronRight } from "lucide-react";
import { Fragment, type ReactNode } from "react";

import { cn } from "./cn";

export function Breadcrumbs({ items }: { items: ReactNode[] }) {
  if (items.length === 0) return null;
  return (
    <nav aria-label="Где вы" className="flex min-w-0 flex-wrap items-center gap-1 text-[13px] text-fg-2">
      {items.map((item, index) => (
        <Fragment key={index}>
          {index > 0 && <ChevronRight aria-hidden className="size-3.5 text-fg-3" />}
          <span className="min-w-0 truncate [&_a]:text-fg-2 [&_a:hover]:text-fg">{item}</span>
        </Fragment>
      ))}
    </nav>
  );
}

// The top of every page: where it is, what it is, what can be done on it.
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
  return (
    <header className="mb-5 flex flex-col gap-2">
      <Breadcrumbs items={breadcrumbs} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className={cn("text-xl font-semibold tracking-tight break-words text-fg", mono && "font-mono text-lg")}>{title}</h1>
          {description && <p className="mt-0.5 max-w-3xl text-sm text-fg-2">{description}</p>}
          {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </header>
  );
}
