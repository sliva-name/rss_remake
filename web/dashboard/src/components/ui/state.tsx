import type { UseQueryResult } from "@tanstack/react-query";
import { AlertTriangle, SearchX } from "lucide-react";
import type { ReactNode } from "react";

import { ApiError } from "../../api";
import { cn } from "./cn";
import { EmptyMark } from "./empty-mark";
import { SuccessMark } from "./success-mark";

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-neutral-bg", className)} />;
}

export function Loading({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div role="status" aria-label="Загрузка" className={cn("flex flex-col gap-2 p-4", className)}>
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className={cn("h-4", index % 2 === 1 ? "w-2/3" : "w-full")} />
      ))}
    </div>
  );
}

// Centred in its block, also when the block is stretched to its row's height.
// "ok" means there is nothing to show because nothing is wrong: it is said as
// good news, not as a gap.
export function EmptyState({ title, children, icon = "empty", action, className }: { title: string; children?: ReactNode; icon?: "empty" | "search" | "ok"; action?: ReactNode; className?: string }) {
  // A mark's circle is half of it; the rest is room for its motion, so the
  // margins pull the text up to where it sits under a plain icon.
  const mark = "-mt-7 -mb-4 size-28";
  return (
    <div className={cn("flex flex-1 flex-col items-center justify-center gap-1.5 px-4 py-10 text-center", className)}>
      {icon === "ok" ? (
        <SuccessMark className={mark} />
      ) : icon === "empty" ? (
        <EmptyMark className={mark} />
      ) : (
        <span aria-hidden className="mb-3 grid size-14 place-items-center rounded-full bg-surface-2 text-fg-3 ring-1 ring-border">
          <SearchX className="size-7" strokeWidth={1.75} />
        </span>
      )}
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <div className="max-w-md text-sm text-fg-2">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function errorText(error: Error): string {
  if (error instanceof ApiError && error.status === 404) return "Объект не найден. Возможно, он удалён или принадлежит другой организации.";
  if (error instanceof ApiError && error.status === 403) return "Недостаточно прав для просмотра.";
  return `Не удалось загрузить: ${error.message}`;
}

export function ErrorState({ error, className }: { error: Error; className?: string }) {
  return (
    <div role="alert" className={cn("flex items-start gap-2 px-4 py-6 text-sm text-bad", className)}>
      <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0" />
      <span>{errorText(error)}</span>
    </div>
  );
}

// Loading, error and empty states of a query, the same way on every page.
export function Loadable<T>({
  query,
  empty,
  isEmpty,
  loading,
  children,
}: {
  query: UseQueryResult<T>;
  empty?: ReactNode;
  isEmpty?: (data: T) => boolean;
  loading?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <>{loading ?? <Loading />}</>;
  if (query.isError) return <ErrorState error={query.error} />;
  if (isEmpty?.(query.data)) return <>{empty ?? <EmptyState title="Нет данных" />}</>;
  return <>{children(query.data)}</>;
}
