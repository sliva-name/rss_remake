import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { coverageStatus, explain, failure } from "./labels";

export function Loadable<T>({
  query,
  empty,
  isEmpty,
  children,
}: {
  query: UseQueryResult<T>;
  empty: string;
  isEmpty?: (data: T) => boolean;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <div className="empty">Загрузка…</div>;
  if (query.isError) return <div className="error">Не удалось загрузить: {query.error.message}</div>;
  if (isEmpty?.(query.data)) return <div className="empty">{empty}</div>;
  return <>{children(query.data)}</>;
}

export function Page({ title, lead, children }: { title: string; lead?: string; children: ReactNode }) {
  return (
    <>
      <h1>{title}</h1>
      <p className="lead">{lead}</p>
      {children}
    </>
  );
}

export function Tile({ value, label }: { value: string; label: string }) {
  return (
    <div className="tile">
      <b>{value}</b>
      <span>{label}</span>
    </div>
  );
}

const coverageTone: Record<string, string> = { OBSERVING: "ok", DEGRADED: "warn", BLIND: "bad", NOT_CONFIGURED: "bad" };

export function CoverageBadge({ status, reason }: { status: string; reason: string }) {
  return (
    <span className={`badge ${coverageTone[status] ?? ""}`} title={reason ? explain(reason) : undefined}>
      {coverageStatus(status)}
    </span>
  );
}

export function Confidence({ value }: { value: number }) {
  return (
    <span className="bar">
      <i>
        <b style={{ width: `${Math.round(value * 100)}%` }} />
      </i>
      {Math.round(value * 100)}%
    </span>
  );
}

// What went wrong and what the operator can do about it.
export function FailureNote({ code }: { code: string }) {
  if (!code) return null;
  const { problem, action } = failure(code);
  return (
    <div className="failure">
      <div className="muted">{problem}</div>
      {action && <div className="hint">{action}</div>}
    </div>
  );
}
