import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { ApiError } from "./api";
import { category, coverageStatus, explain, failure } from "./labels";

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
  if (query.isError && query.error instanceof ApiError && query.error.status === 404) {
    return <div className="empty">Объект не найден. Возможно, он удалён или принадлежит другой организации.</div>;
  }
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

export function Facts({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="facts">
      {items.map(([term, value]) => (
        <div key={term} style={{ display: "contents" }}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Categories({ ids, tone = "warn" }: { ids: string[]; tone?: string }) {
  if (ids.length === 0) return <span className="muted">—</span>;
  return (
    <div className="chips">
      {ids.map((id) => <span key={id} className={`badge ${tone}`}>{category(id)}</span>)}
    </div>
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
