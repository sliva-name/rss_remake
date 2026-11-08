import { useMemo, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { cn } from "./components/ui/cn";
import { useCan, type Permission } from "./permissions";

export interface EventFilter {
  sourceId?: string;
  tableId?: string;
  columnId?: string;
  principal?: string;
  category?: string;
  eventType?: string;
  period?: string;
}

function search(filter: object): string {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (typeof value === "string" && value !== "") parameters.set(key, value);
  }
  const query = parameters.toString();
  return query ? `?${query}` : "";
}

export const paths = {
  source: (id: string) => `/sources/${id}`,
  agent: (id: string) => `/agents/${id}`,
  table: (id: string) => `/tables/${id}`,
  column: (id: string) => `/columns/${id}`,
  category: (id: string) => `/categories/${encodeURIComponent(id)}`,
  events: (filter: EventFilter) => `/audit${search(filter)}`,
  findings: (filter: { sourceId?: string; category?: string }) => `/classification${search({ tab: "findings", ...filter })}`,
  inventory: (filter: { sourceId?: string; category?: string; sensitive?: string; q?: string }) => `/inventory${search(filter)}`,
  principals: (filter: { period?: string }) => `/principals${search(filter)}`,
  sources: (filter: { tab?: string } = {}) => `/sources${search(filter)}`,
};

export const linkStyle = "text-accent hover:underline underline-offset-2";

// A link the user could not follow is plain text: the page behind it would
// answer 403. The API still decides; this only avoids offering a dead end.
export function ObjectLink({ to, needs, className, children }: { to: string; needs: Permission; className?: string; children: ReactNode }) {
  if (!useCan()(needs)) return <span className={className}>{children}</span>;
  return <Link className={cn(linkStyle, className)} to={to}>{children}</Link>;
}

// A category opens its own page when any of its parts is readable.
export const categoryNeeds: readonly Permission[] = ["listCatalogColumns", "listAccessByPrincipal", "listAuditEvents"];

export function CategoryLink({ id, className, children }: { id: string; className?: string; children: ReactNode }) {
  const can = useCan();
  if (!categoryNeeds.some(can)) return <span className={className}>{children}</span>;
  return <Link className={className} to={paths.category(id)}>{children}</Link>;
}

// Filters live in the address, so a filtered list is a link that can be kept,
// sent or opened in another tab. Changing a filter returns to the first page.
export function useUrlFilters<K extends string>(keys: readonly K[]): [Record<K | "offset", string>, (patch: Partial<Record<K | "offset", string>>) => void] {
  const [parameters, setParameters] = useSearchParams();
  const values = Object.fromEntries([...keys, "offset"].map((key) => [key, parameters.get(key) ?? ""])) as Record<K | "offset", string>;
  const update = (patch: Partial<Record<K | "offset", string>>) => {
    const next = new URLSearchParams(parameters);
    for (const [key, value] of Object.entries(patch) as [string, string | undefined][]) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParameters(next, { replace: true });
  };
  return [values, update];
}

export const periods = [
  { id: "24h", label: "24 часа", hours: 24 },
  { id: "7d", label: "7 дней", hours: 24 * 7 },
  { id: "30d", label: "30 дней", hours: 24 * 30 },
  { id: "90d", label: "90 дней", hours: 24 * 90 },
] as const;

export type PeriodId = (typeof periods)[number]["id"];

export interface Period {
  id: PeriodId;
  label: string;
  hours: number;
  from: string;
  to: string;
}

// The reporting window, from the address. The end is rounded to the minute so
// that every widget of a page asks for the same window and shares its cache.
export function usePeriod(fallback: PeriodId = "7d"): [Period, (id: PeriodId) => void] {
  const [parameters, setParameters] = useSearchParams();
  const chosen = periods.find((item) => item.id === parameters.get("period")) ?? periods.find((item) => item.id === fallback) ?? periods[1];
  const minute = Math.floor(Date.now() / 60_000);
  const period = useMemo(() => {
    const end = new Date((minute + 1) * 60_000);
    const start = new Date(end.getTime() - chosen.hours * 3_600_000);
    return { ...chosen, from: start.toISOString(), to: end.toISOString() };
  }, [chosen, minute]);
  const choose = (id: PeriodId) => {
    const next = new URLSearchParams(parameters);
    if (id === fallback) next.delete("period");
    else next.set("period", id);
    next.delete("offset");
    setParameters(next, { replace: true });
  };
  return [period, choose];
}
