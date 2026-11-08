import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useCan, type Permission } from "./permissions";

export interface EventFilter {
  sourceId?: string;
  tableId?: string;
  columnId?: string;
  principal?: string;
  category?: string;
}

export interface CatalogFilter {
  sourceId?: string;
  category?: string;
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
  events: (filter: EventFilter) => `/access${search(filter)}`,
  catalog: (filter: CatalogFilter) => `/catalog${search(filter)}`,
};

// A link the user could not follow is plain text: the page behind it would
// answer 403. The API still decides; this only avoids offering a dead end.
export function ObjectLink({ to, needs, className, children }: { to: string; needs: Permission; className?: string; children: ReactNode }) {
  if (!useCan()(needs)) return <span className={className}>{children}</span>;
  return <Link className={className} to={to}>{children}</Link>;
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

export function Trail({ children }: { children: ReactNode[] }) {
  return (
    <nav className="trail" aria-label="Где вы">
      {children.map((item, index) => (
        <span key={index}>{item}</span>
      ))}
    </nav>
  );
}
