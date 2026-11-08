import type { ReactNode } from "react";

import type { Schemas } from "../api";
import { ago, category, categoryIds, count, coverageStatus, engine, explain, failure, scanStatus, sourceStatus } from "../labels";
import { CategoryLink, linkStyle, ObjectLink, paths, periods, usePeriod, type PeriodId } from "../links";
import { useCan } from "../permissions";
import { queries, usePermittedQuery } from "../queries";
import { Badge, Status, type Tone } from "./ui/badge";
import { cn } from "./ui/cn";
import type { Option } from "./ui/form";
import { Tooltip } from "./ui/menu";

const coverageTone: Record<string, Tone> = { OBSERVING: "ok", DEGRADED: "warn", BLIND: "bad", NOT_CONFIGURED: "bad" };

export function CoverageState({ status, reason }: { status: string; reason: string }) {
  const state = <Status tone={coverageTone[status] ?? "neutral"}>{coverageStatus(status)}</Status>;
  if (!reason) return state;
  return (
    <Tooltip content={explain(reason)}>
      <span tabIndex={0} className="cursor-help">{state}</span>
    </Tooltip>
  );
}

export function SourceState({ statusCode, probedAt, className }: { statusCode: string; probedAt?: string; className?: string }) {
  const state = sourceStatus(statusCode, probedAt);
  return <Status tone={state.tone as Tone} className={className}>{state.label}</Status>;
}

// An agent that has not called in for a while is still "active" in the
// registry; the page says how long ago it was heard from instead of guessing.
const silentAfterMs = 5 * 60_000;

export function agentTone(agent: Schemas["Agent"], now = Date.now()): Tone {
  if (agent.status !== "active") return "bad";
  if (!agent.lastSeenAt) return "warn";
  return now - new Date(agent.lastSeenAt).getTime() > silentAfterMs ? "warn" : "ok";
}

export function AgentState({ agent }: { agent: Schemas["Agent"] }) {
  const tone = agentTone(agent);
  const label = agent.status !== "active" ? "Отозван" : tone === "ok" ? "На связи" : agent.lastSeenAt ? `Молчит ${ago(agent.lastSeenAt).replace(" назад", "")}` : "Ещё не выходил на связь";
  return <Status tone={tone}>{label}</Status>;
}

const scanTone: Record<string, Tone> = { completed: "ok", partial: "warn", failed: "bad", cancelled: "neutral", pending: "accent", running: "accent" };

export function ScanState({ status }: { status: string }) {
  return <Status tone={scanTone[status] ?? "neutral"}>{scanStatus(status)}</Status>;
}

export function Confidence({ value }: { value: number }) {
  const share = Math.round(value * 100);
  return (
    <span className="inline-flex items-center gap-2" aria-label={`Уверенность ${share}%`}>
      <span aria-hidden className="h-1.5 w-14 overflow-hidden rounded-full bg-neutral-bg">
        <span className="block h-full rounded-full bg-accent" style={{ width: `${share}%` }} />
      </span>
      <span className="text-[13px] text-fg-2">{share}%</span>
    </span>
  );
}

// A kind of sensitive data. The dot's colour is its group, personal,
// government, financial and so on, so a row of them reads at a glance without
// a wall of warning colour.
export function CategoryDot({ id, className }: { id: string; className?: string }) {
  const group = id.slice(0, Math.max(0, id.indexOf("."))).toLowerCase();
  return <span aria-hidden className={cn("size-1.5 shrink-0 rounded-full", className)} style={{ background: `var(--cat-${group}, var(--cat-custom))` }} />;
}

export function CategoryBadge({ id, className }: { id: string; className?: string }) {
  return (
    <Badge className={cn("bg-surface text-fg ring-border transition-colors hover:ring-border-strong", className)}>
      <CategoryDot id={id} />
      {category(id)}
    </Badge>
  );
}

// A category's name as a link, with its group's dot, where a badge would be
// too heavy: a list or a table of categories themselves.
export function CategoryName({ id }: { id: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <CategoryDot id={id} className="size-2" />
      <CategoryLink id={id} className={cn(linkStyle, "truncate")}>{category(id)}</CategoryLink>
    </span>
  );
}

// Categories as links. In a table row the list is cut to a few, with the rest
// counted and named on hover, so a row stays one line high.
export function Categories({ ids, empty = "—", limit }: { ids: string[]; empty?: ReactNode; limit?: number }) {
  if (ids.length === 0) return <span className="text-fg-3">{empty}</span>;
  const shown = limit !== undefined && ids.length > limit + 1 ? ids.slice(0, limit) : ids;
  const rest = ids.slice(shown.length);
  return (
    <span className={cn("inline-flex gap-1", limit === undefined ? "flex-wrap" : "flex-nowrap")}>
      {shown.map((id) => (
        <CategoryLink key={id} id={id} className="rounded-md focus-visible:outline-2">
          <CategoryBadge id={id} />
        </CategoryLink>
      ))}
      {rest.length > 0 && (
        <Tooltip content={rest.map(category).join(", ")}>
          <span tabIndex={0} className="cursor-help rounded">
            <Badge aria-label={`Ещё: ${rest.map(category).join(", ")}`}>+{rest.length}</Badge>
          </span>
        </Tooltip>
      )}
    </span>
  );
}

// A table's name with where it lives under it: the two read as one address.
export function TableName({ table }: { table: Pick<Schemas["CatalogTable"], "id" | "table" | "database" | "schema"> }) {
  return (
    <div className="min-w-0">
      <ObjectLink to={paths.table(table.id)} needs="getCatalogTable" className="font-mono text-[13px]">{table.table}</ObjectLink>
      <div className="font-mono text-xs whitespace-nowrap text-fg-3">{table.database} › {table.schema}</div>
    </div>
  );
}

export const sensitiveShareHint = "Чувствительных колонок из всех колонок таблицы";

export function SensitiveShare({ table }: { table: Pick<Schemas["CatalogTable"], "columns" | "sensitiveColumns"> }) {
  return (
    <span className="whitespace-nowrap">
      <span className={table.sensitiveColumns > 0 ? "font-medium text-fg" : "text-fg-3"}>{count(table.sensitiveColumns)}</span>
      <span className="text-fg-3"> из {count(table.columns)}</span>
    </span>
  );
}

// A source by its name. Sources are deleted softly: tables, findings and events
// of a deleted one stay, and they name it as deleted rather than as nothing.
// Without permission to list sources only the link is left to show.
export function SourceName({ id, className }: { id: string; className?: string }) {
  const can = useCan();
  const sources = usePermittedQuery(queries.sources());
  const link = (label: ReactNode) => <ObjectLink to={paths.source(id)} needs="getSource" className={cn("whitespace-nowrap", className)}>{label}</ObjectLink>;
  if (!can("listSources") || sources.isError) return link("Источник");
  if (!sources.data) return <span className={cn("text-fg-3", className)}>…</span>;
  const source = sources.data.find((item) => item.id === id);
  if (!source) return <span className={cn("whitespace-nowrap text-fg-3", className)} title={`Источник ${id} удалён`}>удалённый источник</span>;
  return link(source.key);
}

// What went wrong and what to do about it, from the shared dictionary of codes.
export function FailureNote({ code, className }: { code: string; className?: string }) {
  if (!code) return null;
  const { problem, action } = failure(code);
  return (
    <div className={cn("text-[13px]", className)}>
      <div className="text-fg">{problem}</div>
      {action && <div className="mt-0.5 max-w-prose text-fg-2">{action}</div>}
    </div>
  );
}

export function PeriodPicker({ fallback = "7d", allowed }: { fallback?: PeriodId; allowed?: readonly PeriodId[] }) {
  const [period, choose] = usePeriod(fallback);
  const shown = periods.filter((item) => !allowed || allowed.includes(item.id));
  return (
    <div role="radiogroup" aria-label="Период" className="inline-flex h-9 items-center gap-0.5 rounded-lg bg-neutral-bg p-[3px]">
      {shown.map((item) => (
        <button
          key={item.id}
          type="button"
          role="radio"
          aria-checked={period.id === item.id}
          onClick={() => choose(item.id)}
          className={cn(
            "h-full cursor-pointer rounded-md px-3 text-xs font-medium text-fg-2 transition-[background-color,color,box-shadow] hover:text-fg",
            period.id === item.id && "bg-surface text-fg shadow-xs ring-1 ring-border",
          )}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

// Options of the filters that every list shares, so "all" reads the same way.
export function categoryOptions(all: string): Option[] {
  return [{ value: "", label: all }, ...categoryIds.map((id) => ({ value: id, label: category(id) }))];
}

export function sourceOptions(sources: Schemas["Source"][] | undefined, all = "Все источники"): Option[] {
  return [{ value: "", label: all }, ...(sources ?? []).map((source) => ({ value: source.id, label: source.key, hint: engine(source.engine) }))];
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[13px]", className)}>{children}</span>;
}

export function NoValue() {
  return <span className="text-fg-3">—</span>;
}
