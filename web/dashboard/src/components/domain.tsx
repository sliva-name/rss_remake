import type { ReactNode } from "react";

import type { Schemas } from "../api";
import { ago, category, categoryIds, coverageStatus, engine, explain, failure, scanStatus, sourceStatus } from "../labels";
import { CategoryLink, periods, usePeriod, type PeriodId } from "../links";
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

export function SourceState({ statusCode, probedAt }: { statusCode: string; probedAt?: string }) {
  const state = sourceStatus(statusCode, probedAt);
  return <Status tone={state.tone as Tone}>{state.label}</Status>;
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

export function Categories({ ids, empty = "—" }: { ids: string[]; empty?: ReactNode }) {
  if (ids.length === 0) return <span className="text-fg-3">{empty}</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {ids.map((id) => (
        <CategoryLink key={id} id={id} className="rounded focus-visible:outline-2">
          <Badge tone="warn" className="hover:brightness-95">{category(id)}</Badge>
        </CategoryLink>
      ))}
    </span>
  );
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
    <div role="radiogroup" aria-label="Период" className="inline-flex h-9 items-center rounded-md border border-border bg-surface p-0.5">
      {shown.map((item) => (
        <button
          key={item.id}
          type="button"
          role="radio"
          aria-checked={period.id === item.id}
          onClick={() => choose(item.id)}
          className={cn(
            "h-full cursor-pointer rounded px-3 text-xs font-medium text-fg-2 transition-colors hover:text-fg",
            period.id === item.id && "bg-surface-2 text-fg shadow-[inset_0_0_0_1px_var(--border)]",
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
