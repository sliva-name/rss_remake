import { useMemo, useState } from "react";
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { Schemas } from "../api";
import { count } from "../labels";
import { Button } from "./ui/button";

interface Bucket {
  start: number;
  end: number;
  events: number;
  sensitive: number;
  failed: number;
}

const hourMs = 3_600_000;

// The server returns only hours that had events. Every hour of the window is
// shown, the missing ones as zero; windows longer than a week are summed by
// local day, so that a day on the axis is the reader's day, not a UTC one.
// Lines are straight between points: a smoothed curve would draw growth
// inside a bucket that the data does not show.
export function buckets(points: Schemas["TimelinePoint"][], from: string, to: string): Bucket[] {
  const start = Math.floor(new Date(from).getTime() / hourMs) * hourMs;
  const end = new Date(to).getTime();
  const byHour = new Map(points.map((point) => [new Date(point.hour).getTime(), point]));
  const hours: Bucket[] = [];
  for (let at = start; at < end; at += hourMs) {
    const point = byHour.get(at);
    hours.push({ start: at, end: at + hourMs, events: point?.events ?? 0, sensitive: point?.sensitiveEvents ?? 0, failed: point?.failedEvents ?? 0 });
  }
  if (end - start <= 8 * 24 * hourMs) return hours;
  const days = new Map<number, Bucket>();
  for (const hour of hours) {
    const day = new Date(hour.start);
    day.setHours(0, 0, 0, 0);
    const key = day.getTime();
    const bucket = days.get(key) ?? { start: key, end: key, events: 0, sensitive: 0, failed: 0 };
    bucket.end = hour.end;
    bucket.events += hour.events;
    bucket.sensitive += hour.sensitive;
    bucket.failed += hour.failed;
    days.set(key, bucket);
  }
  return [...days.values()];
}

const compact = new Intl.NumberFormat("ru-RU", { notation: "compact", maximumFractionDigits: 1 });

function label(bucket: Bucket, daily: boolean): string {
  const start = new Date(bucket.start);
  if (daily) return start.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
  return start.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

const series = [
  { key: "events", name: "Все обращения", color: "var(--chart-1)" },
  { key: "sensitive", name: "К чувствительным данным", color: "var(--chart-2)" },
] as const;

function Legend({ totals }: { totals: Record<string, number> }) {
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1 text-[13px]">
      {series.map((item) => (
        <li key={item.key} className="flex items-center gap-2">
          <span aria-hidden className="h-0.5 w-4 rounded-full" style={{ background: item.color }} />
          <span className="text-fg-2">{item.name}</span>
          <span className="font-medium text-fg">{count(totals[item.key] ?? 0)}</span>
        </li>
      ))}
    </ul>
  );
}

function Hover({ active, payload, daily }: { active?: boolean; payload?: { payload: Bucket }[]; daily: boolean }) {
  const bucket = payload?.[0]?.payload;
  if (!active || !bucket) return null;
  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2 text-[13px] shadow-lg">
      <div className="mb-1 font-medium text-fg">{daily ? new Date(bucket.start).toLocaleDateString("ru-RU", { weekday: "short", day: "numeric", month: "long" }) : label(bucket, false)}</div>
      {series.map((item) => (
        <div key={item.key} className="flex items-center justify-between gap-6">
          <span className="flex items-center gap-2 text-fg-2">
            <span aria-hidden className="size-2 rounded-full" style={{ background: item.color }} />
            {item.name}
          </span>
          <span className="font-medium text-fg">{count(bucket[item.key])}</span>
        </div>
      ))}
      {bucket.failed > 0 && <div className="mt-1 text-fg-2">Ошибок выполнения: {count(bucket.failed)}</div>}
      <div className="mt-1.5 text-fg-3">Нажмите, чтобы открыть события</div>
    </div>
  );
}

// Access over time. A point opens the events of its hour or day.
export function ActivityChart({ points, from, to, onOpen }: { points: Schemas["TimelinePoint"][]; from: string; to: string; onOpen: (from: string, to: string) => void }) {
  const [asTable, setAsTable] = useState(false);
  const data = useMemo(() => buckets(points, from, to), [points, from, to]);
  const daily = data.length > 0 && data[0] !== undefined && data[0].end - data[0].start > hourMs;
  const totals = useMemo(() => ({
    events: data.reduce((sum, bucket) => sum + bucket.events, 0),
    sensitive: data.reduce((sum, bucket) => sum + bucket.sensitive, 0),
  }), [data]);
  const open = (bucket: Bucket | undefined) => {
    if (bucket) onOpen(new Date(bucket.start).toISOString(), new Date(bucket.end).toISOString());
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Legend totals={totals} />
        <Button variant="ghost" size="sm" onClick={() => setAsTable(!asTable)}>{asTable ? "График" : "Таблица"}</Button>
      </div>
      {asTable ? (
        <div className="max-h-72 overflow-y-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-2 text-xs text-fg-2">
              <tr><th className="px-3 py-1.5 text-left font-medium">{daily ? "День" : "Час"}</th>{series.map((item) => <th key={item.key} className="px-3 py-1.5 text-right font-medium">{item.name}</th>)}</tr>
            </thead>
            <tbody>
              {data.filter((bucket) => bucket.events > 0).map((bucket) => (
                <tr key={bucket.start} className="cursor-pointer border-t border-border hover:bg-surface-2/60" onClick={() => open(bucket)}>
                  <td className="px-3 py-1.5">{label(bucket, daily)}</td>
                  <td className="px-3 py-1.5 text-right">{count(bucket.events)}</td>
                  <td className="px-3 py-1.5 text-right">{count(bucket.sensitive)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-56" role="img" aria-label={`Обращения за период: всего ${count(totals.events)}, к чувствительным данным ${count(totals.sensitive)}`}>
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart
              data={data}
              margin={{ top: 4, right: 8, bottom: 0, left: 0 }}
              onClick={(state) => {
                const index = typeof state?.activeTooltipIndex === "number" ? state.activeTooltipIndex : Number(state?.activeTooltipIndex);
                if (Number.isInteger(index)) open(data[index]);
              }}
              className="cursor-pointer"
            >
              <CartesianGrid vertical={false} stroke="var(--border)" />
              <XAxis
                dataKey="start"
                tickFormatter={(value: number) => label({ start: value, end: value, events: 0, sensitive: 0, failed: 0 }, daily)}
                tick={{ fill: "var(--text-2)", fontSize: 12 }}
                axisLine={{ stroke: "var(--border)" }}
                tickLine={false}
                minTickGap={40}
              />
              <YAxis
                tickFormatter={(value: number) => (value >= 10_000 ? compact.format(value) : count(value))}
                tick={{ fill: "var(--text-2)", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
                width={48}
                allowDecimals={false}
              />
              <Tooltip content={<Hover daily={daily} />} cursor={{ stroke: "var(--border-strong)", strokeWidth: 1 }} />
              <Area type="linear" dataKey="events" stroke="none" fill="var(--chart-1)" fillOpacity={0.1} isAnimationActive={false} />
              {series.map((item) => (
                <Line key={item.key} type="linear" dataKey={item.key} name={item.name} stroke={item.color} strokeWidth={2} dot={false} activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }} isAnimationActive={false} />
              ))}
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
