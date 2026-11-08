import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Database } from "lucide-react";
import { useMemo } from "react";

import { api, type Schemas } from "../api";
import { Categories, SourceState } from "../components/domain";
import { cn } from "../components/ui/cn";
import { CheckField, Field, Input, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState, Loadable } from "../components/ui/state";
import { DataTable } from "../components/ui/table";
import { ago, category, categoryIds, count, engine, tableKind } from "../labels";
import { ObjectLink, paths, useUrlFilters } from "../links";
import { useCan } from "../permissions";

const pageSize = 50;

type Table = Schemas["CatalogTable"];

function SourceList({ selected, onSelect }: { selected: string; onSelect: (id: string) => void }) {
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  const item = (active: boolean) => cn("flex w-full cursor-pointer flex-col items-start gap-0.5 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-surface-2", active && "bg-accent-bg hover:bg-accent-bg");
  return (
    <Panel title="Источники" flush className="lg:sticky lg:top-16">
      <div className="flex flex-col gap-0.5 p-1.5">
        <button type="button" className={item(selected === "")} onClick={() => onSelect("")} aria-pressed={selected === ""}>
          <span className="text-sm font-medium text-fg">Все источники</span>
        </button>
        <Loadable query={sources} isEmpty={(rows) => rows.length === 0} empty={<p className="px-2.5 py-3 text-sm text-fg-2">Источников пока нет.</p>}>
          {(rows) => rows.map((source) => (
            <button key={source.id} type="button" className={item(selected === source.id)} onClick={() => onSelect(source.id)} aria-pressed={selected === source.id}>
              <span className="flex w-full items-center justify-between gap-2">
                <span className="truncate text-sm font-medium text-fg">{source.key}</span>
                <span className="shrink-0 text-xs text-fg-3">{engine(source.engine)}</span>
              </span>
              <span className="text-xs"><SourceState statusCode={source.statusCode} probedAt={source.probedAt} /></span>
            </button>
          ))}
        </Loadable>
      </div>
    </Panel>
  );
}

export function Inventory() {
  const can = useCan();
  const [filters, update] = useUrlFilters(["sourceId", "q", "sensitive", "category"] as const);
  const offset = Number(filters.offset) || 0;
  const tables = useQuery({
    queryKey: ["tables", filters],
    placeholderData: (previous) => previous,
    queryFn: () => api.tables({ sourceId: filters.sourceId, q: filters.q.trim(), sensitive: filters.sensitive ? "true" : undefined, category: filters.category, limit: pageSize, offset }),
  });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const sourceKey = (id: string) => sources.data?.find((source) => source.id === id)?.key;

  const columns = useMemo<ColumnDef<Table, unknown>[]>(() => [
    {
      id: "table", header: "Таблица", enableHiding: false, cell: ({ row }) => (
        <ObjectLink to={paths.table(row.original.id)} needs="getCatalogTable" className="font-mono text-[13px]">{row.original.table}</ObjectLink>
      ),
    },
    { id: "place", header: "База › схема", cell: ({ row }) => <span className="font-mono text-[13px] text-fg-2">{row.original.database} › {row.original.schema}</span> },
    {
      id: "source", header: "Источник", cell: ({ row }) => (
        <ObjectLink to={paths.source(row.original.sourceId)} needs="getSource">{sourceKey(row.original.sourceId) ?? "Источник"}</ObjectLink>
      ),
    },
    { id: "kind", header: "Вид", cell: ({ row }) => <span className="text-fg-2">{tableKind(row.original.kind)}</span> },
    { id: "columns", header: "Колонок", meta: { align: "right" }, cell: ({ row }) => count(row.original.columns) },
    { id: "sensitive", header: "Чувствительных", meta: { align: "right" }, cell: ({ row }) => <span className={row.original.sensitiveColumns > 0 ? "font-medium" : "text-fg-3"}>{count(row.original.sensitiveColumns)}</span> },
    { id: "categories", header: "Категории", cell: ({ row }) => <Categories ids={row.original.categories} /> },
    { id: "seen", header: "Последний скан", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastSeenAt)}</span> },
  ], [sources.data]);

  return (
    <>
      <PageHeader title="Инвентаризация" description="Базы, схемы и таблицы всех источников. Чувствительность определяет классификатор, значения в платформу не передаются." />
      <div className="grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
        {can("listSources") && <SourceList selected={filters.sourceId} onSelect={(sourceId) => update({ sourceId })} />}
        <Panel flush className={can("listSources") ? undefined : "lg:col-span-2"}>
          <DataTable
            id="inventory"
            columns={columns}
            data={tables.data?.items}
            getRowId={(table) => table.id}
            loading={tables.isPending}
            error={tables.error}
            empty={
              filters.q || filters.sensitive || filters.category ? (
                <EmptyState icon="search" title="Таблиц не найдено">Измените поиск или фильтры.</EmptyState>
              ) : (
                <EmptyState title="Таблиц пока нет">Таблицы появятся после первого сканирования источника.</EmptyState>
              )
            }
            page={tables.data ? { offset, size: pageSize, total: tables.data.total, onChange: (next) => update({ offset: String(next) }) } : undefined}
            toolbar={
              <>
                <Field label="Поиск" className="w-64">
                  <Input type="search" value={filters.q} onChange={(event) => update({ q: event.target.value })} placeholder="Имя или база.схема.таблица" />
                </Field>
                <Field label="Категория" className="w-44">
                  <Select value={filters.category} onChange={(event) => update({ category: event.target.value })}>
                    <option value="">Любая</option>
                    {categoryIds.map((id) => <option key={id} value={id}>{category(id)}</option>)}
                  </Select>
                </Field>
                <CheckField label="Только с чувствительными данными" checked={filters.sensitive !== ""} onChange={(event) => update({ sensitive: event.target.checked ? "1" : "" })} />
              </>
            }
          />
          {tables.data && tables.data.total > 0 && (
            <p className="flex items-center gap-1.5 border-t border-border px-3 py-2 text-xs text-fg-3">
              <Database aria-hidden className="size-3.5" />
              Показаны действующие таблицы. Удалённые открываются по ссылкам из истории и событий.
            </p>
          )}
        </Panel>
      </div>
    </>
  );
}
