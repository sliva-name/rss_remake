import { useQuery } from "@tanstack/react-query";
import { Database } from "lucide-react";
import { useMemo } from "react";

import { api, type Schemas } from "../api";
import { Categories, categoryOptions, SensitiveShare, sensitiveShareHint, SourceName, SourceState, TableName } from "../components/domain";
import { Button } from "../components/ui/button";
import { cn } from "../components/ui/cn";
import { CheckField, Field, filterField, FilterInput, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState, Loadable } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { ago, engine, tableKind } from "../labels";
import { useUrlFilters } from "../links";
import { useCan } from "../permissions";
import { queries } from "../queries";
import { ViewsMenu } from "../workspace";

const pageSize = 50;

type Table = Schemas["CatalogTable"];

function SourceList({ selected, onSelect }: { selected: string; onSelect: (id: string) => void }) {
  const sources = useQuery(queries.sources());
  const item = (active: boolean) => cn("flex w-full cursor-pointer flex-col items-start gap-1 rounded-md px-3 py-2.5 text-left transition-colors hover:bg-surface-2", active && "bg-accent-bg hover:bg-accent-bg");
  return (
    <Panel title="Источники" flush className="lg:sticky lg:top-24">
      <div className="flex flex-col gap-1 p-2">
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

  const columns = useMemo<TableColumn<Table>[]>(() => [
    { id: "table", header: "Таблица", enableHiding: false, cell: ({ row }) => <TableName table={row.original} /> },
    { id: "source", header: "Источник", cell: ({ row }) => <SourceName id={row.original.sourceId} /> },
    { id: "kind", header: "Вид", cell: ({ row }) => <span className="text-fg-2">{tableKind(row.original.kind)}</span> },
    { id: "sensitive", header: "Чувствительных", meta: { align: "right", hint: sensitiveShareHint }, cell: ({ row }) => <SensitiveShare table={row.original} /> },
    { id: "categories", header: "Категории", cell: ({ row }) => <Categories ids={row.original.categories} limit={1} /> },
    { id: "seen", header: "Последний скан", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastSeenAt)}</span> },
  ], []);
  const filtered = filters.q !== "" || filters.sensitive !== "" || filters.category !== "";

  return (
    <>
      <PageHeader title="Инвентаризация" description="Базы, схемы и таблицы всех источников. Чувствительность определяет классификатор, значения в платформу не передаются." actions={<ViewsMenu />} />
      <div className="grid gap-6 lg:grid-cols-[15rem_minmax(0,1fr)]">
        {can("listSources") && <SourceList selected={filters.sourceId} onSelect={(sourceId) => update({ sourceId })} />}
        <Panel flush className={can("listSources") ? undefined : "lg:col-span-2"}>
          <DataTable
            id="inventory"
            columns={columns}
            defaultHidden={["kind"]}
            data={tables.data?.items}
            getRowId={(table) => table.id}
            loading={tables.isPending}
            error={tables.error}
            empty={
              filtered ? (
                <EmptyState
                  icon="search"
                  title="Таблиц не найдено"
                  action={<Button size="sm" onClick={() => update({ q: "", sensitive: "", category: "" })}>Сбросить фильтры</Button>}
                >
                  Измените поиск или фильтры.
                </EmptyState>
              ) : (
                <EmptyState title="Таблиц пока нет">Таблицы появятся после первого сканирования источника.</EmptyState>
              )
            }
            page={tables.data ? { offset, size: pageSize, total: tables.data.total, onChange: (next) => update({ offset: String(next) }) } : undefined}
            toolbar={
              <>
                <Field label="Поиск" className="w-full sm:w-72">
                  <FilterInput type="search" value={filters.q} onValueChange={(q) => update({ q })} placeholder="Имя или база.схема.таблица" />
                </Field>
                <Field label="Категория" className={filterField}>
                  <Select value={filters.category} onValueChange={(value) => update({ category: value })} options={categoryOptions("Любая категория")} />
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
