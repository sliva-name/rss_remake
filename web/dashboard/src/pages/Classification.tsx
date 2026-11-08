import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useMemo } from "react";
import { Link } from "react-router";

import { api, type Schemas } from "../api";
import { Categories, CategoryBadge, categoryOptions, Confidence, Mono, PeriodPicker, SourceName, sourceOptions } from "../components/domain";
import { Button } from "../components/ui/button";
import { Field, filterField, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState, Loadable } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { Tabs } from "../components/ui/tabs";
import { ago, category, categoryIds, count, samplingMethod } from "../labels";
import { CategoryLink, linkStyle, ObjectLink, paths, usePeriod, useUrlFilters } from "../links";
import { downloadCsv, stamp } from "../csv";
import { useCan } from "../permissions";
import { queries, usePermittedQuery } from "../queries";
import { ViewsMenu } from "../workspace";

interface CategoryRow {
  id: string;
  columns?: number;
  tables?: number;
  events?: number;
  principals?: number;
  lastAccess?: string;
}

// Where each kind of data is stored joined with how often it was read: the
// inventory and the access report used to be two separate pages.
function CategoriesTab() {
  const can = useCan();
  const [period] = usePeriod("7d");
  const inventory = usePermittedQuery(queries.inventory());
  const access = usePermittedQuery(queries.categories(period));
  const rows = useMemo<CategoryRow[]>(() => {
    const byId = new Map<string, CategoryRow>();
    for (const row of inventory.data ?? []) byId.set(row.category, { id: row.category, columns: row.columns, tables: row.tables });
    for (const row of access.data ?? []) byId.set(row.category, { ...(byId.get(row.category) ?? { id: row.category }), events: row.events, principals: row.principals, lastAccess: row.lastAccess });
    return [...byId.values()].sort((a, b) => (b.columns ?? 0) - (a.columns ?? 0) || (b.events ?? 0) - (a.events ?? 0));
  }, [inventory.data, access.data]);

  const columns = useMemo<TableColumn<CategoryRow>[]>(() => [
    { id: "category", header: "Категория", enableHiding: false, accessorFn: (row) => category(row.id), cell: ({ row }) => <CategoryLink id={row.original.id} className={linkStyle}>{category(row.original.id)}</CategoryLink> },
    { id: "columns", header: "Колонок", accessorFn: (row) => row.columns ?? 0, meta: { align: "right", needs: "getCatalogSummary" }, cell: ({ row }) => count(row.original.columns ?? 0) },
    { id: "tables", header: "Таблиц", accessorFn: (row) => row.tables ?? 0, meta: { align: "right", needs: "getCatalogSummary" }, cell: ({ row }) => count(row.original.tables ?? 0) },
    { id: "events", header: "Обращений", accessorFn: (row) => row.events ?? 0, meta: { align: "right", needs: "listAccessByCategory" }, cell: ({ row }) => count(row.original.events ?? 0) },
    { id: "principals", header: "Пользователей", accessorFn: (row) => row.principals ?? 0, meta: { align: "right", needs: "listAccessByCategory" }, cell: ({ row }) => count(row.original.principals ?? 0) },
    { id: "last", header: "Последнее обращение", accessorFn: (row) => row.lastAccess ?? "", meta: { needs: "listAccessByCategory" }, cell: ({ row }) => <span className="text-fg-2">{row.original.lastAccess ? ago(row.original.lastAccess) : "—"}</span> },
  ], []);

  return (
    <Panel flush>
      <DataTable
        id="classification-categories"
        columns={columns}
        data={inventory.isPending && access.isPending ? undefined : rows}
        getRowId={(row) => row.id}
        loading={inventory.isPending || access.isPending}
        error={inventory.error ?? access.error}
        sortable
        empty={<EmptyState title="Чувствительных данных не найдено">Запустите сканирование источников.</EmptyState>}
        toolbar={
          <>
            {can("listAccessByCategory") && <PeriodPicker />}
            <Button
              disabled={rows.length === 0}
              onClick={() => downloadCsv(`dataguard-categories-${stamp()}.csv`,
                ["Категория", "Код", "Колонок", "Таблиц", `Обращений за ${period.label}`, "Пользователей", "Последнее обращение (UTC)"],
                rows.map((row) => [category(row.id), row.id, row.columns ?? 0, row.tables ?? 0, row.events ?? 0, row.principals ?? 0, row.lastAccess ?? ""]))}
            >
              <Download /> CSV
            </Button>
          </>
        }
      />
    </Panel>
  );
}

const pageSize = 50;

type Finding = Schemas["CatalogColumn"];

function FindingsTab() {
  const can = useCan();
  const [filters, update] = useUrlFilters(["sourceId", "category"] as const);
  const offset = Number(filters.offset) || 0;
  const sources = usePermittedQuery(queries.sources());
  const findings = useQuery({
    queryKey: ["catalog", filters],
    placeholderData: (previous) => previous,
    queryFn: () => api.catalog({ sourceId: filters.sourceId, category: filters.category, limit: pageSize, offset }),
  });

  const columns = useMemo<TableColumn<Finding>[]>(() => [
    {
      id: "column", header: "Колонка", enableHiding: false, cell: ({ row }) => (
        <div className="min-w-0">
          <ObjectLink to={paths.column(row.original.columnId)} needs="getCatalogColumn" className="font-mono text-[13px]">{row.original.column}</ObjectLink>
          <div className="whitespace-nowrap">
            <ObjectLink to={paths.table(row.original.tableId)} needs="getCatalogTable" className="font-mono text-xs text-fg-2">{row.original.schema}.{row.original.table}</ObjectLink>
          </div>
        </div>
      ),
    },
    { id: "source", header: "Источник", cell: ({ row }) => <SourceName id={row.original.sourceId} /> },
    { id: "type", header: "Тип", cell: ({ row }) => <Mono className="whitespace-nowrap text-fg-2">{row.original.nativeType}</Mono> },
    { id: "category", header: "Категория", cell: ({ row }) => <Categories ids={[row.original.categoryId]} /> },
    { id: "confidence", header: "Уверенность", cell: ({ row }) => <Confidence value={row.original.confidence} /> },
    {
      id: "sampling", header: "Основание", meta: { hint: "Что прочитал классификатор: только имя колонки, выборку СУБД, первые строки или всю таблицу" },
      cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{samplingMethod(row.original.samplingMethod)}</span>,
    },
    { id: "matched", header: "Совпало строк", meta: { align: "right" }, cell: ({ row }) => <span className="whitespace-nowrap">{count(row.original.rowsMatched)}<span className="text-fg-3"> из {count(row.original.rowsInspected)}</span></span> },
    { id: "unique", header: "Уникальных ≈", meta: { align: "right", hint: "Оценка числа разных значений в выборке" }, cell: ({ row }) => count(row.original.uniqueEstimate) },
    { id: "updated", header: "Решение от", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.updatedAt)}</span> },
  ], []);

  return (
    <Panel flush>
      <DataTable
        id="classification-findings"
        columns={columns}
        defaultHidden={["type", "unique"]}
        data={findings.data?.items}
        getRowId={(item) => `${item.columnId}-${item.categoryId}`}
        loading={findings.isPending}
        error={findings.error}
        empty={<EmptyState icon="search" title="Находок нет">{filters.sourceId || filters.category ? "Измените фильтры." : "Запустите сканирование источников."}</EmptyState>}
        page={findings.data ? { offset, size: pageSize, total: findings.data.total, onChange: (next) => update({ offset: String(next) }) } : undefined}
        toolbar={
          <>
            {can("listSources") && (
              <Field label="Источник" className={filterField}>
                <Select value={filters.sourceId} onValueChange={(sourceId) => update({ sourceId })} options={sourceOptions(sources.data)} />
              </Field>
            )}
            <Field label="Категория" className={filterField}>
              <Select value={filters.category} onValueChange={(value) => update({ category: value })} options={categoryOptions("Все категории")} />
            </Field>
          </>
        }
      />
    </Panel>
  );
}

function DetectorsTab() {
  const can = useCan();
  const policy = usePermittedQuery(queries.policy());
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title="Встроенные категории" description="Детекторы агента: имя колонки, формат значений, контрольные суммы">
        <ul className="flex flex-wrap gap-1.5">
          {categoryIds.map((id) => <li key={id}><CategoryLink id={id} className="rounded-md"><CategoryBadge id={id} /></CategoryLink></li>)}
        </ul>
      </Panel>
      {can("getPolicy") && (
        <Panel title="Собственные детекторы" description="Из опубликованной политики организации" actions={<Button size="sm" asChild><Link to="/policy">Открыть политику</Link></Button>}>
          {policy.isError ? (
            <p className="text-sm text-fg-2">Политика ещё не опубликована: работают только встроенные детекторы.</p>
          ) : policy.data ? (
            policy.data.customDetectors.length === 0 ? (
              <p className="text-sm text-fg-2">В политике версии {policy.data.version} собственных детекторов нет.</p>
            ) : (
              <ul className="flex flex-col gap-2 text-sm">
                {policy.data.customDetectors.map((detector) => (
                  <li key={detector.categoryId} className="flex flex-col gap-0.5">
                    <Mono className="text-fg">{detector.categoryId}</Mono>
                    <span className="text-xs text-fg-2">
                      {detector.namePattern && <>имя: <Mono>{detector.namePattern}</Mono> </>}
                      {detector.valuePattern && <>значение: <Mono>{detector.valuePattern}</Mono></>}
                    </span>
                  </li>
                ))}
              </ul>
            )
          ) : (
            <Loadable query={policy}>{() => null}</Loadable>
          )}
        </Panel>
      )}
    </div>
  );
}

export function Classification() {
  return (
    <>
      <PageHeader title="Классификация" description="Какие чувствительные данные найдены, где они хранятся и как часто их читают." actions={<ViewsMenu />} />
      <Tabs
        items={[
          { id: "categories", label: "Категории", needs: ["getCatalogSummary", "listAccessByCategory"], content: <CategoriesTab /> },
          { id: "findings", label: "Находки", needs: "listCatalogColumns", content: <FindingsTab /> },
          { id: "detectors", label: "Детекторы", content: <DetectorsTab /> },
        ]}
      />
    </>
  );
}
