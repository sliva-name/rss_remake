import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Link2, X } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";

import { api, downloadEvents, type Schemas } from "../api";
import { Categories, categoryOptions, FailureNote, Mono, NoValue, PeriodPicker, SourceName, sourceOptions } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Drawer } from "../components/ui/dialog";
import { CheckField, Field, filterField, FilterInput, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { cn } from "../components/ui/cn";
import { Facts, groupLabel, Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { useNotify } from "../components/ui/toast";
import { stamp } from "../csv";
import { count, dateTime, eventType, eventTypeIds, evidenceLevel, executionStatus, identity, lowerFirst, resolution } from "../labels";
import { ObjectLink, paths, usePeriod, useUrlFilters } from "../links";
import { useCan } from "../permissions";
import { queries, usePermittedQuery } from "../queries";
import { ViewsMenu } from "../workspace";

const pageSize = 50;
const filterKeys = ["sourceId", "tableId", "columnId", "principal", "category", "eventType", "sessionId", "scanner", "from", "to"] as const;

type Event = Schemas["AuditEvent"];

function who(event: Event): { name: string; detail: string } {
  if (event.type === "EVENT_TYPE_AUDIT_GAP") return { name: "—", detail: "" };
  if (event.applicationPrincipal) return { name: event.applicationPrincipal, detail: `через ${event.databasePrincipal}` };
  return { name: event.databasePrincipal || "Учётная запись неизвестна", detail: identity(event.identityConfidence) };
}

function objects(event: Event): string[] {
  return event.columns.length > 0 ? event.columns : event.tables;
}

function Chip({ label, value, onClear }: { label: string; value: string | undefined; onClear: () => void }) {
  return (
    <span className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface-2 pr-1 pl-3 text-xs">
      <span className="text-fg-2">{label}:</span>
      <span className="max-w-64 truncate font-medium text-fg">{value ?? "…"}</span>
      <button type="button" aria-label={`Убрать фильтр «${label}»`} onClick={onClear} className="cursor-pointer rounded p-0.5 text-fg-3 hover:bg-surface hover:text-fg">
        <X className="size-3.5" />
      </button>
    </span>
  );
}

// Names in an event are what the agent saw in the query. They are matched to
// the catalog of the same source to become links; a name the catalog does not
// know stays text.
function useCatalogLinks(event: Event | null) {
  const can = useCan();
  const client = useQueryClient();
  const names = event ? [...new Set(event.tables)] : [];
  return useQuery({
    queryKey: ["event-objects", event?.id],
    enabled: event !== null && names.length > 0 && can("listCatalogTables") && can("getCatalogTable"),
    staleTime: 60_000,
    queryFn: async () => {
      const tables = new Map<string, string>();
      const columns = new Map<string, string>();
      for (const name of names) {
        const table = name.slice(name.lastIndexOf(".") + 1);
        const schema = name.slice(0, Math.max(0, name.lastIndexOf(".")));
        const page = await api.tables({ sourceId: event?.sourceId, q: table, limit: 20 });
        const match = page.items.find((item) => item.table === table && item.schema === schema);
        if (!match) continue;
        tables.set(name, match.id);
        const detail = await client.fetchQuery(queries.table(match.id));
        for (const column of detail.columns) columns.set(`${name}.${column.name}`, column.id);
      }
      return { tables, columns };
    },
  });
}

function EventDetails({ event, onClose, onFilter }: { event: Event; onClose: () => void; onFilter: (patch: Record<string, string>) => void }) {
  const links = useCatalogLinks(event);
  const person = who(event);
  const objectLink = (name: string) => {
    const columnId = links.data?.columns.get(name);
    if (columnId) return <ObjectLink to={paths.column(columnId)} needs="getCatalogColumn" className="font-mono text-[13px]">{name}</ObjectLink>;
    const tableId = links.data?.tables.get(name);
    if (tableId) return <ObjectLink to={paths.table(tableId)} needs="getCatalogTable" className="font-mono text-[13px]">{name}</ObjectLink>;
    return <Mono>{name}</Mono>;
  };
  const filterBy = (patch: Record<string, string>) => {
    onFilter(patch);
    onClose();
  };
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-2">
        <Badge tone={event.executionStatus === "EXECUTION_STATUS_FAILURE" ? "bad" : "neutral"}>Исход: {lowerFirst(executionStatus(event.executionStatus))}</Badge>
        <Badge tone="accent">Доказательство: {lowerFirst(evidenceLevel(event.evidenceLevel))}</Badge>
        <Badge>Разбор: {lowerFirst(resolution(event.objectResolution))}</Badge>
      </div>
      <section>
        <h3 className={cn("mb-2", groupLabel)}>Кто</h3>
        <Facts
          items={[
            ["Пользователь", person.name],
            ["Учётная запись СУБД", event.databasePrincipal ? <Mono>{event.databasePrincipal}</Mono> : "—"],
            ["Как установлен", identity(event.identityConfidence)],
            ...(event.applicationId ? [["Приложение", <Mono key="app">{event.applicationId}</Mono>] as [string, ReactNode]] : []),
            ...(event.clientAddress ? [["Адрес клиента", <Mono key="client">{event.clientAddress}</Mono>] as [string, ReactNode]] : []),
          ]}
        />
        <div className="mt-4 flex flex-wrap gap-2">
          {(event.applicationPrincipal || event.databasePrincipal) && (
            <Button size="sm" onClick={() => filterBy({ principal: event.applicationPrincipal || event.databasePrincipal })}>
              Все события пользователя
            </Button>
          )}
          {event.sessionId && (
            <Button size="sm" onClick={() => filterBy({ sessionId: event.sessionId, sourceId: event.sourceId, principal: "" })}>
              Все события этой сессии
            </Button>
          )}
        </div>
      </section>
      <section>
        <h3 className={cn("mb-2", groupLabel)}>К чему</h3>
        <Facts
          items={[
            ["Источник", <SourceName key="source" id={event.sourceId} />],
            ["Операция", event.operation.replace("OPERATION_TYPE_", "")],
            ["Объекты", objects(event).length > 0 ? <ul className="flex flex-col gap-0.5">{objects(event).map((name) => <li key={name}>{objectLink(name)}</li>)}</ul> : "—"],
            ["Категории", <Categories key="categories" ids={event.categories} />],
          ]}
        />
      </section>
      {event.type === "EVENT_TYPE_AUDIT_GAP" && (
        <section>
          <h3 className={cn("mb-2", groupLabel)}>Потеря аудита</h3>
          <p className="mb-1 text-sm text-fg">{event.gapLostEvents === undefined ? "Сколько событий потеряно, неизвестно." : `Потеряно событий: ${count(event.gapLostEvents)}.`}</p>
          <FailureNote code={event.gapReason} />
        </section>
      )}
      <section>
        <h3 className={cn("mb-2", groupLabel)}>Подробности</h3>
        <Facts
          items={[
            ["Время", dateTime(event.time)],
            ["Тип", eventType(event.type)],
            ...(event.errorCode ? [["Код ошибки СУБД", <Mono key="error">{event.errorCode}</Mono>] as [string, ReactNode]] : []),
            ["Отпечаток запроса", event.queryFingerprint ? <Mono className="break-all">{event.queryFingerprint}</Mono> : <span className="text-fg-3">запрос не разобран</span>],
            ...(event.sessionId ? [["Сессия СУБД", <Mono key="session">{event.sessionId}</Mono>] as [string, ReactNode]] : []),
            ...(event.transactionId ? [["Транзакция", <Mono key="tx">{event.transactionId}</Mono>] as [string, ReactNode]] : []),
            ["Идентификатор события", <Mono key="id" className="break-all">{event.id}</Mono>],
          ]}
        />
        <p className="mt-3 text-xs text-fg-3">Текст запроса и значения в платформу не передаются: отпечаток считается после удаления литералов.</p>
      </section>
    </div>
  );
}

export function Audit() {
  const can = useCan();
  const notify = useNotify();
  const [filters, update] = useUrlFilters(filterKeys);
  const [period] = usePeriod("7d");
  const [selected, setSelected] = useState<Event | null>(null);
  const offset = Number(filters.offset) || 0;
  const custom = filters.from !== "" && filters.to !== "";
  const span = custom ? { from: filters.from, to: filters.to } : { from: period.from, to: period.to };
  // The list and the export ask for the same selection.
  const selection = {
    sourceId: filters.sourceId, tableId: filters.tableId, columnId: filters.columnId, principal: filters.principal, category: filters.category,
    sessionId: filters.sessionId,
    includeLogins: filters.eventType === "all" ? "true" : undefined,
    includeScanner: filters.scanner ? "true" : undefined,
    eventType: filters.eventType === "all" ? "" : filters.eventType,
    from: span.from, to: span.to,
  };
  const exporting = useMutation({
    mutationFn: () => downloadEvents(selection, `dataguard-events-${stamp()}.csv`),
    onSuccess: ({ truncated }) => notify(truncated
      ? { tone: "ok", title: "Выгружены первые 100 000 событий", description: "Совпало больше. Сузьте период или фильтры, чтобы выгрузить остальное." }
      : { tone: "ok", title: "Выгрузка готова", description: "Файл CSV сохранён." }),
    onError: (error) => notify({ tone: "bad", title: "Выгрузка не удалась", description: error.message }),
  });

  const events = useQuery({
    queryKey: ["events", filters, span.from, span.to],
    placeholderData: (previous) => previous,
    queryFn: () => api.events({ ...selection, limit: pageSize, offset }),
  });
  const sources = usePermittedQuery(queries.sources());
  const table = usePermittedQuery({ ...queries.table(filters.tableId), enabled: filters.tableId !== "" });
  const column = usePermittedQuery({ ...queries.column(filters.columnId), enabled: filters.columnId !== "" });
  const sourceKey = (id: string) => sources.data?.find((source) => source.id === id)?.key;
  // The scanner is the login the agent was given for that source.
  const isScanner = (event: Event) => sources.data?.some((source) => source.id === event.sourceId && source.username === event.databasePrincipal) ?? false;

  const columns = useMemo<TableColumn<Event>[]>(() => [
    {
      id: "time", header: "Время", enableHiding: false, meta: { className: "whitespace-nowrap" },
      cell: ({ row }) => {
        const at = new Date(row.original.time);
        return (
          <div title={dateTime(row.original.time)} className="tabular-nums">
            <div>{at.toLocaleTimeString("ru-RU")}</div>
            <div className="text-xs text-fg-2">{at.toLocaleDateString("ru-RU")}</div>
          </div>
        );
      },
    },
    {
      // The outcome sits under the type: a refused read is told at a glance
      // without a column of its own.
      id: "type", header: "Тип", meta: { className: "whitespace-nowrap" },
      cell: ({ row }) => (
        <div>
          <div>{eventType(row.original.type)}</div>
          {row.original.type !== "EVENT_TYPE_AUDIT_GAP" && (
            <div className={cn("text-xs", row.original.executionStatus === "EXECUTION_STATUS_FAILURE" ? "text-bad" : "text-fg-2")}>{lowerFirst(executionStatus(row.original.executionStatus))}</div>
          )}
        </div>
      ),
    },
    {
      id: "who", header: "Кто", meta: { className: "min-w-44" }, cell: ({ row }) => {
        const person = who(row.original);
        return (
          <div className="min-w-0">
            <div className="truncate">{person.name}</div>
            <div className="text-xs text-fg-2">{isScanner(row.original) ? <Badge>Сканер DataGuard</Badge> : person.detail}</div>
          </div>
        );
      },
    },
    { id: "source", header: "Источник", cell: ({ row }) => <SourceName id={row.original.sourceId} /> },
    {
      id: "objects", header: "К чему", meta: { className: "max-w-72 min-w-48" }, cell: ({ row }) => {
        const shown = objects(row.original);
        if (row.original.type === "EVENT_TYPE_AUDIT_GAP") return <Badge tone="bad">{row.original.gapLostEvents === undefined ? "Потеря аудита" : `Потеряно ${count(row.original.gapLostEvents)}`}</Badge>;
        return (
          <div className="flex min-w-0 flex-col" title={shown.join("\n")}>
            {shown.slice(0, 2).map((name) => <Mono key={name} className="truncate text-fg-2">{name}</Mono>)}
            {shown.length === 0 && <NoValue />}
            {shown.length > 2 && <span className="text-xs text-fg-3">и ещё {shown.length - 2}</span>}
          </div>
        );
      },
    },
    { id: "categories", header: "Категории", cell: ({ row }) => <Categories ids={row.original.categories} limit={1} /> },
    { id: "outcome", header: "Исход", meta: { className: "whitespace-nowrap" }, cell: ({ row }) => <span className={row.original.executionStatus === "EXECUTION_STATUS_FAILURE" ? "text-bad" : undefined}>{executionStatus(row.original.executionStatus)}</span> },
    {
      id: "evidence", header: "Доказательство", meta: { className: "min-w-36", hint: "Что подтверждено: упоминание в запросе, выполнение, возврат строк или получение данных. Упоминание колонки в запросе не значит, что её прочитали." },
      cell: ({ row }) => <span className="text-fg-2">{evidenceLevel(row.original.evidenceLevel)}</span>,
    },
    { id: "resolution", header: "Разбор", meta: { className: "whitespace-nowrap" }, cell: ({ row }) => <span className="text-fg-2">{resolution(row.original.objectResolution)}</span> },
  ], [sources.data]);

  const copyLink = () => {
    navigator.clipboard.writeText(window.location.href).then(
      () => notify({ tone: "ok", title: "Ссылка скопирована", description: "По ней откроется этот же список с теми же фильтрами." }),
      () => notify({ tone: "bad", title: "Не удалось скопировать ссылку" }),
    );
  };

  const chips = [
    filters.tableId && <Chip key="table" label="Таблица" value={table.data && `${table.data.schema}.${table.data.table}`} onClear={() => update({ tableId: "" })} />,
    filters.columnId && <Chip key="column" label="Колонка" value={column.data && `${column.data.table}.${column.data.name}`} onClear={() => update({ columnId: "" })} />,
    filters.sessionId && <Chip key="session" label="Сессия" value={`${sourceKey(filters.sourceId) ?? ""} № ${filters.sessionId}`} onClear={() => update({ sessionId: "" })} />,
    custom && <Chip key="window" label="Период" value={`${dateTime(filters.from)} – ${dateTime(filters.to)}`} onClear={() => update({ from: "", to: "" })} />,
  ].filter(Boolean);

  return (
    <>
      <PageHeader
        title="Журнал событий"
        description="Обращения к данным из нативного аудита СУБД. Строка открывает подробности события и переходы к объектам."
        actions={
          <>
            {!custom && <PeriodPicker />}
            <ViewsMenu />
            <Button onClick={copyLink}><Link2 /> Ссылка</Button>
            {can("exportAuditEvents") && <Button onClick={() => exporting.mutate()} disabled={exporting.isPending}><Download /> {exporting.isPending ? "Выгрузка…" : "CSV"}</Button>}
          </>
        }
      />
      {chips.length > 0 && <div className="mb-4 flex flex-wrap gap-2">{chips}</div>}
      <Panel flush>
        <DataTable
          id="audit"
          columns={columns}
          defaultHidden={["resolution", "outcome"]}
          data={events.data?.items}
          getRowId={(event) => event.id}
          loading={events.isPending}
          error={events.error}
          onRowClick={setSelected}
          selectedId={selected?.id}
          empty={
            <EmptyState
              icon="search"
              title="Событий нет"
              action={filterKeys.some((key) => filters[key] !== "") ? <Button size="sm" onClick={() => update(Object.fromEntries(filterKeys.map((key) => [key, ""])))}>Сбросить фильтры</Button> : undefined}
            >
              Измените фильтры или период.
            </EmptyState>
          }
          page={events.data ? { offset, size: pageSize, total: events.data.total, exact: events.data.totalExact, onChange: (next) => update({ offset: String(next) }) } : undefined}
          toolbar={
            <>
              {can("listSources") && (
                <Field label="Источник" className={filterField}>
                  <Select value={filters.sourceId} onValueChange={(sourceId) => update({ sourceId })} options={sourceOptions(sources.data)} />
                </Field>
              )}
              <Field label="Пользователь" className={filterField}>
                <FilterInput value={filters.principal} onValueChange={(principal) => update({ principal })} placeholder="Точное совпадение" />
              </Field>
              <Field label="Категория" className={filterField}>
                <Select value={filters.category} onValueChange={(value) => update({ category: value })} options={categoryOptions("Все категории")} />
              </Field>
              <Field label="Тип" className={filterField}>
                <Select
                  value={filters.eventType}
                  onValueChange={(value) => update({ eventType: value })}
                  options={[
                    { value: "", label: "Все, кроме входов", hint: "Входов на порядок больше обращений" },
                    { value: "all", label: "Все, включая входы" },
                    ...eventTypeIds.map((id) => ({ value: id, label: eventType(id) })),
                  ]}
                />
              </Field>
              <CheckField label="Чтения сканера" checked={filters.scanner !== ""} onChange={(event) => update({ scanner: event.target.checked ? "1" : "" })} />
            </>
          }
        />
      </Panel>
      <Drawer open={selected !== null} onOpenChange={(open) => { if (!open) setSelected(null); }} title={selected ? eventType(selected.type) : ""} description={selected ? dateTime(selected.time) : undefined}>
        {selected && <EventDetails event={selected} onClose={() => setSelected(null)} onFilter={(patch) => update(patch)} />}
      </Drawer>
    </>
  );
}
