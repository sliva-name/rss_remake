import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Pencil, Play, ScrollText, Trash2 } from "lucide-react";
import { useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, type Schemas } from "../api";
import { Categories, CoverageState, FailureNote, Mono, ScanState, SourceState } from "../components/domain";
import { Badge, type Tone } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Facts, Panel } from "../components/ui/panel";
import { EmptyState, ErrorState, Loadable, Loading } from "../components/ui/state";
import { DataTable } from "../components/ui/table";
import { Tabs } from "../components/ui/tabs";
import { ago, capability, count, dateTime, engine, percent, support, tableKind } from "../labels";
import { ObjectLink, paths, useUrlFilters } from "../links";
import { useMe } from "../me";
import { useCan } from "../permissions";
import { useSourceActions } from "./SourcesList";

const supportTone: Record<string, Tone> = { SUPPORT_AVAILABLE: "ok", SUPPORT_NOT_CONFIGURED: "warn", SUPPORT_UNKNOWN: "warn", SUPPORT_UNAVAILABLE: "neutral" };

function Overview({ source }: { source: Schemas["Source"] }) {
  const can = useCan();
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24), enabled: can("getAuditCoverage") });
  const row = coverage.data?.find((item) => item.sourceId === source.id);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Подключение">
        <Facts
          items={[
            ["Состояние", <div key="state" className="flex flex-col gap-1"><SourceState statusCode={source.statusCode} probedAt={source.probedAt} /><FailureNote code={source.statusCode} /></div>],
            ["Агент", <ObjectLink key="agent" to={paths.agent(source.agentId)} needs="getAgent" className="font-mono text-[13px]">{source.agentId}</ObjectLink>],
            ["Адрес", <Mono key="address">{source.host}:{source.port}</Mono>],
            ["База данных", <Mono key="database">{source.database}</Mono>],
            ["Пользователь", <Mono key="user">{source.username}</Mono>],
            ["TLS", source.tls],
            ["Каталог журналов", source.auditDirectory ? <Mono key="dir">{source.auditDirectory}</Mono> : <span key="dir" className="text-fg-3">не указан — аудит не собирается</span>],
            ["Соединений", String(source.maxConnections)],
            ["Проверено агентом", source.probedAt ? ago(source.probedAt) : "ещё нет"],
          ]}
        />
      </Panel>
      {can("getAuditCoverage") && (
        <Panel title="Аудит за сутки" description="«Нет данных» значит, что измерять было нечего: это не ноль">
          {coverage.isPending ? <Loading /> : !row ? <p className="text-sm text-fg-2">Покрытие ещё не посчитано.</p> : (
            <Facts
              items={[
                ["Состояние", <div key="state" className="flex flex-col gap-1"><CoverageState status={row.status} reason={row.reason} /><FailureNote code={row.reason} /></div>],
                ["Аудит чтения", row.readsAudited ? "Да" : <Badge key="reads" tone="bad">Нет</Badge>],
                ["Запросов", count(row.statements)],
                ["Разобрано до колонок", percent(row.columnsShare)],
                ["Известна учётная запись", percent(row.principalShare)],
                ["Подтверждён пользователь", percent(row.verifiedShare)],
                ["Потерь аудита", row.gaps > 0 ? <ObjectLink key="gaps" to={paths.events({ sourceId: source.id, eventType: "EVENT_TYPE_AUDIT_GAP" })} needs="listAuditEvents" className="text-bad">{count(row.gaps)}</ObjectLink> : "0"],
                ["Последнее событие", ago(row.lastEventAt)],
              ]}
            />
          )}
        </Panel>
      )}
      {source.capabilities.length > 0 && (
        <Panel title="Что источник позволяет видеть" className="xl:col-span-2">
          <ul className="flex flex-wrap gap-1.5">
            {source.capabilities.map((item) => (
              <li key={item.capability}>
                <Badge tone={supportTone[item.support] ?? "neutral"} title={item.reasonCode || undefined}>{capability(item.capability)}: {support(item.support)}</Badge>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

const pageSize = 50;

function Tables({ sourceId }: { sourceId: string }) {
  const [filters, update] = useUrlFilters(["q"] as const);
  const offset = Number(filters.offset) || 0;
  const tables = useQuery({
    queryKey: ["tables", sourceId, filters],
    placeholderData: (previous) => previous,
    queryFn: () => api.tables({ sourceId, q: filters.q.trim(), limit: pageSize, offset }),
  });
  const columns = useMemo<ColumnDef<Schemas["CatalogTable"], unknown>[]>(() => [
    { id: "table", header: "Таблица", enableHiding: false, cell: ({ row }) => <ObjectLink to={paths.table(row.original.id)} needs="getCatalogTable" className="font-mono text-[13px]">{row.original.table}</ObjectLink> },
    { id: "place", header: "База › схема", cell: ({ row }) => <Mono className="text-fg-2">{row.original.database} › {row.original.schema}</Mono> },
    { id: "kind", header: "Вид", cell: ({ row }) => <span className="text-fg-2">{tableKind(row.original.kind)}</span> },
    { id: "columns", header: "Колонок", meta: { align: "right" }, cell: ({ row }) => count(row.original.columns) },
    { id: "sensitive", header: "Чувствительных", meta: { align: "right" }, cell: ({ row }) => count(row.original.sensitiveColumns) },
    { id: "categories", header: "Категории", cell: ({ row }) => <Categories ids={row.original.categories} /> },
  ], []);
  return (
    <Panel flush>
      <DataTable
        id="source-tables"
        columns={columns}
        data={tables.data?.items}
        getRowId={(table) => table.id}
        loading={tables.isPending}
        error={tables.error}
        empty={filters.q ? <EmptyState icon="search" title="Таблиц не найдено" /> : <EmptyState title="Таблиц нет">Источник ещё не сканировали.</EmptyState>}
        page={tables.data ? { offset, size: pageSize, total: tables.data.total, onChange: (next) => update({ offset: String(next) }) } : undefined}
        toolbar={<Input type="search" aria-label="Поиск таблицы" className="w-64" value={filters.q} onChange={(event) => update({ q: event.target.value })} placeholder="Имя или база.схема.таблица" />}
      />
    </Panel>
  );
}

function Scans({ sourceId }: { sourceId: string }) {
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  return (
    <Panel flush>
      <Loadable query={scans} isEmpty={(rows) => !rows.some((row) => row.sourceId === sourceId)} empty={<EmptyState title="Среди последних 20 сканирований этого источника нет" />}>
        {(rows) => (
          <ul className="divide-y divide-border">
            {rows.filter((row) => row.sourceId === sourceId).map((scan) => (
              <li key={scan.id} className="flex flex-wrap items-start justify-between gap-3 px-4 py-3 text-sm">
                <div className="flex flex-col gap-1">
                  <ScanState status={scan.status} />
                  <FailureNote code={scan.failureCode} />
                </div>
                <div className="text-right text-[13px] text-fg-2">
                  <div>Запущено {dateTime(scan.createdAt)}</div>
                  {scan.finishedAt && <div>Завершено {dateTime(scan.finishedAt)}</div>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Loadable>
    </Panel>
  );
}

export function SourcePage() {
  const { id = "" } = useParams();
  const can = useCan();
  const navigate = useNavigate();
  const me = useMe();
  const actions = useSourceActions(me.data?.tenantId ?? "");
  const source = useQuery({ queryKey: ["source", id], queryFn: () => api.source(id), refetchInterval: 10_000 });

  if (source.isPending) return <Loading rows={8} />;
  if (source.isError) return <ErrorState error={source.error} />;
  const data = source.data;
  const connected = Boolean(data.probedAt) && !data.statusCode;
  const tabs = [
    { id: "overview", label: "Обзор", content: <Overview source={data} /> },
    ...(can("listCatalogTables") ? [{ id: "tables", label: "Таблицы", content: <Tables sourceId={data.id} /> }] : []),
    ...(can("listScans") ? [{ id: "scans", label: "Сканирования", content: <Scans sourceId={data.id} /> }] : []),
  ];

  return (
    <>
      <PageHeader
        breadcrumbs={[<Link key="sources" to="/sources">Источники</Link>, data.key]}
        title={data.key}
        meta={
          <>
            <Badge>{engine(data.engine)} {data.engineVersion}</Badge>
            <SourceState statusCode={data.statusCode} probedAt={data.probedAt} />
          </>
        }
        actions={
          <>
            {can("listAuditEvents") && <Button asChild><Link to={paths.events({ sourceId: data.id })}><ScrollText /> События</Link></Button>}
            {can("requestScan") && <Button disabled={!connected || actions.scanning} onClick={() => actions.scan([data])} title={connected ? undefined : "Источник не подключён"}><Play /> Сканировать</Button>}
            {can("updateSource") && <Button onClick={() => actions.edit(data)}><Pencil /> Изменить</Button>}
            {can("deleteSource") && <Button variant="danger" size="icon" aria-label="Удалить источник" onClick={() => void actions.remove(data).then((removed) => { if (removed) navigate("/sources"); })}><Trash2 /></Button>}
          </>
        }
      />
      <Tabs items={tabs} />
      {actions.drawer}
    </>
  );
}
