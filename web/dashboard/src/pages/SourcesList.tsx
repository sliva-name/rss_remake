import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";

import { api, type Schemas } from "../api";
import { CoverageState, FailureNote, Mono, NoValue, ScanState, SourceState } from "../components/domain";
import { SourceDrawer } from "../components/source-form";
import { Badge, type Tone } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { useConfirm } from "../components/ui/dialog";
import { Menu, MenuItem, MenuSeparator } from "../components/ui/menu";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState, Loadable } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { Tabs } from "../components/ui/tabs";
import { useNotify } from "../components/ui/toast";
import { ago, capability, count, dateTime, engine, failure, percent, shortId, support } from "../labels";
import { ObjectLink, paths } from "../links";
import { useCan } from "../permissions";
import { queries, usePermittedQuery } from "../queries";

type Source = Schemas["Source"];

// Scanning, editing and removing a source, the same from the list and from
// the source's own page.
export function useSourceActions(tenantId: string) {
  const client = useQueryClient();
  const confirm = useConfirm();
  const notify = useNotify();
  const [editing, setEditing] = useState<Source | undefined>();
  const [open, setOpen] = useState(false);
  const scan = useMutation({
    mutationFn: async (sources: Source[]) => Promise.all(sources.map((source) => api.requestScan(source.id))),
    onSuccess: (jobs) => {
      notify({ tone: "ok", title: jobs.length === 1 ? "Сканирование поставлено в очередь" : `Поставлено в очередь сканирований: ${jobs.length}`, description: "Агент заберёт задание со следующим сигналом." });
      return client.invalidateQueries({ queryKey: queries.scans().queryKey });
    },
    onError: (error) => notify({ tone: "bad", title: "Сканирование не запущено", description: error.message }),
  });
  const remove = useMutation({
    mutationFn: (source: Source) => api.deleteSource(source.id),
    onSuccess: () => {
      notify({ tone: "ok", title: "Источник удалён", description: "История инвентаря и обращений сохранена." });
      return client.invalidateQueries({ queryKey: queries.sources().queryKey });
    },
    onError: (error) => notify({ tone: "bad", title: "Источник не удалён", description: error.message }),
  });
  // Resolves to true once the source is deleted, false if the user changed
  // their mind or the server refused.
  const askRemove = async (source: Source): Promise<boolean> => {
    const yes = await confirm({
      title: `Удалить источник ${source.key}?`,
      description: "Агент перестанет к нему подключаться. История инвентаря и обращений останется, имя освободится для нового источника.",
      confirm: "Удалить",
      danger: true,
    });
    if (!yes) return false;
    return remove.mutateAsync(source).then(() => true, () => false);
  };
  const drawer = <SourceDrawer open={open} onOpenChange={setOpen} tenantId={tenantId} editing={editing} />;
  return {
    drawer,
    create: () => { setEditing(undefined); setOpen(true); },
    edit: (source: Source) => { setEditing(source); setOpen(true); },
    scan: (sources: Source[]) => scan.mutate(sources),
    scanning: scan.isPending,
    remove: askRemove,
  };
}

const connected = (source: Source) => Boolean(source.probedAt) && !source.statusCode;

function SourcesTab({ tenantId }: { tenantId: string }) {
  const can = useCan();
  const actions = useSourceActions(tenantId);
  const sources = useQuery({ ...queries.sources(), refetchInterval: 5000 });
  const coverage = usePermittedQuery(queries.coverage(24));
  const coverageOf = (id: string) => coverage.data?.find((row) => row.sourceId === id);

  const columns = useMemo<TableColumn<Source>[]>(() => [
    {
      id: "name", header: "Источник", enableHiding: false, accessorFn: (row) => row.key,
      cell: ({ row }) => (
        <div>
          <ObjectLink to={paths.source(row.original.id)} needs="getSource" className="font-medium">{row.original.key}</ObjectLink>
          <div className="text-xs text-fg-2">{engine(row.original.engine)} {row.original.engineVersion}</div>
        </div>
      ),
    },
    {
      id: "connection", header: "Подключение", accessorFn: (row) => row.statusCode || (row.probedAt ? "ok" : "wait"),
      cell: ({ row }) => (
        <div className="flex flex-col gap-0.5">
          <SourceState statusCode={row.original.statusCode} probedAt={row.original.probedAt} />
          {row.original.probedAt && row.original.statusCode && <span className="max-w-xs text-xs text-fg-2">{failure(row.original.statusCode).action}</span>}
        </div>
      ),
    },
    {
      id: "audit", header: "Аудит за сутки", meta: { needs: "getAuditCoverage" }, accessorFn: (row) => coverageOf(row.id)?.status ?? "",
      cell: ({ row }) => {
        const state = coverageOf(row.original.id);
        return state ? <CoverageState status={state.status} reason={state.reason} /> : <NoValue />;
      },
    },
    {
      id: "scan", header: "Последний скан", meta: { needs: "getAuditCoverage" }, accessorFn: (row) => coverageOf(row.id)?.lastScanAt ?? "",
      cell: ({ row }) => {
        const state = coverageOf(row.original.id);
        return state?.lastScanStatus ? <div><ScanState status={state.lastScanStatus} /><div className="text-xs text-fg-2">{ago(state.lastScanAt)}</div></div> : <span className="text-fg-3">Не было</span>;
      },
    },
    { id: "address", header: "Адрес", accessorFn: (row) => row.host, cell: ({ row }) => <Mono className="text-fg-2">{row.original.host}:{row.original.port}/{row.original.database}</Mono> },
    { id: "agent", header: "Агент", accessorFn: (row) => row.agentId, cell: ({ row }) => <ObjectLink to={paths.agent(row.original.agentId)} needs="getAgent" className="font-mono text-[13px]">{shortId(row.original.agentId)}</ObjectLink> },
    {
      id: "actions", header: "", enableHiding: false, enableSorting: false, meta: { className: "w-10 text-right" },
      cell: ({ row }) => {
        const source = row.original;
        const items = [
          can("requestScan") && connected(source) && <MenuItem key="scan" icon={<Play />} onSelect={() => actions.scan([source])}>Сканировать</MenuItem>,
          can("updateSource") && <MenuItem key="edit" icon={<Pencil />} onSelect={() => actions.edit(source)}>Изменить</MenuItem>,
          can("deleteSource") && <MenuSeparator key="separator" />,
          can("deleteSource") && <MenuItem key="delete" icon={<Trash2 />} className="text-bad [&_svg]:text-bad" onSelect={() => void actions.remove(source)}>Удалить</MenuItem>,
        ].filter(Boolean);
        if (items.length === 0) return null;
        return <Menu trigger={<Button variant="ghost" size="icon-sm" aria-label={`Действия с источником ${source.key}`}><MoreHorizontal /></Button>}>{items}</Menu>;
      },
    },
  ], [can, coverage.data, actions]);

  return (
    <>
      <Panel flush>
        <DataTable
          id="sources"
          columns={columns}
          data={sources.data}
          getRowId={(source) => source.id}
          loading={sources.isPending}
          error={sources.error}
          sortable
          empty={<EmptyState title="Источников пока нет" action={can("createSource") ? <Button variant="primary" onClick={actions.create}><Plus /> Добавить источник</Button> : undefined}>Источник — это база данных, к которой агент подключается для сканирования и сбора аудита.</EmptyState>}
          bulkActions={can("requestScan") ? (rows, clear) => {
            const ready = rows.filter(connected);
            return (
              <Button size="sm" disabled={ready.length === 0 || actions.scanning} onClick={() => { actions.scan(ready); clear(); }}>
                <Play /> Сканировать{ready.length < rows.length ? ` подключённые (${ready.length})` : ""}
              </Button>
            );
          } : undefined}
          toolbar={can("createSource") ? <Button variant="primary" onClick={actions.create}><Plus /> Добавить источник</Button> : undefined}
        />
      </Panel>
      {actions.drawer}
    </>
  );
}

function CoverageTab() {
  const coverage = useQuery(queries.coverage(24));
  const columns = useMemo<TableColumn<Schemas["CoverageRow"]>[]>(() => [
    { id: "source", header: "Источник", enableHiding: false, accessorFn: (row) => row.sourceKey, cell: ({ row }) => <div><ObjectLink to={paths.source(row.original.sourceId)} needs="getSource">{row.original.sourceKey}</ObjectLink><div className="text-xs text-fg-2">{engine(row.original.engine)}</div></div> },
    { id: "status", header: "Состояние", accessorFn: (row) => row.status, cell: ({ row }) => <div className="flex flex-col gap-0.5"><CoverageState status={row.original.status} reason={row.original.reason} />{row.original.reason && <FailureNote code={row.original.reason} className="max-w-xs" />}</div> },
    { id: "reads", header: "Аудит чтения", accessorFn: (row) => row.readsAudited, cell: ({ row }) => (row.original.readsAudited ? "Да" : <Badge tone="bad">Нет</Badge>) },
    { id: "statements", header: "Запросов", accessorFn: (row) => row.statements, meta: { align: "right" }, cell: ({ row }) => count(row.original.statements) },
    { id: "columns", header: "До колонок", accessorFn: (row) => row.columnsShare ?? -1, meta: { align: "right" }, cell: ({ row }) => percent(row.original.columnsShare) },
    { id: "principal", header: "Учётная запись", accessorFn: (row) => row.principalShare ?? -1, meta: { align: "right" }, cell: ({ row }) => percent(row.original.principalShare) },
    { id: "verified", header: "Подтверждён", accessorFn: (row) => row.verifiedShare ?? -1, meta: { align: "right" }, cell: ({ row }) => percent(row.original.verifiedShare) },
    { id: "gaps", header: "Потерь", accessorFn: (row) => row.gaps, meta: { align: "right" }, cell: ({ row }) => <span className={row.original.gaps > 0 ? "font-medium text-bad" : undefined}>{count(row.original.gaps)}</span> },
    { id: "last", header: "Последнее событие", accessorFn: (row) => row.lastEventAt ?? "", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastEventAt)}</span> },
  ], []);
  return (
    <Panel flush>
      <DataTable
        id="coverage"
        columns={columns}
        data={coverage.data}
        getRowId={(row) => row.sourceId}
        loading={coverage.isPending}
        error={coverage.error}
        sortable
        empty={<EmptyState title="Источники ещё не подключены" />}
        toolbar={<p className="py-1.5 text-[13px] text-fg-2">«Нет данных» значит, что измерять было нечего: это не ноль.</p>}
      />
    </Panel>
  );
}

const supportTone: Record<string, Tone> = { SUPPORT_AVAILABLE: "ok", SUPPORT_NOT_CONFIGURED: "warn", SUPPORT_UNKNOWN: "warn", SUPPORT_UNAVAILABLE: "neutral" };

function CapabilitiesTab() {
  const sources = useQuery(queries.sources());
  return (
    <Panel flush>
      <Loadable query={sources} isEmpty={(rows) => rows.every((row) => row.capabilities.length === 0)} empty={<EmptyState title="Возможности появятся, когда агент подключится к источникам" />}>
        {(rows) => {
          const probed = rows.filter((row) => row.capabilities.length > 0);
          const names = [...new Set(probed.flatMap((row) => row.capabilities.map((item) => item.capability)))];
          return (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-surface-2/60 text-xs text-fg-2">
                    <th scope="col" className="px-3 py-2 text-left font-medium">Что видно</th>
                    {probed.map((row) => <th key={row.id} scope="col" className="px-3 py-2 text-left font-medium whitespace-nowrap">{row.key}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {names.map((name) => (
                    <tr key={name} className="border-b border-border last:border-0">
                      <th scope="row" className="px-3 py-2 text-left font-normal whitespace-nowrap text-fg">{capability(name)}</th>
                      {probed.map((row) => {
                        const item = row.capabilities.find((entry) => entry.capability === name);
                        return (
                          <td key={row.id} className="px-3 py-2">
                            {item ? <Badge tone={supportTone[item.support] ?? "neutral"} title={item.reasonCode || undefined}>{support(item.support)}</Badge> : <NoValue />}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }}
      </Loadable>
    </Panel>
  );
}

function ScansTab() {
  const scans = useQuery(queries.scans());
  const sources = useQuery(queries.sources());
  const keyOf = (id: string) => sources.data?.find((source) => source.id === id)?.key ?? shortId(id);
  const columns = useMemo<TableColumn<Schemas["Scan"]>[]>(() => [
    { id: "source", header: "Источник", enableHiding: false, cell: ({ row }) => <ObjectLink to={paths.source(row.original.sourceId)} needs="getSource">{keyOf(row.original.sourceId)}</ObjectLink> },
    { id: "status", header: "Статус", cell: ({ row }) => <ScanState status={row.original.status} /> },
    { id: "created", header: "Запущено", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{dateTime(row.original.createdAt)}</span> },
    { id: "finished", header: "Завершено", cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{dateTime(row.original.finishedAt)}</span> },
    { id: "reason", header: "Причина", cell: ({ row }) => <FailureNote code={row.original.failureCode} /> },
  ], [sources.data]);
  return (
    <Panel flush>
      <DataTable id="scans" columns={columns} data={scans.data} getRowId={(scan) => scan.id} loading={scans.isPending} error={scans.error} empty={<EmptyState title="Сканирований ещё не было" />} toolbar={<p className="py-1.5 text-[13px] text-fg-2">Последние 20 заданий</p>} />
    </Panel>
  );
}

export function SourcesList({ tenantId }: { tenantId: string }) {
  return (
    <>
      <PageHeader title="Источники" description="Базы данных, к которым подключаются агенты: состояние подключения, аудита и сканирования." />
      <Tabs
        items={[
          { id: "sources", label: "Источники", needs: "listSources", content: <SourcesTab tenantId={tenantId} /> },
          { id: "coverage", label: "Покрытие аудита", needs: "getAuditCoverage", content: <CoverageTab /> },
          { id: "capabilities", label: "Возможности", needs: "listSources", content: <CapabilitiesTab /> },
          { id: "scans", label: "Сканирования", needs: "listScans", content: <ScansTab /> },
        ]}
      />
    </>
  );
}
