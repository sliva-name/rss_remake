import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { ScrollText } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { api, type Schemas } from "../api";
import { Categories, Mono } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { PageHeader } from "../components/ui/page";
import { Facts, Panel } from "../components/ui/panel";
import { EmptyState, ErrorState, Loading } from "../components/ui/state";
import { DataTable } from "../components/ui/table";
import { dateTime, tableKind } from "../labels";
import { ObjectLink, paths } from "../links";
import { useCan } from "../permissions";
import { FavoriteButton, type ObjectRef, useRememberVisit } from "../workspace";

// The source's name in a trail. Without permission to read the source, its
// identifier is all the page can honestly show.
export function SourceCrumb({ id }: { id: string }) {
  const can = useCan();
  const source = useQuery({ queryKey: ["source", id], queryFn: () => api.source(id), enabled: can("getSource") });
  return <ObjectLink to={paths.source(id)} needs="getSource">{source.data?.key ?? "Источник"}</ObjectLink>;
}

export function Renames({ renames }: { renames: Schemas["Rename"][] }) {
  if (renames.length === 0) return null;
  return (
    <Panel title="Переименования" description="Определяются по совпадению структуры и могут ошибаться. История обращений идёт за объектом, а не за именем." flush>
      <ul className="divide-y divide-border">
        {renames.map((rename) => (
          <li key={rename.detectedAt + rename.oldName} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
            <Mono className="text-fg-2 line-through">{rename.oldName}</Mono>
            <span aria-hidden className="text-fg-3">→</span>
            <Mono>{rename.newName}</Mono>
            <span className="ml-auto text-[13px] text-fg-3">{dateTime(rename.detectedAt)}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function RemovedNote({ status, lastSeenAt }: { status: string; lastSeenAt: string }): ReactNode {
  if (status !== "removed") return null;
  return (
    <div role="status" className="mb-4 rounded-lg border border-warn/30 bg-warn-bg px-4 py-3 text-sm text-warn">
      Объекта больше нет в базе: последний скан видел его {dateTime(lastSeenAt)}. История обращений сохранена.
    </div>
  );
}

type Column = Schemas["TableColumn"];

export function TablePage() {
  const { id = "" } = useParams();
  const can = useCan();
  const table = useQuery({ queryKey: ["table", id], queryFn: () => api.table(id) });
  const columns = useMemo<ColumnDef<Column, unknown>[]>(() => [
    { id: "ordinal", header: "№", accessorFn: (row) => row.ordinal, meta: { align: "right", className: "w-12" }, cell: ({ row }) => <span className="text-fg-3">{row.original.ordinal}</span> },
    { id: "name", header: "Колонка", enableHiding: false, accessorFn: (row) => row.name, cell: ({ row }) => <ObjectLink to={paths.column(row.original.id)} needs="getCatalogColumn" className="font-mono text-[13px]">{row.original.name}</ObjectLink> },
    { id: "type", header: "Тип", accessorFn: (row) => row.nativeType, cell: ({ row }) => <Mono className="text-fg-2">{row.original.nativeType}</Mono> },
    { id: "nullable", header: "NULL", accessorFn: (row) => row.nullable, cell: ({ row }) => <span className="text-fg-2">{row.original.nullable ? "Да" : "Нет"}</span> },
    { id: "categories", header: "Категории", accessorFn: (row) => row.categories.length, cell: ({ row }) => <Categories ids={row.original.categories} /> },
  ], []);
  const item: ObjectRef | undefined = table.data && { kind: "table", id, label: table.data.table, context: `${table.data.database} › ${table.data.schema}` };
  useRememberVisit(item);

  if (table.isPending) return <Loading rows={8} />;
  if (table.isError) return <ErrorState error={table.error} />;
  const data = table.data;
  const sensitive = data.columns.filter((column) => column.categories.length > 0).length;

  return (
    <>
      <PageHeader
        breadcrumbs={[<Link key="inventory" to="/inventory">Инвентаризация</Link>, <SourceCrumb key="source" id={data.sourceId} />, `${data.database} › ${data.schema}`]}
        title={data.table}
        mono
        meta={
          <>
            <Badge>{tableKind(data.kind)}</Badge>
            {sensitive > 0 ? <Badge tone="warn">Чувствительных колонок: {sensitive}</Badge> : <Badge>Чувствительных данных не найдено</Badge>}
          </>
        }
        actions={
          <>
            {item && <FavoriteButton item={item} />}
            {can("listAuditEvents") && <Button asChild><Link to={paths.events({ tableId: data.id })}><ScrollText /> Обращения к таблице</Link></Button>}
          </>
        }
      />
      <RemovedNote status={data.status} lastSeenAt={data.lastSeenAt} />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)]">
        <Panel title="Колонки" flush>
          <DataTable id="table-columns" columns={columns} data={data.columns} getRowId={(column) => column.id} sortable empty={<EmptyState title="Колонок нет" />} />
        </Panel>
        <div className="flex flex-col gap-6">
          <Panel title="Таблица">
            <Facts
              items={[
                ["Источник", <SourceCrumb key="source" id={data.sourceId} />],
                ["База", <Mono key="db">{data.database}</Mono>],
                ["Схема", <Mono key="schema">{data.schema}</Mono>],
                ["Впервые обнаружена", dateTime(data.firstSeenAt)],
                ["Последний скан видел", dateTime(data.lastSeenAt)],
              ]}
            />
          </Panel>
          <Renames renames={data.renames} />
        </div>
      </div>
    </>
  );
}
