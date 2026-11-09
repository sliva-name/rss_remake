import { useMemo } from "react";

import type { Schemas } from "../api";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { dateTime, operatorAction, operatorActionDetails, shortId } from "../labels";
import { ObjectLink, paths } from "../links";
import { queries, usePermittedQuery } from "../queries";

type Action = Schemas["OperatorAction"];

// The object an action was about. A deleted source has no page any more, so
// its name stays text.
function ActionObject({ action, environments }: { action: Action; environments?: Schemas["Environment"][] }) {
  const label = action.objectLabel;
  switch (action.objectKind) {
    case "source":
      return action.action === "source.delete"
        ? <span>{label}</span>
        : <ObjectLink to={paths.source(action.objectId)} needs="getSource">{label || shortId(action.objectId)}</ObjectLink>;
    case "agent":
      return <ObjectLink to={paths.agent(action.objectId)} needs="getAgent">Агент <span className="font-mono">{shortId(action.objectId)}</span></ObjectLink>;
    case "environment":
      return <span>Среда «{label || environments?.find((item) => item.id === action.objectId)?.name || shortId(action.objectId)}»</span>;
    default:
      return <span>{label || "Организация"}</span>;
  }
}

function actorOf(action: Action): string {
  return action.actorSubject === "" ? "Платформа" : action.actorName;
}

export function actionColumns(environments?: Schemas["Environment"][], withObject = true): TableColumn<Action>[] {
  return [
    { id: "at", header: "Когда", accessorFn: (row) => row.at, cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{dateTime(row.original.at)}</span> },
    { id: "actor", header: "Кто", accessorFn: actorOf, cell: ({ row }) => <span className="whitespace-nowrap font-medium">{actorOf(row.original)}</span> },
    { id: "action", header: "Действие", accessorFn: (row) => operatorAction(row.action) },
    ...(withObject ? [{ id: "object", header: "Объект", accessorFn: (row: Action) => row.objectLabel, cell: ({ row }: { row: { original: Action } }) => <ActionObject action={row.original} environments={environments} /> } as TableColumn<Action>] : []),
    { id: "details", header: "Подробности", accessorFn: operatorActionDetails, cell: ({ getValue }) => <span className="text-fg-2">{getValue() as string}</span> },
  ];
}

const shownAtMost = 500;

export function Journal() {
  const actions = usePermittedQuery(queries.operatorActions());
  const environments = usePermittedQuery(queries.environments());
  const columns = useMemo(() => actionColumns(environments.data), [environments.data]);
  return (
    <>
      <PageHeader
        title="Журнал действий"
        description="Кто и когда менял источники и политику, выпускал токены, регистрировал и отзывал агентов. Записи нельзя изменить или удалить, значений и паролей в них нет."
      />
      <Panel flush>
        <DataTable
          id="journal"
          columns={columns}
          data={actions.data}
          getRowId={(row) => row.id}
          loading={actions.isPending}
          error={actions.error}
          sortable
          caption={actions.data && actions.data.length >= shownAtMost ? `Последние ${shownAtMost} действий` : undefined}
          empty={<EmptyState title="Действий пока не было">Здесь появятся изменения источников, политики и агентов.</EmptyState>}
        />
      </Panel>
    </>
  );
}

// The journal of one object, on its page.
export function ObjectJournal({ objectId }: { objectId: string }) {
  const actions = usePermittedQuery(queries.operatorActions(objectId));
  const columns = useMemo(() => actionColumns(undefined, false), []);
  return (
    <Panel title="Журнал действий" flush>
      <DataTable
        id="object-journal"
        columns={columns}
        data={actions.data}
        getRowId={(row) => row.id}
        loading={actions.isPending}
        error={actions.error}
        empty={<EmptyState title="Действий не было">Изменения этого объекта появятся здесь.</EmptyState>}
      />
    </Panel>
  );
}
