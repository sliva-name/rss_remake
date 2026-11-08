import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api, type Schemas } from "../api";
import { dateTime, tableKind } from "../labels";
import { ObjectLink, paths, Trail } from "../links";
import { Allowed, useCan } from "../permissions";
import { Categories, Facts, Loadable } from "../ui";

// The source name in a trail. Without permission to read the source, its
// identifier is all the page can honestly show.
export function SourceCrumb({ id }: { id: string }) {
  const can = useCan();
  const source = useQuery({ queryKey: ["source", id], queryFn: () => api.source(id), enabled: can("getSource") });
  return <ObjectLink to={paths.source(id)} needs="getSource">{source.data?.key ?? "Источник"}</ObjectLink>;
}

export function Renames({ renames }: { renames: Schemas["Rename"][] }) {
  if (renames.length === 0) return null;
  return (
    <section className="card">
      <h2>Переименования</h2>
      <table>
        <thead><tr><th>Когда замечено</th><th>Было</th><th>Стало</th></tr></thead>
        <tbody>
          {renames.map((rename) => (
            <tr key={rename.detectedAt + rename.oldName}>
              <td className="muted">{dateTime(rename.detectedAt)}</td>
              <td className="mono">{rename.oldName}</td>
              <td className="mono">{rename.newName}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted">Переименование определяется по совпадению структуры и может ошибиться. История обращений идёт за объектом, а не за именем.</p>
    </section>
  );
}

export function RemovedNote({ status, lastSeenAt }: { status: string; lastSeenAt: string }) {
  if (status !== "removed") return null;
  return <div className="alert" role="status">Объекта больше нет в базе: последний скан видел его {dateTime(lastSeenAt)}. История обращений к нему сохранена.</div>;
}

export function TablePage() {
  const { id = "" } = useParams();
  const table = useQuery({ queryKey: ["table", id], queryFn: () => api.table(id) });
  return (
    <Loadable query={table} empty="">
      {(data) => (
        <>
          <Trail>{[<SourceCrumb key="source" id={data.sourceId} />, `База ${data.database}`, `Схема ${data.schema}`, "Таблица"]}</Trail>
          <h1 className="mono">{data.table}</h1>
          <p className="lead">Колонки таблицы и найденные в них категории. Значения в платформу не передаются.</p>
          <RemovedNote status={data.status} lastSeenAt={data.lastSeenAt} />
          <section className="card">
            <div className="card-head">
              <h2>Таблица</h2>
              <Allowed to="listAuditEvents">
                <Link to={paths.events({ tableId: data.id })}>Обращения к таблице</Link>
              </Allowed>
            </div>
            <Facts
              items={[
                ["Вид", tableKind(data.kind)],
                ["Впервые обнаружена", dateTime(data.firstSeenAt)],
                ["Последний скан видел", dateTime(data.lastSeenAt)],
              ]}
            />
          </section>
          <section className="card">
            <h2>Колонки</h2>
            {data.columns.length === 0 ? (
              <div className="empty">Колонок нет.</div>
            ) : (
              <div className="scroll">
                <table>
                  <thead><tr><th className="num">№</th><th>Колонка</th><th>Тип</th><th>NULL</th><th>Категории</th></tr></thead>
                  <tbody>
                    {data.columns.map((column) => (
                      <tr key={column.id}>
                        <td className="num muted">{column.ordinal}</td>
                        <td className="mono"><ObjectLink to={paths.column(column.id)} needs="getCatalogColumn">{column.name}</ObjectLink></td>
                        <td className="mono muted">{column.nativeType}</td>
                        <td className="muted">{column.nullable ? "Да" : "Нет"}</td>
                        <td><Categories ids={column.categories} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <Renames renames={data.renames} />
        </>
      )}
    </Loadable>
  );
}
