import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api, type Schemas } from "../api";
import { category, count, dateTime, eventType, executionStatus, identity, percent, samplingMethod } from "../labels";
import { ObjectLink, paths, Trail } from "../links";
import { Allowed } from "../permissions";
import { Confidence, Facts, Loadable } from "../ui";
import { RemovedNote, Renames, SourceCrumb } from "./TablePage";

// What the classifier relied on, in the words an auditor would use.
function grounds(decision: Schemas["Classification"]): string {
  const signs = [];
  if (decision.nameMatch) signs.push("имя колонки");
  if (decision.contextMatch) signs.push("имя таблицы");
  if (decision.rowsInspected > 0) signs.push(`формат у ${percent(decision.formatRatio)} значений`);
  if (decision.checksumRatio !== undefined) signs.push(`контрольная сумма у ${percent(decision.checksumRatio)}`);
  return signs.length > 0 ? signs.join(", ") : "—";
}

function Classifications({ decisions }: { decisions: Schemas["Classification"][] }) {
  return (
    <section className="card">
      <h2>Классификация</h2>
      {decisions.length === 0 ? (
        <div className="empty">Классификатор эту колонку не оценивал.</div>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Категория</th><th>Решение</th><th>Уверенность</th><th>Основание</th><th>Выборка</th>
                <th className="num">Совпало строк</th><th className="num">Уникальных ≈</th><th>Обновлено</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((decision) => (
                <tr key={decision.categoryId}>
                  <td>{category(decision.categoryId)}</td>
                  <td>{decision.detected ? <span className="badge warn">Найдено</span> : <span className="badge">Не найдено</span>}</td>
                  <td><Confidence value={decision.confidence} /></td>
                  <td className="hint">{grounds(decision)}</td>
                  <td className="muted">{samplingMethod(decision.samplingMethod)}</td>
                  <td className="num">{count(decision.rowsMatched)}<span className="muted"> из {count(decision.rowsInspected)}</span></td>
                  <td className="num">{count(decision.uniqueEstimate)}</td>
                  <td className="muted">{dateTime(decision.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const recent = 10;

function RecentAccess({ columnId }: { columnId: string }) {
  const events = useQuery({ queryKey: ["events", "column", columnId], queryFn: () => api.events({ columnId, limit: recent }) });
  return (
    <section className="card">
      <div className="card-head">
        <h2>Последние обращения за 7 дней</h2>
        <Link to={paths.events({ columnId })}>Все обращения к колонке</Link>
      </div>
      <Loadable query={events} empty="За 7 дней к колонке не обращались." isEmpty={(page) => page.items.length === 0}>
        {(page) => (
          <table>
            <thead><tr><th>Время</th><th>Тип</th><th>Кто</th><th>Исход</th></tr></thead>
            <tbody>
              {page.items.map((event) => (
                <tr key={event.id}>
                  <td className="muted">{dateTime(event.time)}</td>
                  <td>{eventType(event.type)}</td>
                  <td>
                    {event.applicationPrincipal || event.databasePrincipal || <span className="muted">Учётная запись неизвестна</span>}
                    <div className="muted">{event.applicationPrincipal ? event.databasePrincipal : identity(event.identityConfidence)}</div>
                  </td>
                  <td>{executionStatus(event.executionStatus)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Loadable>
    </section>
  );
}

export function ColumnPage() {
  const { id = "" } = useParams();
  const column = useQuery({ queryKey: ["column", id], queryFn: () => api.column(id) });
  return (
    <Loadable query={column} empty="">
      {(data) => (
        <>
          <Trail>
            {[
              <SourceCrumb key="source" id={data.sourceId} />,
              `База ${data.database}`,
              `Схема ${data.schema}`,
              <ObjectLink key="table" className="mono" to={paths.table(data.tableId)} needs="getCatalogTable">{data.table}</ObjectLink>,
              "Колонка",
            ]}
          </Trail>
          <h1 className="mono">{data.name}</h1>
          <p className="lead">Что классификатор решил о колонке и на чём основано решение. Значения в платформу не передаются.</p>
          <RemovedNote status={data.status} lastSeenAt={data.lastSeenAt} />
          <section className="card">
            <Facts
              items={[
                ["Тип", <span className="mono">{data.nativeType}</span>],
                ["Допускает NULL", data.nullable ? "Да" : "Нет"],
                ["Позиция", String(data.ordinal)],
                ["Впервые обнаружена", dateTime(data.firstSeenAt)],
                ["Последний скан видел", dateTime(data.lastSeenAt)],
              ]}
            />
          </section>
          <Classifications decisions={data.classifications} />
          <Allowed to="listAuditEvents"><RecentAccess columnId={data.id} /></Allowed>
          <Renames renames={data.renames} />
        </>
      )}
    </Loadable>
  );
}
