import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment } from "react";
import { Link, useParams } from "react-router-dom";

import { api, type Schemas } from "../api";
import { capability, count, dateTime, engine, percent, scanStatus, sourceStatus, support, tableKind } from "../labels";
import { ObjectLink, paths, Trail, useUrlFilters } from "../links";
import { Allowed, useCan } from "../permissions";
import { Categories, CoverageBadge, Facts, FailureNote, Loadable } from "../ui";

const pageSize = 100;

function Tables({ sourceId }: { sourceId: string }) {
  const [filters, setFilters] = useUrlFilters([]);
  const offset = Number(filters.offset) || 0;
  const tables = useQuery({
    queryKey: ["tables", sourceId, offset],
    queryFn: () => api.tables({ sourceId, limit: pageSize, offset }),
  });
  return (
    <section className="card">
      <h2>Базы, схемы и таблицы</h2>
      <Loadable query={tables} empty="Таблиц нет: источник ещё не сканировали." isEmpty={(page) => page.items.length === 0}>
        {(page) => (
          <>
            <div className="scroll">
              <table>
                <thead>
                  <tr><th>Таблица</th><th>Вид</th><th className="num">Колонок</th><th className="num">Чувствительных</th><th>Категории</th></tr>
                </thead>
                <tbody>
                  {page.items.map((table, index) => {
                    const previous = page.items[index - 1];
                    const group = !previous || previous.database !== table.database || previous.schema !== table.schema;
                    return (
                      <Fragment key={table.id}>
                        {group && (
                          <tr className="group"><td colSpan={5}>База {table.database} › схема {table.schema}</td></tr>
                        )}
                        <tr>
                          <td className="mono"><ObjectLink to={paths.table(table.id)} needs="getCatalogTable">{table.table}</ObjectLink></td>
                          <td className="muted">{tableKind(table.kind)}</td>
                          <td className="num">{count(table.columns)}</td>
                          <td className="num">{count(table.sensitiveColumns)}</td>
                          <td><Categories ids={table.categories} /></td>
                        </tr>
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {page.total > pageSize && (
              <div className="pager">
                <button disabled={offset === 0} onClick={() => setFilters({ offset: String(Math.max(0, offset - pageSize)) })}>Назад</button>
                <button disabled={offset + pageSize >= page.total} onClick={() => setFilters({ offset: String(offset + pageSize) })}>Дальше</button>
                <span>Всего: {count(page.total)}</span>
              </div>
            )}
          </>
        )}
      </Loadable>
    </section>
  );
}

function Coverage({ sourceId }: { sourceId: string }) {
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24) });
  return (
    <section className="card">
      <h2>Аудит за сутки</h2>
      <Loadable query={coverage} empty="">
        {(rows) => {
          const row = rows.find((item) => item.sourceId === sourceId);
          if (!row) return <div className="empty">Покрытие ещё не посчитано.</div>;
          return (
            <Facts
              items={[
                ["Состояние", <><CoverageBadge status={row.status} reason={row.reason} /><FailureNote code={row.reason} /></>],
                ["Аудит чтения", row.readsAudited ? "Да" : <span className="badge bad">Нет</span>],
                ["Запросов", count(row.statements)],
                ["Разобрано до колонок", percent(row.columnsShare)],
                ["Известна учётная запись", percent(row.principalShare)],
                ["Подтверждён пользователь", percent(row.verifiedShare)],
                ["Потерь аудита", count(row.gaps)],
                ["Последнее событие", dateTime(row.lastEventAt)],
              ]}
            />
          );
        }}
      </Loadable>
    </section>
  );
}

function Scans({ sourceId }: { sourceId: string }) {
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans });
  return (
    <section className="card">
      <h2>Сканирования</h2>
      <Loadable query={scans} empty="">
        {(rows) => {
          const own = rows.filter((row) => row.sourceId === sourceId);
          if (own.length === 0) return <div className="empty">Среди последних сканирований этого источника нет.</div>;
          return (
            <table>
              <thead><tr><th>Статус</th><th>Запущено</th><th>Завершено</th><th>Причина</th></tr></thead>
              <tbody>
                {own.map((row) => (
                  <tr key={row.id}>
                    <td>{scanStatus(row.status)}</td>
                    <td className="muted">{dateTime(row.createdAt)}</td>
                    <td className="muted">{dateTime(row.finishedAt)}</td>
                    <td><FailureNote code={row.failureCode} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          );
        }}
      </Loadable>
    </section>
  );
}

function Connection({ source }: { source: Schemas["Source"] }) {
  const can = useCan();
  const client = useQueryClient();
  const scan = useMutation({
    mutationFn: api.requestScan,
    onSuccess: () => client.invalidateQueries({ queryKey: ["scans"] }),
  });
  const status = sourceStatus(source.statusCode, source.probedAt);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Подключение</h2>
        <div className="actions">
          {can("requestScan") && !source.statusCode && source.probedAt && (
            <button disabled={scan.isPending} onClick={() => scan.mutate(source.id)}>Сканировать</button>
          )}
          <Allowed to="listAuditEvents">
            <Link to={paths.events({ sourceId: source.id })}>Обращения к источнику</Link>
          </Allowed>
        </div>
      </div>
      <Facts
        items={[
          ["Состояние", <><span className={`badge ${status.tone}`}>{status.label}</span><FailureNote code={source.statusCode} /></>],
          ["Агент", <ObjectLink className="mono" to={paths.agent(source.agentId)} needs="getAgent">{source.agentId}</ObjectLink>],
          ["Адрес", <span className="mono">{source.host}:{source.port}</span>],
          ["База данных", <span className="mono">{source.database}</span>],
          ["Пользователь", <span className="mono">{source.username}</span>],
          ["TLS", source.tls],
          ["Каталог журналов", source.auditDirectory ? <span className="mono">{source.auditDirectory}</span> : <span className="muted">не указан</span>],
          ["Проверено агентом", dateTime(source.probedAt)],
        ]}
      />
      {scan.isError && <div className="error">{scan.error.message}</div>}
      {scan.isSuccess && <p className="muted">Скан поставлен в очередь.</p>}
      {source.capabilities.length > 0 && (
        <>
          <h2 style={{ marginTop: 16 }}>Что источник позволяет видеть</h2>
          <div className="chips">
            {source.capabilities.map((item) => (
              <span key={item.capability} className={`badge ${item.support === "SUPPORT_AVAILABLE" ? "ok" : ""}`} title={support(item.support)}>
                {capability(item.capability)}: {support(item.support)}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

export function SourcePage() {
  const { id = "" } = useParams();
  const source = useQuery({ queryKey: ["source", id], queryFn: () => api.source(id) });
  return (
    <>
      <Trail>{[<ObjectLink key="infra" to="/infrastructure" needs="listSources">Инфраструктура</ObjectLink>, "Источник"]}</Trail>
      <Loadable query={source} empty="">
        {(data) => (
          <>
            <h1>{data.key}</h1>
            <p className="lead">{engine(data.engine)} {data.engineVersion}</p>
            <Connection source={data} />
            <Allowed to="getAuditCoverage"><Coverage sourceId={data.id} /></Allowed>
            <Allowed to="listCatalogTables"><Tables sourceId={data.id} /></Allowed>
            <Allowed to="listScans"><Scans sourceId={data.id} /></Allowed>
          </>
        )}
      </Loadable>
    </>
  );
}
