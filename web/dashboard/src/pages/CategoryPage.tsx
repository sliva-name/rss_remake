import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { category, count, dateTime, eventType, executionStatus, identity } from "../labels";
import { ObjectLink, paths, Trail } from "../links";
import { Allowed, useCan } from "../permissions";
import { Confidence, Loadable, Page, Tile } from "../ui";

const shown = 20;

function Figures({ id }: { id: string }) {
  const can = useCan();
  const inventory = useQuery({ queryKey: ["inventory"], queryFn: api.inventory, enabled: can("getCatalogSummary") });
  const access = useQuery({ queryKey: ["categories"], queryFn: api.categories, enabled: can("listAccessByCategory") });
  const stored = inventory.data?.find((row) => row.category === id);
  const read = access.data?.find((row) => row.category === id);
  return (
    <div className="tiles">
      {can("getCatalogSummary") && inventory.data && (
        <>
          <Tile value={count(stored?.columns ?? 0)} label="Колонок" />
          <Tile value={count(stored?.tables ?? 0)} label="Таблиц" />
        </>
      )}
      {can("listAccessByCategory") && access.data && (
        <>
          <Tile value={count(read?.events ?? 0)} label="Обращений за 7 дней" />
          <Tile value={count(read?.principals ?? 0)} label="Пользователей" />
          <Tile value={count(read?.sources ?? 0)} label="Источников" />
        </>
      )}
    </div>
  );
}

function Storage({ id }: { id: string }) {
  const can = useCan();
  const columns = useQuery({ queryKey: ["catalog", id, "", 0, shown], queryFn: () => api.catalog({ category: id, limit: shown }) });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  return (
    <section className="card">
      <div className="card-head">
        <h2>Где хранятся</h2>
        <Link to={paths.catalog({ category: id })}>Все колонки в каталоге</Link>
      </div>
      <Loadable query={columns} empty="В каталоге таких колонок нет." isEmpty={(page) => page.items.length === 0}>
        {(page) => (
          <>
            <div className="scroll">
              <table>
                <thead><tr><th>Источник</th><th>Колонка</th><th>Уверенность</th></tr></thead>
                <tbody>
                  {page.items.map((item) => (
                    <tr key={item.columnId}>
                      <td>
                        <ObjectLink to={paths.source(item.sourceId)} needs="getSource">
                          {sources.data?.find((source) => source.id === item.sourceId)?.key ?? "Источник"}
                        </ObjectLink>
                      </td>
                      <td className="mono">
                        <ObjectLink to={paths.table(item.tableId)} needs="getCatalogTable">{item.schema}.{item.table}</ObjectLink>.
                        <ObjectLink to={paths.column(item.columnId)} needs="getCatalogColumn">{item.column}</ObjectLink>
                      </td>
                      <td><Confidence value={item.confidence} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {page.total > page.items.length && <p className="muted">Показаны {page.items.length} из {count(page.total)}.</p>}
          </>
        )}
      </Loadable>
    </section>
  );
}

function Readers({ id }: { id: string }) {
  const principals = useQuery({ queryKey: ["principals", id], queryFn: () => api.principals(id) });
  return (
    <section className="card">
      <h2>Кто обращался за 7 дней</h2>
      <Loadable query={principals} empty="За 7 дней к этим данным не обращались." isEmpty={(rows) => rows.length === 0}>
        {(rows) => (
          <div className="scroll">
            <table>
              <thead>
                <tr><th>Пользователь</th><th>Учётная запись СУБД</th><th>Как установлен</th><th className="num">Обращений</th><th className="num">Источников</th><th>Последнее</th></tr>
              </thead>
              <tbody>
                {rows.map((row, index) => {
                  const principal = row.applicationPrincipal || row.databasePrincipal;
                  return (
                    <tr key={index}>
                      <td>
                        {row.applicationPrincipal ? (
                          <ObjectLink to={paths.events({ principal, category: id })} needs="listAuditEvents">{row.applicationPrincipal}</ObjectLink>
                        ) : (
                          <span className="muted">Не идентифицирован</span>
                        )}
                      </td>
                      <td className="mono">
                        {row.databasePrincipal ? (
                          <ObjectLink to={paths.events({ principal: row.databasePrincipal, category: id })} needs="listAuditEvents">{row.databasePrincipal}</ObjectLink>
                        ) : "—"}
                      </td>
                      <td className="muted">{identity(row.identityConfidence)}</td>
                      <td className="num">{count(row.events)}</td>
                      <td className="num">{count(row.sources)}</td>
                      <td className="muted">{dateTime(row.lastAccess)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Loadable>
    </section>
  );
}

function Recent({ id }: { id: string }) {
  const events = useQuery({ queryKey: ["events", "category", id], queryFn: () => api.events({ category: id, limit: 10 }) });
  return (
    <section className="card">
      <div className="card-head">
        <h2>Последние обращения</h2>
        <Link to={paths.events({ category: id })}>Все обращения к категории</Link>
      </div>
      <Loadable query={events} empty="За 7 дней обращений не было." isEmpty={(page) => page.items.length === 0}>
        {(page) => (
          <table>
            <thead><tr><th>Время</th><th>Тип</th><th>Кто</th><th>К чему</th><th>Исход</th></tr></thead>
            <tbody>
              {page.items.map((event) => (
                <tr key={event.id}>
                  <td className="muted">{dateTime(event.time)}</td>
                  <td>{eventType(event.type)}</td>
                  <td>{event.applicationPrincipal || event.databasePrincipal || <span className="muted">Учётная запись неизвестна</span>}</td>
                  <td className="mono">{(event.columns.length > 0 ? event.columns : event.tables).slice(0, 3).join(", ")}</td>
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

// One page answers "who reads this kind of data": where it is stored, who read
// it and what they did, each with a way to the details.
export function CategoryPage() {
  const { id = "" } = useParams();
  return (
    <>
      <Trail>{[<ObjectLink key="catalog" to="/catalog" needs="listCatalogColumns">Каталог данных</ObjectLink>, "Категория"]}</Trail>
      <Page title={category(id)} lead="Где хранятся эти данные, кто к ним обращался за 7 дней и что именно делал. Значения в платформу не передаются.">
        <Figures id={id} />
        <Allowed to="listCatalogColumns"><Storage id={id} /></Allowed>
        <Allowed to="listAccessByPrincipal"><Readers id={id} /></Allowed>
        <Allowed to="listAuditEvents"><Recent id={id} /></Allowed>
      </Page>
    </>
  );
}
