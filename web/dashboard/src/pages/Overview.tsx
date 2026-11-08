import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { category, change, count, dateTime, percent } from "../labels";
import { CategoryLink, ObjectLink, paths } from "../links";
import { Allowed, useCan } from "../permissions";
import { CoverageBadge, Loadable, Page, Tile } from "../ui";

export function Overview() {
  const can = useCan();
  const summary = useQuery({ queryKey: ["summary"], queryFn: api.summary, enabled: can("getAccessSummary") });
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24), enabled: can("getAuditCoverage") });
  const categories = useQuery({ queryKey: ["categories"], queryFn: api.categories, enabled: can("listAccessByCategory") });
  const changes = useQuery({ queryKey: ["changes"], queryFn: api.changes, enabled: can("listCatalogChanges") });
  const blind = coverage.data?.filter((row) => row.status === "BLIND" || row.status === "NOT_CONFIGURED") ?? [];

  return (
    <Page title="Обзор" lead="Обращения за последние 7 дней и текущее состояние наблюдения.">
      {blind.length > 0 && (
        <div className="alert" role="alert">
          Нет наблюдения за источниками: {blind.map((row) => row.sourceKey).join(", ")}. Отсутствие событий по ним ничего
          не значит.
        </div>
      )}
      <Allowed to="getAccessSummary">
        <Loadable query={summary} empty="">
          {(data) => (
            <div className="tiles">
              <Tile value={count(data.events)} label="Обращений" />
              <Tile value={count(data.sensitiveEvents)} label="К чувствительным данным" />
              <Tile value={count(data.failedEvents)} label="Отказов" />
              <Tile value={count(data.principals)} label="Пользователей" />
              <Tile value={count(data.gaps)} label="Потерь аудита" />
            </div>
          )}
        </Loadable>
      </Allowed>

      <Allowed to="getAuditCoverage">
        <section className="card">
          <h2>Покрытие за сутки</h2>
          <Loadable query={coverage} empty="Источники ещё не подключены." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Источник</th>
                      <th>Состояние</th>
                      <th className="num">Разобрано до колонок</th>
                      <th className="num">Подтверждён пользователь</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.sourceId}>
                        <td><ObjectLink to={paths.source(row.sourceId)} needs="getSource">{row.sourceKey}</ObjectLink></td>
                        <td>
                          <CoverageBadge status={row.status} reason={row.reason} />
                        </td>
                        <td className="num">{percent(row.columnsShare)}</td>
                        <td className="num">{percent(row.verifiedShare)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
        </section>
      </Allowed>

      <Allowed to="listAccessByCategory">
        <section className="card">
          <h2>Что читают чаще всего</h2>
          <Loadable query={categories} empty="Обращений к чувствительным данным не было." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <table>
                <thead>
                  <tr>
                    <th>Категория</th>
                    <th className="num">Обращений</th>
                    <th className="num">Пользователей</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, 6).map((row) => (
                    <tr key={row.category}>
                      <td><CategoryLink id={row.category}>{category(row.category)}</CategoryLink></td>
                      <td className="num">{count(row.events)}</td>
                      <td className="num">{count(row.principals)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Loadable>
        </section>
      </Allowed>

      <Allowed to="listCatalogChanges">
        <section className="card">
          <h2>Изменения в инвентаре</h2>
          <Loadable query={changes} empty="Изменений пока нет." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <tbody>
                    {rows.map((row, index) => (
                      <tr key={index}>
                        <td className="muted">{dateTime(row.occurredAt)}</td>
                        <td>{change(row.kind)}</td>
                        <td>{row.sourceKey}</td>
                        <td className="mono">
                          <ObjectLink to={paths.table(row.tableId)} needs="getCatalogTable">{row.tableName}</ObjectLink>
                          {row.columnId && row.columnName && (
                            <>.<ObjectLink to={paths.column(row.columnId)} needs="getCatalogColumn">{row.columnName}</ObjectLink></>
                          )}
                        </td>
                        <td>{row.categoryId ? <CategoryLink id={row.categoryId}>{category(row.categoryId)}</CategoryLink> : ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Loadable>
        </section>
      </Allowed>
    </Page>
  );
}
