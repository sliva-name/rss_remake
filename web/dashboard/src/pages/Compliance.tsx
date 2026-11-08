import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { category, count, dateTime } from "../labels";
import { CategoryLink } from "../links";
import { Allowed, useCan } from "../permissions";
import { Loadable, Page } from "../ui";

export function Compliance() {
  const can = useCan();
  const categories = useQuery({ queryKey: ["categories"], queryFn: api.categories, enabled: can("listAccessByCategory") });
  const inventory = useQuery({ queryKey: ["inventory"], queryFn: api.inventory, enabled: can("getCatalogSummary") });

  return (
    <Page title="Отчёты" lead="Где хранятся категории данных и кто к ним обращался за 7 дней.">
      <Allowed to="getCatalogSummary">
        <section className="card">
          <h2>Инвентарь по категориям</h2>
          <Loadable query={inventory} empty="Каталог пуст." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <table>
                <thead>
                  <tr>
                    <th>Категория</th>
                    <th className="num">Колонок</th>
                    <th className="num">Таблиц</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.category}>
                      <td><CategoryLink id={row.category}>{category(row.category)}</CategoryLink></td>
                      <td className="num">{count(row.columns)}</td>
                      <td className="num">{count(row.tables)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Loadable>
        </section>
      </Allowed>
      <Allowed to="listAccessByCategory">
        <section className="card">
          <h2>Доступ по категориям</h2>
          <Loadable query={categories} empty="Обращений к чувствительным данным не было." isEmpty={(rows) => rows.length === 0}>
            {(rows) => (
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Категория</th>
                      <th className="num">Обращений</th>
                      <th className="num">Пользователей</th>
                      <th className="num">Источников</th>
                      <th>Последнее</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.category}>
                        <td><CategoryLink id={row.category}>{category(row.category)}</CategoryLink></td>
                        <td className="num">{count(row.events)}</td>
                        <td className="num">{count(row.principals)}</td>
                        <td className="num">{count(row.sources)}</td>
                        <td className="muted">{dateTime(row.lastAccess)}</td>
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
