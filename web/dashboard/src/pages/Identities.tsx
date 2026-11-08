import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { category, count, dateTime, identity } from "../labels";
import { CategoryLink, ObjectLink, paths } from "../links";
import { Loadable, Page } from "../ui";

export function Identities() {
  const principals = useQuery({ queryKey: ["principals"], queryFn: () => api.principals() });
  return (
    <Page title="Пользователи" lead="Кто обращался к данным за 7 дней. Подтверждённые и заявленные личности показаны отдельно и не объединяются.">
      <section className="card">
        <Loadable query={principals} empty="Обращений не было." isEmpty={(rows) => rows.length === 0}>
          {(rows) => (
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    <th>Пользователь</th>
                    <th>Учётная запись СУБД</th>
                    <th>Как установлен</th>
                    <th className="num">Обращений</th>
                    <th className="num">К чувствительным</th>
                    <th>Категории</th>
                    <th>Последнее</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, index) => (
                    <tr key={index}>
                      <td>
                        {row.applicationPrincipal ? (
                          <ObjectLink to={paths.events({ principal: row.applicationPrincipal })} needs="listAuditEvents">{row.applicationPrincipal}</ObjectLink>
                        ) : (
                          <span className="muted">Не идентифицирован</span>
                        )}
                      </td>
                      <td className="mono">
                        {row.databasePrincipal ? (
                          <ObjectLink to={paths.events({ principal: row.databasePrincipal })} needs="listAuditEvents">{row.databasePrincipal}</ObjectLink>
                        ) : "—"}
                      </td>
                      <td className="muted">{identity(row.identityConfidence)}</td>
                      <td className="num">{count(row.events)}</td>
                      <td className="num">{count(row.sensitiveEvents)}</td>
                      <td>
                        <div className="chips">
                          {row.categories.map((id) => <CategoryLink key={id} id={id} className="badge">{category(id)}</CategoryLink>)}
                        </div>
                      </td>
                      <td className="muted">{dateTime(row.lastAccess)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
