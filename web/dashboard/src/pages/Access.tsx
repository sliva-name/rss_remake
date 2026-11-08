import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { api, type Schemas } from "../api";
import { category, categoryIds, count, dateTime, eventType, eventTypeIds, evidenceLevel, executionStatus, identity, resolution } from "../labels";
import { useCan } from "../permissions";
import { FailureNote, Loadable, Page } from "../ui";

const pageSize = 50;

function Who({ event, scanner }: { event: Schemas["AuditEvent"]; scanner: boolean }) {
  if (event.type === "EVENT_TYPE_AUDIT_GAP") return <span className="muted">—</span>;
  if (scanner) {
    return (
      <>
        {event.databasePrincipal}
        <div><span className="badge">Сканер DataGuard</span></div>
      </>
    );
  }
  if (event.applicationPrincipal) {
    return (
      <>
        {event.applicationPrincipal}
        <div className="muted">{event.databasePrincipal}</div>
      </>
    );
  }
  return (
    <>
      {event.databasePrincipal || <span className="muted">Учётная запись неизвестна</span>}
      <div className="muted">{identity(event.identityConfidence)}</div>
    </>
  );
}

function What({ event }: { event: Schemas["AuditEvent"] }) {
  if (event.type === "EVENT_TYPE_AUDIT_GAP") {
    return (
      <>
        <span className="badge bad">
          {event.gapLostEvents === undefined ? "Сколько потеряно, неизвестно" : `Потеряно ${count(event.gapLostEvents)}`}
        </span>
        <FailureNote code={event.gapReason} />
      </>
    );
  }
  const shown = event.columns.length > 0 ? event.columns : event.tables;
  return (
    <>
      <div className="mono">{shown.slice(0, 4).join(", ") || "—"}{shown.length > 4 ? ` и ещё ${shown.length - 4}` : ""}</div>
      <div className="chips">
        {event.categories.map((id) => (
          <span key={id} className="badge warn">{category(id)}</span>
        ))}
      </div>
    </>
  );
}

export function Access() {
  const [filters, setFilters] = useState({ principal: "", category: "", eventType: "" });
  const [withScanner, setWithScanner] = useState(false);
  const [offset, setOffset] = useState(0);
  const events = useQuery({
    queryKey: ["events", filters, withScanner, offset],
    queryFn: () => api.events({
      ...filters, includeLogins: filters.eventType === "all" ? "true" : undefined,
      includeScanner: withScanner ? "true" : undefined,
      eventType: filters.eventType === "all" ? "" : filters.eventType, limit: pageSize, offset,
    }),
  });
  const can = useCan();
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  // The scanner is the login the agent was given for that source.
  const isScanner = (event: Schemas["AuditEvent"]) =>
    sources.data?.some((source) => source.id === event.sourceId && source.username === event.databasePrincipal) ?? false;
  const update = (key: keyof typeof filters, value: string) => {
    setFilters({ ...filters, [key]: value });
    setOffset(0);
  };

  return (
    <Page title="Обращения" lead="События нативного аудита за 7 дней. Колонка «Доказательство» показывает, что именно подтверждено: упоминание в запросе не значит, что данные были прочитаны.">
      <div className="filters">
        <label className="field">
          Пользователь
          <input value={filters.principal} onChange={(event) => update("principal", event.target.value)} placeholder="Точное совпадение" />
        </label>
        <label className="field">
          Категория
          <select value={filters.category} onChange={(event) => update("category", event.target.value)}>
            <option value="">Все</option>
            {categoryIds.map((id) => <option key={id} value={id}>{category(id)}</option>)}
          </select>
        </label>
        <label className="field">
          Тип
          <select value={filters.eventType} onChange={(event) => update("eventType", event.target.value)}>
            <option value="">Все, кроме входов</option>
            <option value="all">Все, включая входы</option>
            {eventTypeIds.map((id) => <option key={id} value={id}>{eventType(id)}</option>)}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={withScanner} onChange={(event) => { setWithScanner(event.target.checked); setOffset(0); }} />
          Чтения сканера DataGuard
        </label>
      </div>
      <section className="card">
        <Loadable query={events} empty="Событий нет." isEmpty={(page) => page.items.length === 0}>
          {(page) => (
            <>
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Время</th>
                      <th>Тип</th>
                      <th>Кто</th>
                      <th>К чему</th>
                      <th>Исход</th>
                      <th>Доказательство</th>
                      <th>Разбор</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((event) => (
                      <tr key={event.id}>
                        <td className="muted">{dateTime(event.time)}</td>
                        <td>{eventType(event.type)}</td>
                        <td><Who event={event} scanner={isScanner(event)} /></td>
                        <td><What event={event} /></td>
                        <td>
                          {executionStatus(event.executionStatus)}
                          {event.errorCode && <div className="muted mono">{event.errorCode}</div>}
                        </td>
                        <td>{evidenceLevel(event.evidenceLevel)}</td>
                        <td>{resolution(event.objectResolution)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="pager">
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>Назад</button>
                <button disabled={offset + pageSize >= page.total} onClick={() => setOffset(offset + pageSize)}>Дальше</button>
                <span>{page.totalExact ? `Всего: ${count(page.total)}` : `Больше ${count(page.total)}, уточните фильтр`}</span>
              </div>
            </>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
