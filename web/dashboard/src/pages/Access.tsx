import { useQuery } from "@tanstack/react-query";

import { api, type Schemas } from "../api";
import { category, categoryIds, count, dateTime, eventType, eventTypeIds, evidenceLevel, executionStatus, identity, resolution } from "../labels";
import { CategoryLink, ObjectLink, paths, useUrlFilters } from "../links";
import { useCan } from "../permissions";
import { FailureNote, Loadable, Page } from "../ui";

const pageSize = 50;

// A principal narrows the list to that principal: the next question after "who"
// is usually "what else did they read".
function Pick({ name, onPick }: { name: string; onPick: (name: string) => void }) {
  return <button className="link" title="Показать только этого пользователя" onClick={() => onPick(name)}>{name}</button>;
}

function Who({ event, scanner, onPick }: { event: Schemas["AuditEvent"]; scanner: boolean; onPick: (name: string) => void }) {
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
        <Pick name={event.applicationPrincipal} onPick={onPick} />
        <div className="muted">{event.databasePrincipal}</div>
      </>
    );
  }
  return (
    <>
      {event.databasePrincipal ? <Pick name={event.databasePrincipal} onPick={onPick} /> : <span className="muted">Учётная запись неизвестна</span>}
      <div className="muted">{identity(event.identityConfidence)}</div>
    </>
  );
}

function What({ event, sourceKey }: { event: Schemas["AuditEvent"]; sourceKey: string | undefined }) {
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
      <div className="muted">
        <ObjectLink to={paths.source(event.sourceId)} needs="getSource">{sourceKey ?? "Источник"}</ObjectLink>
      </div>
      <div className="chips">
        {event.categories.map((id) => (
          <CategoryLink key={id} id={id} className="badge warn">{category(id)}</CategoryLink>
        ))}
      </div>
    </>
  );
}

// The object a link narrowed the list to, named so the user sees what is filtered
// and can drop it.
function ObjectFilter({ label, name, onClear }: { label: string; name: string | undefined; onClear: () => void }) {
  return (
    <span className="chip-filter">
      {label}: <b className="mono">{name ?? "…"}</b>
      <button aria-label={`Убрать фильтр «${label}»`} onClick={onClear}>×</button>
    </span>
  );
}

const filterKeys = ["sourceId", "tableId", "columnId", "principal", "category", "eventType", "scanner"] as const;

export function Access() {
  const can = useCan();
  const [filters, update] = useUrlFilters(filterKeys);
  const offset = Number(filters.offset) || 0;
  const events = useQuery({
    queryKey: ["events", filters],
    queryFn: () => api.events({
      sourceId: filters.sourceId, tableId: filters.tableId, columnId: filters.columnId,
      principal: filters.principal, category: filters.category,
      includeLogins: filters.eventType === "all" ? "true" : undefined,
      includeScanner: filters.scanner ? "true" : undefined,
      eventType: filters.eventType === "all" ? "" : filters.eventType, limit: pageSize, offset,
    }),
  });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const table = useQuery({
    queryKey: ["table", filters.tableId], queryFn: () => api.table(filters.tableId),
    enabled: filters.tableId !== "" && can("getCatalogTable"),
  });
  const column = useQuery({
    queryKey: ["column", filters.columnId], queryFn: () => api.column(filters.columnId),
    enabled: filters.columnId !== "" && can("getCatalogColumn"),
  });
  // The scanner is the login the agent was given for that source.
  const isScanner = (event: Schemas["AuditEvent"]) =>
    sources.data?.some((source) => source.id === event.sourceId && source.username === event.databasePrincipal) ?? false;
  const sourceKey = (id: string) => sources.data?.find((source) => source.id === id)?.key;

  return (
    <Page title="Обращения" lead="События нативного аудита за 7 дней. Колонка «Доказательство» показывает, что именно подтверждено: упоминание в запросе не значит, что данные были прочитаны.">
      {(filters.tableId || filters.columnId) && (
        <div className="filters">
          {filters.tableId && (
            <ObjectFilter label="Таблица" name={table.data && `${table.data.schema}.${table.data.table}`} onClear={() => update({ tableId: "" })} />
          )}
          {filters.columnId && (
            <ObjectFilter label="Колонка" name={column.data && `${column.data.table}.${column.data.name}`} onClear={() => update({ columnId: "" })} />
          )}
        </div>
      )}
      <div className="filters">
        {can("listSources") && (
          <label className="field">
            Источник
            <select value={filters.sourceId} onChange={(event) => update({ sourceId: event.target.value })}>
              <option value="">Все</option>
              {sources.data?.map((source) => <option key={source.id} value={source.id}>{source.key}</option>)}
            </select>
          </label>
        )}
        <label className="field">
          Пользователь
          <input value={filters.principal} onChange={(event) => update({ principal: event.target.value })} placeholder="Точное совпадение" />
        </label>
        <label className="field">
          Категория
          <select value={filters.category} onChange={(event) => update({ category: event.target.value })}>
            <option value="">Все</option>
            {categoryIds.map((id) => <option key={id} value={id}>{category(id)}</option>)}
          </select>
        </label>
        <label className="field">
          Тип
          <select value={filters.eventType} onChange={(event) => update({ eventType: event.target.value })}>
            <option value="">Все, кроме входов</option>
            <option value="all">Все, включая входы</option>
            {eventTypeIds.map((id) => <option key={id} value={id}>{eventType(id)}</option>)}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={filters.scanner !== ""} onChange={(event) => update({ scanner: event.target.checked ? "1" : "" })} />
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
                        <td><Who event={event} scanner={isScanner(event)} onPick={(principal) => update({ principal })} /></td>
                        <td><What event={event} sourceKey={sourceKey(event.sourceId)} /></td>
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
                <button disabled={offset === 0} onClick={() => update({ offset: String(Math.max(0, offset - pageSize)) })}>Назад</button>
                <button disabled={offset + pageSize >= page.total} onClick={() => update({ offset: String(offset + pageSize) })}>Дальше</button>
                <span>{page.totalExact ? `Всего: ${count(page.total)}` : `Больше ${count(page.total)}, уточните фильтр`}</span>
              </div>
            </>
          )}
        </Loadable>
      </section>
    </Page>
  );
}
