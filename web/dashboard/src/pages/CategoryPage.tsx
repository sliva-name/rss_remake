import { useQuery } from "@tanstack/react-query";
import { Database, ScrollText } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { BarList } from "../components/bar-list";
import { Confidence, Mono, PeriodPicker } from "../components/domain";
import { Button } from "../components/ui/button";
import { PageHeader } from "../components/ui/page";
import { Panel, Stat } from "../components/ui/panel";
import { EmptyState, Loadable } from "../components/ui/state";
import { ago, category, count, dateTime, eventType, executionStatus } from "../labels";
import { ObjectLink, paths, usePeriod } from "../links";
import { useCan } from "../permissions";

const shown = 15;

function Figures({ id }: { id: string }) {
  const can = useCan();
  const [period] = usePeriod("7d");
  const inventory = useQuery({ queryKey: ["inventory"], queryFn: api.inventory, enabled: can("getCatalogSummary") });
  const access = useQuery({ queryKey: ["categories", period.from, period.to], queryFn: () => api.categories(period), enabled: can("listAccessByCategory") });
  const stored = inventory.data?.find((row) => row.category === id);
  const read = access.data?.find((row) => row.category === id);
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      {can("getCatalogSummary") && (
        <>
          <Stat label="Колонок" value={inventory.data ? count(stored?.columns ?? 0) : "…"} to={paths.findings({ category: id })} />
          <Stat label="Таблиц" value={inventory.data ? count(stored?.tables ?? 0) : "…"} to={paths.inventory({ category: id })} />
        </>
      )}
      {can("listAccessByCategory") && (
        <>
          <Stat label={`Обращений за ${period.label}`} value={access.data ? count(read?.events ?? 0) : "…"} to={paths.events({ category: id, period: period.id === "7d" ? undefined : period.id })} />
          <Stat label="Пользователей" value={access.data ? count(read?.principals ?? 0) : "…"} />
          <Stat label="Источников" value={access.data ? count(read?.sources ?? 0) : "…"} hint={read ? `последнее обращение ${ago(read.lastAccess)}` : undefined} />
        </>
      )}
    </div>
  );
}

function Storage({ id }: { id: string }) {
  const can = useCan();
  const columns = useQuery({ queryKey: ["catalog", "category", id], queryFn: () => api.catalog({ category: id, limit: shown }) });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  return (
    <Panel title="Где хранятся" actions={<Button size="sm" asChild><Link to={paths.findings({ category: id })}>Все колонки</Link></Button>} flush>
      <Loadable query={columns} isEmpty={(page) => page.items.length === 0} empty={<EmptyState title="В каталоге таких колонок нет" />}>
        {(page) => (
          <>
            <ul className="divide-y divide-border">
              {page.items.map((item) => (
                <li key={item.columnId} className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0">
                    <div className="truncate text-sm">
                      <ObjectLink to={paths.table(item.tableId)} needs="getCatalogTable" className="font-mono text-[13px]">{item.schema}.{item.table}</ObjectLink>
                      <span className="text-fg-3">.</span>
                      <ObjectLink to={paths.column(item.columnId)} needs="getCatalogColumn" className="font-mono text-[13px]">{item.column}</ObjectLink>
                    </div>
                    <div className="text-xs text-fg-2">
                      <ObjectLink to={paths.source(item.sourceId)} needs="getSource" className="text-fg-2">{sources.data?.find((source) => source.id === item.sourceId)?.key ?? "Источник"}</ObjectLink> · <Mono>{item.nativeType}</Mono>
                    </div>
                  </div>
                  <Confidence value={item.confidence} />
                </li>
              ))}
            </ul>
            {page.total > page.items.length && <p className="border-t border-border px-4 py-2 text-xs text-fg-3">Показаны {page.items.length} из {count(page.total)}</p>}
          </>
        )}
      </Loadable>
    </Panel>
  );
}

function Readers({ id }: { id: string }) {
  const [period] = usePeriod("7d");
  const principals = useQuery({ queryKey: ["principals", id, period.from, period.to], queryFn: () => api.principals(period, { category: id }) });
  return (
    <Panel title="Кто обращался" description={`За ${period.label}, число обращений именно к этой категории`}>
      <Loadable query={principals}>
        {(rows) => (
          <BarList
            empty={<EmptyState title="За этот период к этим данным не обращались" />}
            items={rows.map((row, index) => ({
              key: `${row.databasePrincipal}-${row.applicationPrincipal}-${index}`,
              label: (
                <ObjectLink to={paths.events({ principal: row.applicationPrincipal || row.databasePrincipal, category: id, period: period.id === "7d" ? undefined : period.id })} needs="listAuditEvents">
                  {row.applicationPrincipal || row.databasePrincipal || "Не идентифицирован"}
                </ObjectLink>
              ),
              value: row.events,
              hint: `${row.applicationPrincipal ? `через ${row.databasePrincipal} · ` : ""}${count(row.sources)} ист. · последнее ${ago(row.lastAccess)}`,
            }))}
          />
        )}
      </Loadable>
    </Panel>
  );
}

function Recent({ id }: { id: string }) {
  const events = useQuery({ queryKey: ["events", "category", id], queryFn: () => api.events({ category: id, limit: 8 }) });
  return (
    <Panel title="Последние обращения" actions={<Button size="sm" asChild><Link to={paths.events({ category: id })}>Все</Link></Button>} flush>
      <Loadable query={events} isEmpty={(page) => page.items.length === 0} empty={<EmptyState title="За 7 дней обращений не было" />}>
        {(page) => (
          <ul className="divide-y divide-border">
            {page.items.map((event) => (
              <li key={event.id} className="flex flex-col gap-0.5 px-4 py-2.5 text-sm">
                <span className="flex flex-wrap items-baseline justify-between gap-2">
                  <span>{event.applicationPrincipal || event.databasePrincipal || "Учётная запись неизвестна"} <span className="text-fg-2">· {eventType(event.type).toLowerCase()} · {executionStatus(event.executionStatus).toLowerCase()}</span></span>
                  <span className="text-[13px] whitespace-nowrap text-fg-3">{dateTime(event.time)}</span>
                </span>
                <Mono className="truncate text-fg-2">{(event.columns.length > 0 ? event.columns : event.tables).slice(0, 3).join(", ")}</Mono>
              </li>
            ))}
          </ul>
        )}
      </Loadable>
    </Panel>
  );
}

// One page answers "who reads this kind of data": where it is stored, who read
// it and what they did, each with a way to the details.
export function CategoryPage() {
  const { id = "" } = useParams();
  const can = useCan();
  return (
    <>
      <PageHeader
        breadcrumbs={[<Link key="classification" to="/classification">Классификация</Link>, category(id)]}
        title={category(id)}
        description="Где хранятся эти данные, кто к ним обращался и что делал. Значения в платформу не передаются."
        actions={
          <>
            <PeriodPicker allowed={["24h", "7d", "30d"]} />
            {can("listCatalogTables") && <Button asChild><Link to={paths.inventory({ category: id })}><Database /> Таблицы</Link></Button>}
            {can("listAuditEvents") && <Button asChild><Link to={paths.events({ category: id })}><ScrollText /> События</Link></Button>}
          </>
        }
      />
      <div className="flex flex-col gap-4">
        <Figures id={id} />
        <div className="grid gap-4 xl:grid-cols-2">
          {can("listCatalogColumns") && <Storage id={id} />}
          {can("listAccessByPrincipal") && <Readers id={id} />}
        </div>
        {can("listAuditEvents") && <Recent id={id} />}
      </div>
    </>
  );
}
