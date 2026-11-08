import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { Link, useParams } from "react-router";

import { api, type Schemas } from "../api";
import { BarList } from "../components/bar-list";
import { Categories, Confidence, Mono, PeriodPicker } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { PageHeader } from "../components/ui/page";
import { Facts, Panel } from "../components/ui/panel";
import { EmptyState, ErrorState, Loadable, Loading } from "../components/ui/state";
import { ago, category, count, dateTime, eventType, executionStatus, percent, samplingMethod } from "../labels";
import { CategoryLink, linkStyle, ObjectLink, paths, usePeriod } from "../links";
import { useCan } from "../permissions";
import { FavoriteButton, type ObjectRef, useRememberVisit } from "../workspace";
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

function Decisions({ decisions }: { decisions: Schemas["Classification"][] }) {
  return (
    <Panel title="Классификация" description="Решения классификатора по каждой категории, включая отрицательные" flush>
      {decisions.length === 0 ? (
        <EmptyState title="Классификатор эту колонку не оценивал" />
      ) : (
        <ul className="divide-y divide-border">
          {decisions.map((decision) => (
            <li key={decision.categoryId} className="grid gap-2 px-4 py-3 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto] sm:items-start">
              <div className="flex flex-col gap-1">
                <CategoryLink id={decision.categoryId} className={`${linkStyle} font-medium`}>{category(decision.categoryId)}</CategoryLink>
                {decision.detected ? <Badge tone="warn" className="self-start">Найдено</Badge> : <Badge className="self-start">Не найдено</Badge>}
              </div>
              <div className="flex flex-col gap-1 text-[13px] text-fg-2">
                <span>Основание: {grounds(decision)}</span>
                <span>{samplingMethod(decision.samplingMethod)} · совпало {count(decision.rowsMatched)} из {count(decision.rowsInspected)} · уникальных ≈ {count(decision.uniqueEstimate)}</span>
                <span className="text-fg-3">Решение обновлено {ago(decision.updatedAt)}</span>
              </div>
              <Confidence value={decision.confidence} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Readers({ columnId }: { columnId: string }) {
  const [period] = usePeriod("7d");
  const principals = useQuery({ queryKey: ["principals", "column", columnId, period.from, period.to], queryFn: () => api.principals(period, { columnId }) });
  return (
    <Panel title="Кто читал колонку" description={`За ${period.label}`} actions={<PeriodPicker allowed={["24h", "7d", "30d"]} />}>
      <Loadable query={principals}>
        {(rows) => (
          <BarList
            empty={<EmptyState title="За этот период колонку никто не читал" />}
            items={rows.map((row, index) => {
              const name = row.applicationPrincipal || row.databasePrincipal || "Не идентифицирован";
              return {
                key: `${row.databasePrincipal}-${row.applicationPrincipal}-${index}`,
                label: <ObjectLink to={paths.events({ columnId, principal: row.applicationPrincipal || row.databasePrincipal, period: period.id === "7d" ? undefined : period.id })} needs="listAuditEvents">{name}</ObjectLink>,
                value: row.events,
                hint: `${row.applicationPrincipal ? `через ${row.databasePrincipal} · ` : ""}последнее ${ago(row.lastAccess)}`,
              };
            })}
          />
        )}
      </Loadable>
    </Panel>
  );
}

function Recent({ columnId }: { columnId: string }) {
  const events = useQuery({ queryKey: ["events", "column", columnId], queryFn: () => api.events({ columnId, limit: 8 }) });
  return (
    <Panel title="Последние обращения" actions={<Button size="sm" asChild><Link to={paths.events({ columnId })}>Все</Link></Button>} flush>
      <Loadable query={events} isEmpty={(page) => page.items.length === 0} empty={<EmptyState title="За 7 дней обращений не было" />}>
        {(page) => (
          <ul className="divide-y divide-border">
            {page.items.map((event) => (
              <li key={event.id} className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2.5 text-sm">
                <span className="min-w-0">
                  <span className="text-fg">{event.applicationPrincipal || event.databasePrincipal || "Учётная запись неизвестна"}</span>
                  <span className="text-fg-2"> · {eventType(event.type).toLowerCase()} · {executionStatus(event.executionStatus).toLowerCase()}</span>
                </span>
                <span className="text-[13px] whitespace-nowrap text-fg-3">{dateTime(event.time)}</span>
              </li>
            ))}
          </ul>
        )}
      </Loadable>
    </Panel>
  );
}

export function ColumnPage() {
  const { id = "" } = useParams();
  const can = useCan();
  const column = useQuery({ queryKey: ["column", id], queryFn: () => api.column(id) });
  const item: ObjectRef | undefined = column.data && { kind: "column", id, label: column.data.name, context: `${column.data.schema}.${column.data.table}` };
  useRememberVisit(item);
  if (column.isPending) return <Loading rows={8} />;
  if (column.isError) return <ErrorState error={column.error} />;
  const data = column.data;
  const detected = data.classifications.filter((decision) => decision.detected).map((decision) => decision.categoryId);

  return (
    <>
      <PageHeader
        breadcrumbs={[
          <Link key="inventory" to="/inventory">Инвентаризация</Link>,
          <SourceCrumb key="source" id={data.sourceId} />,
          `${data.database} › ${data.schema}`,
          <ObjectLink key="table" to={paths.table(data.tableId)} needs="getCatalogTable" className="font-mono">{data.table}</ObjectLink>,
        ]}
        title={data.name}
        mono
        meta={
          <>
            <Badge><Mono>{data.nativeType}</Mono></Badge>
            <Categories ids={detected} empty={<Badge>Чувствительных данных не найдено</Badge>} />
          </>
        }
        actions={
          <>
            {item && <FavoriteButton item={item} />}
            {can("listAuditEvents") && <Button asChild><Link to={paths.events({ columnId: data.id })}><ScrollText /> Обращения к колонке</Link></Button>}
          </>
        }
      />
      <RemovedNote status={data.status} lastSeenAt={data.lastSeenAt} />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-6">
          <Decisions decisions={data.classifications} />
          {can("listAccessByPrincipal") && <Readers columnId={data.id} />}
        </div>
        <div className="flex flex-col gap-6">
          <Panel title="Колонка">
            <Facts
              items={[
                ["Таблица", <ObjectLink key="table" to={paths.table(data.tableId)} needs="getCatalogTable" className="font-mono text-[13px]">{data.schema}.{data.table}</ObjectLink>],
                ["Тип", <Mono key="type">{data.nativeType}</Mono>],
                ["Допускает NULL", data.nullable ? "Да" : "Нет"],
                ["Позиция", String(data.ordinal)],
                ["Впервые обнаружена", dateTime(data.firstSeenAt)],
                ["Последний скан видел", dateTime(data.lastSeenAt)],
              ]}
            />
            <p className="mt-3 text-xs text-fg-3">Значения колонки в платформу не передаются: классификатор работает у агента.</p>
          </Panel>
          {can("listAuditEvents") && <Recent columnId={data.id} />}
          <Renames renames={data.renames} />
        </div>
      </div>
    </>
  );
}
