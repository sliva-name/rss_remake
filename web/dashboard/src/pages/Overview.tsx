import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CircleSlash, ServerCrash, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";

import { api, type Schemas } from "../api";
import { BarList } from "../components/bar-list";
import { ActivityChart } from "../components/charts";
import { agentTone, PeriodPicker } from "../components/domain";
import { Panel, Stat } from "../components/ui/panel";
import { PageHeader } from "../components/ui/page";
import { EmptyState, Loadable, Loading } from "../components/ui/state";
import { ago, category, change, count, coverageStatus, failure, shortId } from "../labels";
import { CategoryLink, linkStyle, ObjectLink, paths, usePeriod } from "../links";
import { useCan } from "../permissions";

interface Issue {
  key: string;
  icon: ReactNode;
  title: ReactNode;
  detail: string;
  to: string;
}

// Facts about collection that need someone to act: a source that is not
// observed, refused to connect or failed to scan, an agent that went silent.
// No guesses about intent: the platform has no risk assessment yet.
function issuesOf(sources: Schemas["Source"][], coverage: Schemas["CoverageRow"][], agents: Schemas["Agent"][], scans: Schemas["Scan"][]): Issue[] {
  const issues: Issue[] = [];
  for (const source of sources) {
    if (source.probedAt && source.statusCode) {
      issues.push({ key: `refused-${source.id}`, icon: <CircleSlash className="text-bad" />, title: <>{source.key}: {failure(source.statusCode).problem}</>, detail: failure(source.statusCode).action, to: paths.source(source.id) });
    }
  }
  for (const row of coverage) {
    if (row.status !== "OBSERVING" && !issues.some((issue) => issue.key === `refused-${row.sourceId}`)) {
      issues.push({
        key: `coverage-${row.sourceId}`,
        icon: <ShieldAlert className={row.status === "DEGRADED" ? "text-warn" : "text-bad"} />,
        title: <>{row.sourceKey}: {coverageStatus(row.status).toLowerCase()}</>,
        detail: row.reason ? failure(row.reason).action || failure(row.reason).problem : "Отсутствие событий по источнику ничего не значит.",
        to: paths.source(row.sourceId),
      });
    }
  }
  const latest = new Map<string, Schemas["Scan"]>();
  for (const scan of scans) if (!latest.has(scan.sourceId)) latest.set(scan.sourceId, scan);
  for (const scan of latest.values()) {
    if (scan.status === "failed" || scan.status === "partial") {
      const key = sources.find((source) => source.id === scan.sourceId)?.key ?? shortId(scan.sourceId);
      issues.push({ key: `scan-${scan.id}`, icon: <AlertTriangle className="text-warn" />, title: <>{key}: скан {scan.status === "failed" ? "не удался" : "прошёл частично"}</>, detail: scan.failureCode ? failure(scan.failureCode).action || failure(scan.failureCode).problem : "Часть таблиц не прочитана.", to: paths.source(scan.sourceId) });
    }
  }
  for (const agent of agents) {
    if (agent.status === "active" && agentTone(agent) !== "ok") {
      issues.push({ key: `agent-${agent.id}`, icon: <ServerCrash className="text-warn" />, title: <>Агент {shortId(agent.id)} молчит</>, detail: `Последний сигнал ${ago(agent.lastSeenAt)}. Его источники не сканируются и не присылают события.`, to: paths.agent(agent.id) });
    }
  }
  return issues;
}

function Attention() {
  const can = useCan();
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24), enabled: can("getAuditCoverage") });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents, enabled: can("listAgents") });
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.scans, enabled: can("listScans") });
  const pending = [sources, coverage, agents, scans].some((query) => query.isPending && query.fetchStatus !== "idle");
  const issues = issuesOf(sources.data ?? [], coverage.data ?? [], agents.data ?? [], scans.data ?? []);
  return (
    <Panel title="Требует внимания" description="Состояние сбора за сутки" flush className="flex flex-col">
      {pending ? (
        <Loading />
      ) : issues.length === 0 ? (
        <EmptyState title="Всё работает">Источники наблюдаются, агенты на связи, последние сканы прошли.</EmptyState>
      ) : (
        <ul className="divide-y divide-border">
          {issues.map((issue) => (
            <li key={issue.key}>
              <Link to={issue.to} className="flex gap-3 px-4 py-3 transition-colors hover:bg-surface-2/60 [&_svg]:mt-0.5 [&_svg]:size-4 [&_svg]:shrink-0">
                {issue.icon}
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-fg">{issue.title}</span>
                  <span className="block text-[13px] text-fg-2">{issue.detail}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Headline() {
  const can = useCan();
  const [period] = usePeriod("7d");
  const summary = useQuery({ queryKey: ["summary", period.from, period.to], queryFn: () => api.summary(period), enabled: can("getAccessSummary") });
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources, enabled: can("listSources") });
  const coverage = useQuery({ queryKey: ["coverage", 24], queryFn: () => api.coverage(24), enabled: can("getAuditCoverage") });
  const agents = useQuery({ queryKey: ["agents"], queryFn: api.agents, enabled: can("listAgents") });
  const inventory = useQuery({ queryKey: ["inventory"], queryFn: api.inventory, enabled: can("getCatalogSummary") });
  const sensitiveTables = useQuery({ queryKey: ["tables", "sensitive-count"], queryFn: () => api.tables({ sensitive: "true", limit: 1 }), enabled: can("listCatalogTables") });

  const observing = coverage.data?.filter((row) => row.status === "OBSERVING").length ?? 0;
  const active = agents.data?.filter((agent) => agent.status === "active") ?? [];
  const silent = active.filter((agent) => agentTone(agent) !== "ok").length;
  const sensitiveColumns = inventory.data?.reduce((sum, row) => sum + row.columns, 0);

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      {can("listSources") && (
        <Stat label="Источники" to="/sources" value={sources.data ? count(sources.data.length) : "…"} hint={coverage.data ? `${observing} наблюдаются · ${(coverage.data.length - observing)} с проблемами` : undefined} tone={coverage.data && coverage.data.length > observing ? "warn" : undefined} />
      )}
      {can("listAgents") && (
        <Stat label="Агенты на связи" to="/agents" value={agents.data ? `${active.length - silent} из ${active.length}` : "…"} hint={silent > 0 ? `${silent} молчат` : "все отвечают"} tone={silent > 0 ? "warn" : undefined} />
      )}
      {can("getCatalogSummary") && (
        <Stat label="Чувствительные колонки" to="/classification" value={sensitiveColumns === undefined ? "…" : count(sensitiveColumns)} hint={sensitiveTables.data ? `в ${count(sensitiveTables.data.total)} таблицах` : undefined} />
      )}
      {can("getAccessSummary") && (
        <>
          <Stat label={`Обращения за ${period.label}`} to={paths.events({ period: period.id === "7d" ? undefined : period.id })} value={summary.data ? count(summary.data.events) : "…"} hint={summary.data ? `к чувствительным: ${count(summary.data.sensitiveEvents)} · пользователей: ${count(summary.data.principals)}` : undefined} />
          <Stat label="Потери аудита" to={paths.events({ eventType: "EVENT_TYPE_AUDIT_GAP", period: period.id === "7d" ? undefined : period.id })} value={summary.data ? count(summary.data.gaps) : "…"} hint={summary.data ? (summary.data.gaps > 0 ? "периоды без наблюдения" : "пропусков не было") : undefined} tone={summary.data && summary.data.gaps > 0 ? "bad" : undefined} />
        </>
      )}
    </div>
  );
}

function Activity() {
  const navigate = useNavigate();
  const [period] = usePeriod("7d");
  const timeline = useQuery({ queryKey: ["timeline", period.from, period.to], queryFn: () => api.timeline(period) });
  return (
    <Panel title="Активность" description={`Обращения к данным за ${period.label}`} className="xl:col-span-2">
      <Loadable query={timeline} loading={<Loading rows={6} />}>
        {(points) => (
          <ActivityChart points={points} from={period.from} to={period.to} onOpen={(from, to) => navigate(`/audit?${new URLSearchParams({ from, to }).toString()}`)} />
        )}
      </Loadable>
    </Panel>
  );
}

function TopCategories() {
  const [period] = usePeriod("7d");
  const categories = useQuery({ queryKey: ["categories", period.from, period.to], queryFn: () => api.categories(period) });
  return (
    <Panel title="Что читают" description="Категории данных по числу обращений">
      <Loadable query={categories}>
        {(rows) => (
          <BarList
            empty={<EmptyState title="Обращений к чувствительным данным не было" />}
            items={rows.slice(0, 6).map((row) => ({
              key: row.category,
              label: <CategoryLink id={row.category} className={linkStyle}>{category(row.category)}</CategoryLink>,
              value: row.events,
              hint: `${count(row.principals)} польз. · ${count(row.sources)} ист.`,
            }))}
          />
        )}
      </Loadable>
    </Panel>
  );
}

function TopReaders() {
  const [period] = usePeriod("7d");
  const principals = useQuery({ queryKey: ["principals", period.from, period.to], queryFn: () => api.principals(period) });
  return (
    <Panel title="Кто читает чувствительные данные" description="Учётные записи и пользователи приложений">
      <Loadable query={principals}>
        {(rows) => (
          <BarList
            empty={<EmptyState title="Обращений к чувствительным данным не было" />}
            items={rows.filter((row) => row.sensitiveEvents > 0).slice(0, 6).map((row, index) => {
              const name = row.applicationPrincipal || row.databasePrincipal || "Не идентифицирован";
              return {
                key: `${row.databasePrincipal}-${row.applicationPrincipal}-${index}`,
                label: <ObjectLink to={paths.events({ principal: row.applicationPrincipal || row.databasePrincipal })} needs="listAuditEvents">{name}</ObjectLink>,
                value: row.sensitiveEvents,
                hint: row.applicationPrincipal ? `через ${row.databasePrincipal}` : undefined,
              };
            })}
          />
        )}
      </Loadable>
    </Panel>
  );
}

function Changes() {
  const [period] = usePeriod("7d");
  const changes = useQuery({ queryKey: ["changes", period.from, period.to], queryFn: () => api.changes({ from: period.from, to: period.to, limit: 8 }) });
  return (
    <Panel title="Изменения в инвентаре" description={`За ${period.label}`} flush>
      <Loadable query={changes} isEmpty={(rows) => rows.length === 0} empty={<EmptyState title="Изменений не было" />}>
        {(rows) => (
          <ul className="divide-y divide-border">
            {rows.map((row, index) => (
              <li key={index} className="flex flex-col gap-0.5 px-4 py-2.5 text-sm">
                <span className="flex items-baseline justify-between gap-3">
                  <span className="text-fg">{change(row.kind)}</span>
                  <span className="shrink-0 text-xs text-fg-3">{ago(row.occurredAt)}</span>
                </span>
                <span className="min-w-0 truncate text-[13px] text-fg-2">
                  {row.sourceKey} ·{" "}
                  <ObjectLink to={paths.table(row.tableId)} needs="getCatalogTable" className="font-mono">{row.tableName}</ObjectLink>
                  {row.columnId && row.columnName && <>.<ObjectLink to={paths.column(row.columnId)} needs="getCatalogColumn" className="font-mono">{row.columnName}</ObjectLink></>}
                  {row.categoryId && <> · {category(row.categoryId)}</>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Loadable>
    </Panel>
  );
}

export function Overview() {
  const can = useCan();
  return (
    <>
      <PageHeader title="Обзор" description="Состояние сбора и обращения к данным." actions={<PeriodPicker allowed={["24h", "7d", "30d"]} />} />
      <div className="flex flex-col gap-4">
        <Headline />
        <div className="grid gap-4 xl:grid-cols-3">
          {can("getAccessTimeline") && <Activity />}
          {(can("listSources") || can("getAuditCoverage") || can("listAgents")) && <Attention />}
        </div>
        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
          {can("listAccessByCategory") && <TopCategories />}
          {can("listAccessByPrincipal") && <TopReaders />}
          {can("listCatalogChanges") && <Changes />}
        </div>
      </div>
    </>
  );
}
