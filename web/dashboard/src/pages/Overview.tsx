import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowDown, ArrowUp, CircleSlash, ServerCrash, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";

import { api, type Schemas } from "../api";
import { BarList } from "../components/bar-list";
import { ActivityChart } from "../components/charts";
import { agentTone, PeriodPicker } from "../components/domain";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { cn } from "../components/ui/cn";
import { Dialog } from "../components/ui/dialog";
import { CheckField } from "../components/ui/form";
import { Panel, Stat } from "../components/ui/panel";
import { PageHeader } from "../components/ui/page";
import { EmptyState, Loadable, Loading } from "../components/ui/state";
import { ago, category, change, count, coverageStatus, failure, shortId } from "../labels";
import { CategoryLink, linkStyle, ObjectLink, paths, usePeriod } from "../links";
import { type Permission, useCan } from "../permissions";
import { queries } from "../queries";
import { defaultLayout, kindNames, type OverviewLayout, pathOf, useFavorites, useOverviewLayout, useRecent } from "../workspace";
import { observed, signalKinds } from "./Signals";

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
  const sources = useQuery({ ...queries.sources(), enabled: can("listSources") });
  const coverage = useQuery({ ...queries.coverage(24), enabled: can("getAuditCoverage") });
  const agents = useQuery({ ...queries.agents(), enabled: can("listAgents") });
  const scans = useQuery({ ...queries.scans(), enabled: can("listScans") });
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
              <Link to={issue.to} className="flex gap-3 px-5 py-3.5 transition-colors hover:bg-surface-2/60 [&_svg]:mt-0.5 [&_svg]:size-4 [&_svg]:shrink-0">
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
  const sources = useQuery({ ...queries.sources(), enabled: can("listSources") });
  const coverage = useQuery({ ...queries.coverage(24), enabled: can("getAuditCoverage") });
  const agents = useQuery({ ...queries.agents(), enabled: can("listAgents") });
  const inventory = useQuery({ ...queries.inventory(), enabled: can("getCatalogSummary") });
  const sensitiveTables = useQuery({ queryKey: ["tables", "sensitive-count"], queryFn: () => api.tables({ sensitive: "true", limit: 1 }), enabled: can("listCatalogTables") });

  const observing = coverage.data?.filter((row) => row.status === "OBSERVING").length ?? 0;
  const active = agents.data?.filter((agent) => agent.status === "active") ?? [];
  const silent = active.filter((agent) => agentTone(agent) !== "ok").length;
  const sensitiveColumns = inventory.data?.reduce((sum, row) => sum + row.columns, 0);

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
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
    <Panel title="Активность" description={`Обращения к данным за ${period.label}`}>
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
  const categories = useQuery(queries.categories(period));
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
              <li key={index} className="flex flex-col gap-0.5 px-5 py-3 text-sm">
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

function TopSignals() {
  const signals = useQuery(queries.signals());
  return (
    <Panel title="Сигналы риска" description="Отклонения за сутки — повод посмотреть, не инцидент" actions={<Button size="sm" variant="ghost" asChild><Link to="/signals">Все</Link></Button>} flush>
      <Loadable query={signals} isEmpty={(rows) => rows.length === 0} empty={<EmptyState title="Сигналов нет">Активность за сутки обычная.</EmptyState>}>
        {(rows) => (
          <ul className="divide-y divide-border">
            {rows.slice(0, 5).map((signal) => (
              <li key={`${signal.kind}-${signal.databasePrincipal}-${signal.applicationPrincipal}-${signal.category}`} className="flex flex-col gap-1 px-5 py-3">
                <span className="flex items-center justify-between gap-3">
                  <span className="truncate text-sm font-medium text-fg">{signal.applicationPrincipal || signal.databasePrincipal}</span>
                  <Badge tone={signalKinds[signal.kind].tone}>{signalKinds[signal.kind].title}</Badge>
                </span>
                <span className="text-xs text-fg-2">{signal.category ? `${category(signal.category)} · ` : ""}{observed(signal)}</span>
              </li>
            ))}
          </ul>
        )}
      </Loadable>
    </Panel>
  );
}

function Shortcuts({ kind }: { kind: "favorites" | "recent" }) {
  const favorites = useFavorites();
  const recent = useRecent();
  const items = kind === "favorites" ? favorites.value : recent.value;
  return (
    <Panel title={kind === "favorites" ? "Избранное" : "Недавно открытые"} flush>
      {items.length === 0 ? (
        <EmptyState title={kind === "favorites" ? "В избранном пусто" : "Пока ничего не открывали"}>
          {kind === "favorites" ? "Отметьте источник, таблицу, колонку или категорию звёздочкой на её странице." : "Здесь появятся страницы объектов, которые вы открывали."}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-border">
          {items.slice(0, 7).map((item) => (
            <li key={`${item.kind}-${item.id}`}>
              <Link to={pathOf(item)} className="flex items-center justify-between gap-3 px-5 py-3 transition-colors hover:bg-surface-2/60">
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium text-fg">{item.label}</span>
                  <span className="block truncate text-xs text-fg-2">{[kindNames[item.kind], item.context].filter(Boolean).join(" · ")}</span>
                </span>
                {"at" in item && <span className="shrink-0 text-xs text-fg-3">{ago((item as { at: string }).at)}</span>}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

interface Widget {
  id: string;
  title: string;
  span: "full" | "wide" | "narrow";
  needs: readonly Permission[];
  render: () => ReactNode;
}

// The overview is a set of widgets the user arranges; a widget whose data the
// user may not read is not offered at all.
const widgets: Widget[] = [
  { id: "headline", title: "Ключевые показатели", span: "full", needs: ["listSources", "listAgents", "getCatalogSummary", "getAccessSummary"], render: () => <Headline /> },
  { id: "activity", title: "Активность", span: "wide", needs: ["getAccessTimeline"], render: () => <Activity /> },
  { id: "attention", title: "Требует внимания", span: "narrow", needs: ["listSources", "getAuditCoverage", "listAgents"], render: () => <Attention /> },
  { id: "signals", title: "Сигналы риска", span: "narrow", needs: ["listRiskSignals"], render: () => <TopSignals /> },
  { id: "categories", title: "Что читают", span: "narrow", needs: ["listAccessByCategory"], render: () => <TopCategories /> },
  { id: "readers", title: "Кто читает чувствительные данные", span: "narrow", needs: ["listAccessByPrincipal"], render: () => <TopReaders /> },
  { id: "changes", title: "Изменения в инвентаре", span: "narrow", needs: ["listCatalogChanges"], render: () => <Changes /> },
  { id: "favorites", title: "Избранное", span: "narrow", needs: ["getPreference"], render: () => <Shortcuts kind="favorites" /> },
  { id: "recent", title: "Недавно открытые", span: "narrow", needs: ["getPreference"], render: () => <Shortcuts kind="recent" /> },
];

function arrange(available: Widget[], layout: OverviewLayout): Widget[] {
  const known = layout.order.map((id) => available.find((widget) => widget.id === id)).filter((widget): widget is Widget => widget !== undefined);
  const rest = available.filter((widget) => !layout.order.includes(widget.id));
  return [...known, ...rest];
}

function Customize({ open, onOpenChange, available }: { open: boolean; onOpenChange: (open: boolean) => void; available: Widget[] }) {
  const layout = useOverviewLayout();
  const [draft, setDraft] = useState<OverviewLayout>(layout.value);
  useEffect(() => { if (open) setDraft(layout.value); }, [open, layout.value]);
  const ordered = arrange(available, draft);
  const move = (index: number, by: number) => {
    const ids = ordered.map((widget) => widget.id);
    const [moved] = ids.splice(index, 1);
    if (moved === undefined) return;
    ids.splice(index + by, 0, moved);
    setDraft({ ...draft, order: ids });
  };
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Настроить обзор"
      description="Какие блоки показывать и в каком порядке. Раскладка хранится в вашей учётной записи."
      footer={
        <>
          <Button onClick={() => setDraft(defaultLayout)}>По умолчанию</Button>
          <Button variant="primary" onClick={() => { layout.save(draft); onOpenChange(false); }}>Сохранить</Button>
        </>
      }
    >
      <ul className="flex flex-col divide-y divide-border">
        {ordered.map((widget, index) => (
          <li key={widget.id} className="flex items-center justify-between gap-3 py-2.5">
            <CheckField
              label={widget.title}
              checked={!draft.hidden.includes(widget.id)}
              onChange={(event) => setDraft({ ...draft, hidden: event.target.checked ? draft.hidden.filter((id) => id !== widget.id) : [...draft.hidden, widget.id] })}
            />
            <span className="flex gap-1">
              <Button variant="ghost" size="icon-sm" aria-label={`Выше: ${widget.title}`} disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp /></Button>
              <Button variant="ghost" size="icon-sm" aria-label={`Ниже: ${widget.title}`} disabled={index === ordered.length - 1} onClick={() => move(index, 1)}><ArrowDown /></Button>
            </span>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

const spans = { full: "xl:col-span-3 lg:col-span-2", wide: "xl:col-span-2 lg:col-span-2", narrow: "" };

export function Overview() {
  const can = useCan();
  const layout = useOverviewLayout();
  const [customizing, setCustomizing] = useState(false);
  const available = widgets.filter((widget) => widget.needs.some(can));
  const shown = arrange(available, layout.value).filter((widget) => !layout.value.hidden.includes(widget.id));
  return (
    <>
      <PageHeader
        title="Обзор"
        description="Состояние сбора и обращения к данным."
        actions={
          <>
            <PeriodPicker allowed={["24h", "7d", "30d"]} />
            {layout.canSave && <Button onClick={() => setCustomizing(true)}><SlidersHorizontal /> Настроить</Button>}
          </>
        }
      />
      {shown.length === 0 ? (
        <EmptyState title="Все блоки скрыты" action={<Button onClick={() => setCustomizing(true)}>Настроить обзор</Button>} />
      ) : (
        <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
          {shown.map((widget) => <div key={widget.id} className={cn("min-w-0 [&>*]:h-full", spans[widget.span])}>{widget.render()}</div>)}
        </div>
      )}
      <Customize open={customizing} onOpenChange={setCustomizing} available={available} />
    </>
  );
}
