import { useQuery } from "@tanstack/react-query";
import { Info } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router";

import type { Schemas } from "../api";
import { Categories, Mono } from "../components/domain";
import { Badge, type Tone } from "../components/ui/badge";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { ago, count, identity } from "../labels";
import { paths } from "../links";
import { useCan } from "../permissions";
import { queries } from "../queries";

type Signal = Schemas["RiskSignal"];

// The rule behind each kind, as the server applies it (internal/core/risk).
export const signalKinds: Record<Signal["kind"], { title: string; tone: Tone; rule: string }> = {
  VOLUME_SPIKE: { title: "Всплеск чтения", tone: "warn", rule: "За сутки прочитано не меньше 50 раз и втрое больше обычного дня предыдущей недели" },
  NEW_CATEGORY: { title: "Новая категория", tone: "accent", rule: "Пользователь прочитал категорию, которую не читал 30 дней до этого" },
  FAILED_ACCESS: { title: "Отказы доступа", tone: "bad", rule: "За сутки не меньше 10 отказов и втрое больше обычного дня предыдущей недели" },
};

export function observed(signal: Signal): string {
  const number = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });
  switch (signal.kind) {
    case "VOLUME_SPIKE":
      return `${count(signal.observed)} за сутки, обычно ${number.format(signal.baseline)} в день`;
    case "FAILED_ACCESS":
      return `${count(signal.observed)} отказов за сутки, обычно ${number.format(signal.baseline)} в день`;
    case "NEW_CATEGORY":
      return `${count(signal.observed)} за сутки, за 30 дней до этого — ни одного`;
  }
}

// The events a signal was raised on: the same person, category and day.
export function signalEvents(signal: Signal): string {
  return paths.events({
    principal: signal.applicationPrincipal || signal.databasePrincipal,
    category: signal.category || undefined,
    eventType: signal.kind === "FAILED_ACCESS" ? "EVENT_TYPE_FAILED_ACCESS" : undefined,
    period: "24h",
  });
}

export function Signals() {
  const can = useCan();
  const navigate = useNavigate();
  const signals = useQuery(queries.signals());

  const columns = useMemo<TableColumn<Signal>[]>(() => [
    {
      id: "kind", header: "Сигнал", enableHiding: false, accessorFn: (row) => row.kind,
      cell: ({ row }) => <Badge tone={signalKinds[row.original.kind].tone}>{signalKinds[row.original.kind].title}</Badge>,
    },
    {
      id: "who", header: "Кто", accessorFn: (row) => row.applicationPrincipal || row.databasePrincipal,
      cell: ({ row }) => (
        <div>
          <div className="font-medium">{row.original.applicationPrincipal || row.original.databasePrincipal || "Учётная запись неизвестна"}</div>
          <div className="text-xs text-fg-2">{row.original.applicationPrincipal ? <>через <Mono>{row.original.databasePrincipal}</Mono></> : identity(row.original.identityConfidence)}</div>
        </div>
      ),
    },
    {
      id: "category", header: "Категория", accessorFn: (row) => row.category,
      cell: ({ row }) => <Categories ids={row.original.category ? [row.original.category] : []} empty="все данные" />,
    },
    { id: "observed", header: "Что замечено", accessorFn: (row) => row.observed, cell: ({ row }) => <span className="text-fg-2">{observed(row.original)}</span> },
    { id: "last", header: "Последнее", accessorFn: (row) => row.lastSeen, cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastSeen)}</span> },
  ], []);

  return (
    <>
      <PageHeader
        title="Сигналы риска"
        description="Отклонения от обычной активности за последние сутки. Это повод посмотреть, а не установленный инцидент: каждое правило и числа, по которым оно сработало, видны."
      />
      <div className="flex flex-col gap-6">
        <Panel flush>
          <DataTable
            id="signals"
            columns={columns}
            data={signals.data}
            getRowId={(row) => `${row.kind}\u0000${row.databasePrincipal}\u0000${row.applicationPrincipal}\u0000${row.category}`}
            loading={signals.isPending}
            error={signals.error}
            sortable
            caption={signals.data && `За последние сутки: ${count(signals.data.length)}.${can("listAuditEvents") ? " Строка открывает события, на которых сработало правило." : ""}`}
            onRowClick={can("listAuditEvents") ? (row) => navigate(signalEvents(row)) : undefined}
            empty={<EmptyState icon="ok" title="Сигналов нет">За последние сутки активность не отличалась от обычной по правилам ниже.</EmptyState>}
          />
        </Panel>
        <Panel title="Правила" description="Учётные записи сканера DataGuard не учитываются">
          <ul className="flex flex-col gap-3">
            {Object.values(signalKinds).map((kind) => (
              <li key={kind.title} className="flex items-start gap-3 text-sm">
                <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-3" />
                <span><span className="font-medium text-fg">{kind.title}.</span> <span className="text-fg-2">{kind.rule}.</span></span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </>
  );
}
