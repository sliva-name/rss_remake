import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Download } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";

import { api, type Schemas } from "../api";
import { Categories, categoryOptions, Mono, PeriodPicker } from "../components/domain";
import { Button } from "../components/ui/button";
import { Field, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable } from "../components/ui/table";
import { downloadCsv, stamp } from "../csv";
import { ago, category, count, identity } from "../labels";
import { paths, usePeriod, useUrlFilters } from "../links";
import { useCan } from "../permissions";
import { ViewsMenu } from "../workspace";

type Row = Schemas["PrincipalAccess"];

export function Principals() {
  const can = useCan();
  const navigate = useNavigate();
  const [period] = usePeriod("7d");
  const [filters, update] = useUrlFilters(["category"] as const);
  const principals = useQuery({
    queryKey: ["principals", period.from, period.to, filters.category],
    placeholderData: (previous) => previous,
    queryFn: () => api.principals(period, { category: filters.category || undefined }),
  });

  const columns = useMemo<ColumnDef<Row, unknown>[]>(() => [
    {
      id: "user", header: "Пользователь приложения", enableHiding: false, accessorFn: (row) => row.applicationPrincipal,
      cell: ({ row }) => (row.original.applicationPrincipal ? <span className="font-medium">{row.original.applicationPrincipal}</span> : <span className="text-fg-3">Не идентифицирован</span>),
    },
    { id: "account", header: "Учётная запись СУБД", accessorFn: (row) => row.databasePrincipal, cell: ({ row }) => (row.original.databasePrincipal ? <Mono>{row.original.databasePrincipal}</Mono> : "—") },
    { id: "identity", header: "Как установлен", accessorFn: (row) => identity(row.identityConfidence), cell: ({ getValue }) => <span className="text-fg-2">{getValue() as string}</span> },
    { id: "events", header: filters.category ? "Обращений к категории" : "Обращений", accessorFn: (row) => row.events, meta: { align: "right" }, cell: ({ row }) => count(row.original.events) },
    { id: "sensitive", header: "К чувствительным", accessorFn: (row) => row.sensitiveEvents, meta: { align: "right" }, cell: ({ row }) => <span className={row.original.sensitiveEvents > 0 ? "font-medium" : "text-fg-3"}>{count(row.original.sensitiveEvents)}</span> },
    { id: "categories", header: "Категории", enableSorting: false, cell: ({ row }) => <Categories ids={row.original.categories} /> },
    { id: "sources", header: "Источников", accessorFn: (row) => row.sources, meta: { align: "right" }, cell: ({ row }) => count(row.original.sources) },
    { id: "last", header: "Последнее", accessorFn: (row) => row.lastAccess, cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastAccess)}</span> },
  ], [filters.category]);

  return (
    <>
      <PageHeader
        title="Пользователи СУБД"
        description="Кто обращался к данным. Подтверждённые приложением и заявленные личности показаны отдельно и не объединяются."
        actions={
          <>
            <PeriodPicker />
            <ViewsMenu />
            <Button
              disabled={!principals.data?.length}
              onClick={() => downloadCsv(`dataguard-principals-${stamp()}.csv`,
                ["Пользователь приложения", "Учётная запись СУБД", "Как установлен", filters.category ? "Обращений к категории" : "Обращений", "К чувствительным", "Категории", "Источников", "Последнее (UTC)"],
                (principals.data ?? []).map((row) => [row.applicationPrincipal, row.databasePrincipal, identity(row.identityConfidence), row.events, row.sensitiveEvents, row.categories.map(category).join(", "), row.sources, row.lastAccess]))}
            >
              <Download /> CSV
            </Button>
          </>
        }
      />
      <Panel flush>
        <DataTable
          id="principals"
          columns={columns}
          data={principals.data}
          getRowId={(row) => `${row.databasePrincipal}\u0000${row.applicationPrincipal}\u0000${row.identityConfidence}`}
          loading={principals.isPending}
          error={principals.error}
          sortable
          onRowClick={can("listAuditEvents") ? (row) => navigate(paths.events({ principal: row.applicationPrincipal || row.databasePrincipal, category: filters.category || undefined, period: period.id === "7d" ? undefined : period.id })) : undefined}
          empty={<EmptyState title="Обращений не было">За выбранный период{filters.category ? " к этой категории" : ""} никто не обращался.</EmptyState>}
          toolbar={
            <Field label="Категория" className="w-56">
              <Select value={filters.category} onValueChange={(value) => update({ category: value })} options={categoryOptions("Все обращения")} />
            </Field>
          }
        />
      </Panel>
    </>
  );
}
