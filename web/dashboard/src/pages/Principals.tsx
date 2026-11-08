import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router";

import { api, type Schemas } from "../api";
import { Categories, categoryOptions, Mono, PeriodPicker } from "../components/domain";
import { Button } from "../components/ui/button";
import { Field, filterField, Select } from "../components/ui/form";
import { PageHeader } from "../components/ui/page";
import { Panel } from "../components/ui/panel";
import { EmptyState } from "../components/ui/state";
import { DataTable, type TableColumn } from "../components/ui/table";
import { downloadCsv, stamp } from "../csv";
import { ago, category, count, identity, lowerFirst } from "../labels";
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

  const columns = useMemo<TableColumn<Row>[]>(() => [
    {
      // The person when the application vouched for one, otherwise the login;
      // how the identity was established is said under it.
      id: "who", header: "Кто", enableHiding: false, accessorFn: (row) => row.applicationPrincipal || row.databasePrincipal,
      cell: ({ row }) => (
        <div className="min-w-0">
          <div className="font-medium">{row.original.applicationPrincipal || (row.original.databasePrincipal ? <Mono className="text-sm">{row.original.databasePrincipal}</Mono> : <span className="font-normal text-fg-3">Учётная запись неизвестна</span>)}</div>
          <div className="text-xs whitespace-nowrap text-fg-2">
            {row.original.applicationPrincipal ? <>через <Mono className="text-xs">{row.original.databasePrincipal}</Mono> · </> : null}
            {row.original.applicationPrincipal ? lowerFirst(identity(row.original.identityConfidence)) : identity(row.original.identityConfidence)}
          </div>
        </div>
      ),
    },
    { id: "events", header: filters.category ? "Обращений к категории" : "Обращений", accessorFn: (row) => row.events, meta: { align: "right" }, cell: ({ row }) => count(row.original.events) },
    { id: "sensitive", header: "К чувствительным", accessorFn: (row) => row.sensitiveEvents, meta: { align: "right" }, cell: ({ row }) => <span className={row.original.sensitiveEvents > 0 ? "font-medium" : "text-fg-3"}>{count(row.original.sensitiveEvents)}</span> },
    { id: "categories", header: "Категории", enableSorting: false, cell: ({ row }) => <Categories ids={row.original.categories} limit={2} /> },
    { id: "sources", header: "Источников", accessorFn: (row) => row.sources, meta: { align: "right" }, cell: ({ row }) => count(row.original.sources) },
    { id: "last", header: "Последнее", accessorFn: (row) => row.lastAccess, cell: ({ row }) => <span className="whitespace-nowrap text-fg-2">{ago(row.original.lastAccess)}</span> },
  ], [filters.category]);

  return (
    <>
      <PageHeader
        title="Пользователи СУБД"
        description="Кто обращался к данным. Подтверждённые приложением и заявленные личности показаны отдельно и не объединяются. Строка открывает события пользователя."
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
            <Field label="Категория" className={filterField}>
              <Select value={filters.category} onValueChange={(value) => update({ category: value })} options={categoryOptions("Все обращения")} />
            </Field>
          }
        />
      </Panel>
    </>
  );
}
