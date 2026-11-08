import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type RowSelectionState,
  type SortingState,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Columns3, Rows3 } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import { count } from "../../labels";
import { Button } from "./button";
import { cn } from "./cn";
import { Checkbox } from "./form";
import { Menu, MenuCheckbox, MenuSeparator } from "./menu";
import { ErrorState, Loading } from "./state";

declare module "@tanstack/react-table" {
  interface ColumnMeta<TData, TValue> {
    align?: "right";
    // The name in the column settings menu when the header is not plain text.
    label?: string;
    className?: string;
  }
}

type Density = "comfortable" | "compact";

// Per-viewer conveniences only: storage may be missing, and the table works
// the same without it.
function stored<T>(key: string, fallback: T): T {
  try {
    const value = localStorage.getItem(key);
    return value === null ? fallback : (JSON.parse(value) as T);
  } catch {
    return fallback;
  }
}

function store(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Without storage the choice lasts until reload.
  }
}

export interface Page {
  offset: number;
  size: number;
  total: number;
  // False when the server stopped counting: the total is a lower bound.
  exact?: boolean;
  onChange: (offset: number) => void;
}

export interface DataTableProps<T> {
  // Names the table's saved column choice.
  id: string;
  columns: ColumnDef<T, unknown>[];
  data: T[] | undefined;
  getRowId: (row: T) => string;
  loading?: boolean;
  error?: Error | null;
  empty: ReactNode;
  // Sorting reorders rows in the browser, so it is offered only when the
  // table holds the whole list, never one page of a server-side list.
  sortable?: boolean;
  page?: Page;
  onRowClick?: (row: T) => void;
  selectedId?: string;
  bulkActions?: (rows: T[], clear: () => void) => ReactNode;
  toolbar?: ReactNode;
  // Columns hidden until the user turns them on in the column settings.
  defaultHidden?: string[];
}

export function DataTable<T>({
  id,
  columns,
  data,
  getRowId,
  loading,
  error,
  empty,
  sortable,
  page,
  onRowClick,
  selectedId,
  bulkActions,
  toolbar,
  defaultHidden = [],
}: DataTableProps<T>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [visibility, setVisibility] = useState<VisibilityState>(() =>
    stored(`table:${id}:columns`, Object.fromEntries(defaultHidden.map((column) => [column, false]))),
  );
  const [density, setDensity] = useState<Density>(() => stored("table:density", "comfortable"));
  const [selection, setSelection] = useState<RowSelectionState>({});

  useEffect(() => store(`table:${id}:columns`, visibility), [id, visibility]);
  useEffect(() => store("table:density", density), [density]);
  useEffect(() => setSelection({}), [data]);

  const selectable = bulkActions !== undefined;
  const table = useReactTable({
    data: data ?? [],
    columns: selectable ? [selectColumn<T>(), ...columns] : columns,
    getRowId,
    state: { sorting, columnVisibility: visibility, rowSelection: selection },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setVisibility,
    onRowSelectionChange: setSelection,
    enableSorting: sortable === true,
    enableRowSelection: selectable,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: sortable ? getSortedRowModel() : undefined,
  });

  const chosen = table.getSelectedRowModel().rows.map((row) => row.original);
  const cell = density === "compact" ? "px-3 py-1.5" : "px-3 py-2.5";
  const hideable = table.getAllLeafColumns().filter((column) => column.getCanHide() && column.id !== "select");

  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-end justify-between gap-2 border-b border-border px-3 py-2.5">
        <div className="flex min-w-0 flex-1 flex-wrap items-end gap-2">
          {chosen.length > 0 && bulkActions ? (
            <div className="flex h-8 flex-wrap items-center gap-2 text-sm">
              <span className="text-fg-2">Выбрано: {chosen.length}</span>
              {bulkActions(chosen, () => setSelection({}))}
              <Button variant="ghost" size="sm" onClick={() => setSelection({})}>Снять выбор</Button>
            </div>
          ) : (
            toolbar
          )}
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={density === "compact" ? "Обычная плотность" : "Плотнее"}
            title={density === "compact" ? "Обычная плотность" : "Плотнее"}
            onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
          >
            <Rows3 />
          </Button>
          {hideable.length > 1 && (
            <Menu label="Колонки" trigger={<Button variant="ghost" size="icon-sm" aria-label="Настроить колонки" title="Настроить колонки"><Columns3 /></Button>}>
              {hideable.map((column) => (
                <MenuCheckbox key={column.id} checked={column.getIsVisible()} onChange={(value) => column.toggleVisibility(value)}>
                  {column.columnDef.meta?.label ?? (typeof column.columnDef.header === "string" ? column.columnDef.header : column.id)}
                </MenuCheckbox>
              ))}
              <MenuSeparator />
              <MenuCheckbox checked={Object.values(visibility).every(Boolean)} onChange={() => setVisibility({})}>Показать все</MenuCheckbox>
            </Menu>
          )}
        </div>
      </div>

      {error ? (
        <ErrorState error={error} />
      ) : loading && !data ? (
        <Loading rows={5} />
      ) : table.getRowModel().rows.length === 0 ? (
        empty
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              {table.getHeaderGroups().map((group) => (
                <tr key={group.id} className="border-b border-border bg-surface-2/60">
                  {group.headers.map((header) => {
                    const meta = header.column.columnDef.meta;
                    const sorted = header.column.getIsSorted();
                    return (
                      <th
                        key={header.id}
                        scope="col"
                        aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                        className={cn("px-3 py-2 text-left text-xs font-medium whitespace-nowrap text-fg-2", meta?.align === "right" && "text-right", meta?.className)}
                      >
                        {header.isPlaceholder ? null : header.column.getCanSort() ? (
                          <button
                            type="button"
                            onClick={header.column.getToggleSortingHandler()}
                            className={cn("inline-flex cursor-pointer items-center gap-1 hover:text-fg", meta?.align === "right" && "flex-row-reverse")}
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {sorted === "asc" ? <ArrowUp className="size-3" /> : sorted === "desc" ? <ArrowDown className="size-3" /> : null}
                          </button>
                        ) : (
                          flexRender(header.column.columnDef.header, header.getContext())
                        )}
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={onRowClick ? (event) => {
                    if ((event.target as HTMLElement).closest("a, button, input, select, label")) return;
                    onRowClick(row.original);
                  } : undefined}
                  className={cn(
                    "border-b border-border last:border-b-0",
                    onRowClick && "cursor-pointer hover:bg-surface-2/60",
                    row.getIsSelected() && "bg-accent-bg/60",
                    selectedId === row.id && "bg-accent-bg",
                  )}
                >
                  {row.getVisibleCells().map((item) => {
                    const meta = item.column.columnDef.meta;
                    return (
                      <td key={item.id} className={cn(cell, "align-top text-fg", meta?.align === "right" && "text-right", meta?.className)}>
                        {flexRender(item.column.columnDef.cell, item.getContext())}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {page && page.total > 0 && <Pager page={page} />}
    </div>
  );
}

function selectColumn<T>(): ColumnDef<T, unknown> {
  return {
    id: "select",
    enableHiding: false,
    enableSorting: false,
    meta: { className: "w-8 pr-0" },
    header: ({ table }) => (
      <Checkbox
        aria-label="Выбрать все на странице"
        checked={table.getIsAllRowsSelected()}
        ref={(element) => { if (element) element.indeterminate = table.getIsSomeRowsSelected(); }}
        onChange={table.getToggleAllRowsSelectedHandler()}
      />
    ),
    cell: ({ row }) => (
      <Checkbox aria-label="Выбрать строку" checked={row.getIsSelected()} disabled={!row.getCanSelect()} onChange={row.getToggleSelectedHandler()} />
    ),
  };
}

export function Pager({ page }: { page: Page }) {
  const last = Math.min(page.offset + page.size, page.total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-[13px] text-fg-2">
      <span>
        {count(page.offset + 1)}–{count(last)} из {page.exact === false ? `более ${count(page.total)}` : count(page.total)}
        {page.exact === false && <span className="text-fg-3"> · уточните фильтр, чтобы увидеть точное число</span>}
      </span>
      <div className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={page.offset === 0} onClick={() => page.onChange(Math.max(0, page.offset - page.size))}>
          <ChevronLeft /> Назад
        </Button>
        <Button size="sm" variant="ghost" disabled={last >= page.total} onClick={() => page.onChange(page.offset + page.size)}>
          Дальше <ChevronRight />
        </Button>
      </div>
    </div>
  );
}
