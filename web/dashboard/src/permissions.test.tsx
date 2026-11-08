import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { DataTable, type TableColumn } from "./components/ui/table";
import { Tabs } from "./components/ui/tabs";
import { type Permission, PermissionsProvider } from "./permissions";

function withPermissions(permissions: readonly Permission[], children: ReactNode) {
  return render(
    <MemoryRouter>
      <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
    </MemoryRouter>,
  );
}

describe("permissions", () => {
  it("leave out a tab the user may not open, and keep one that needs any of several", () => {
    withPermissions(["listAccessByCategory"], (
      <Tabs
        items={[
          { id: "categories", label: "Категории", needs: ["getCatalogSummary", "listAccessByCategory"], content: null },
          { id: "findings", label: "Находки", needs: "listCatalogColumns", content: null },
          { id: "detectors", label: "Детекторы", content: null },
        ]}
      />
    ));
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Категории", "Детекторы"]);
  });

  it("leave out a column whose data the user may not read", () => {
    const columns: TableColumn<{ id: string }>[] = [
      { id: "id", header: "Агент", cell: ({ row }) => row.original.id },
      { id: "sources", header: "Источников", meta: { needs: "listSources" }, cell: () => 0 },
    ];
    withPermissions([], <DataTable id="test" columns={columns} data={[{ id: "a1" }]} getRowId={(row) => row.id} empty={null} />);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual(["Агент"]);
  });
});
