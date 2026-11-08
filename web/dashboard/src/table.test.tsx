import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { type ReactNode, useState } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Categories } from "./components/domain";
import { FilterInput } from "./components/ui/form";
import { TooltipProvider } from "./components/ui/menu";
import { DataTable, type TableColumn } from "./components/ui/table";
import { lowerFirst } from "./labels";
import { PermissionsProvider } from "./permissions";

interface Agent {
  id: string;
  environmentId: string;
}

// The columns read the names of environments, which arrive after the agents.
function Agents({ names }: { names: Record<string, string> | undefined }) {
  const columns: TableColumn<Agent>[] = [
    { id: "environment", header: "Среда", accessorFn: (row) => names?.[row.environmentId] ?? "—", cell: ({ getValue }) => getValue() as string },
  ];
  return <DataTable id="test" columns={columns} data={agents} getRowId={(row) => row.id} empty={null} />;
}

const agents: Agent[] = [{ id: "a1", environmentId: "e1" }];

afterEach(cleanup);

function wrap(children: ReactNode) {
  return (
    <MemoryRouter>
      <PermissionsProvider permissions={[]}>
        <TooltipProvider>{children}</TooltipProvider>
      </PermissionsProvider>
    </MemoryRouter>
  );
}

describe("data table", () => {
  it("shows a value its columns read once that value arrives, not the one cached before", () => {
    const { rerender } = render(wrap(<Agents names={undefined} />));
    expect(screen.getByRole("cell").textContent).toBe("—");
    rerender(wrap(<Agents names={{ e1: "production" }} />));
    expect(screen.getByRole("cell").textContent).toBe("production");
  });

  it("opens a row from the keyboard as from the mouse", () => {
    const opened = vi.fn();
    const columns: TableColumn<Agent>[] = [{ id: "id", header: "Агент", cell: ({ row }) => row.original.id }];
    render(wrap(<DataTable id="test" columns={columns} data={agents} getRowId={(row) => row.id} empty={null} onRowClick={opened} />));
    const row = screen.getAllByRole("row")[1] as HTMLElement;
    expect(row.tabIndex).toBe(0);
    fireEvent.keyDown(row, { key: "Enter" });
    expect(opened).toHaveBeenCalledWith(agents[0]);
  });
});

describe("categories in a row", () => {
  it("show the first and count the rest", () => {
    render(wrap(<Categories ids={["PERSONAL.EMAIL", "GOVERNMENT.TAX_ID", "GOVERNMENT.SNILS"]} limit={1} />));
    expect(screen.getByText("Email")).toBeTruthy();
    expect(screen.queryByText("ИНН")).toBeNull();
    expect(screen.getByText("+2").closest("[aria-label]")?.getAttribute("aria-label")).toBe("Ещё: ИНН, СНИЛС");
  });

  it("never hide a single category behind a count", () => {
    render(wrap(<Categories ids={["PERSONAL.EMAIL", "GOVERNMENT.TAX_ID"]} limit={1} />));
    expect(screen.getByText("ИНН")).toBeTruthy();
    expect(screen.queryByText("+1")).toBeNull();
  });
});

describe("filter input", () => {
  afterEach(() => vi.useRealTimers());

  function Filter({ onSend }: { onSend: (value: string) => void }) {
    const [value, setValue] = useState("");
    return <FilterInput aria-label="Поиск" value={value} onValueChange={(next) => { onSend(next); setValue(next); }} />;
  }

  it("sends what was typed once typing pauses", () => {
    vi.useFakeTimers();
    const sent = vi.fn();
    render(<Filter onSend={sent} />);
    const input = screen.getByLabelText("Поиск");
    fireEvent.change(input, { target: { value: "d" } });
    fireEvent.change(input, { target: { value: "dg_" } });
    act(() => vi.advanceTimersByTime(299));
    expect(sent).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(1));
    expect(sent).toHaveBeenCalledTimes(1);
    expect(sent).toHaveBeenCalledWith("dg_");
  });
});

describe("lowerFirst", () => {
  it("keeps an abbreviation inside the label", () => {
    expect(lowerFirst("Только учётная запись СУБД")).toBe("только учётная запись СУБД");
  });
});
