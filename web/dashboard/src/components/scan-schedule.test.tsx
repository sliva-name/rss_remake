import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Schemas } from "../api";
import { type Permission, PermissionsProvider } from "../permissions";
import { localMinute, nextNight, ScanSchedulePanel } from "./scan-schedule";
import { NotificationsProvider } from "./ui/toast";

const source = {
  id: "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f", key: "crm", draft: false,
  scanSchedule: { everyHours: 24, nextRunAt: "2026-11-14T02:00:00Z" },
} as Schemas["Source"];

function panel(permissions: readonly Permission[], item: Schemas["Source"]) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <NotificationsProvider>
        <PermissionsProvider permissions={permissions}>
          <ScanSchedulePanel source={item} />
        </PermissionsProvider>
      </NotificationsProvider>
    </QueryClientProvider>,
  );
}

describe("scan schedule", () => {
  it("shows the schedule to everyone and the controls only to those who may change it", () => {
    panel(["getSource"], source);
    expect(screen.getByText(/Сканировать каждый день/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("offers to set a schedule where there is none, and to switch off one that exists", () => {
    const buttons = () => screen.getAllByRole("button").map((button) => button.textContent.trim());
    const manual = panel(["setScanSchedule", "deleteScanSchedule"], { ...source, scanSchedule: undefined });
    expect(screen.getByText("Сканы этого источника запускаются только вручную.")).toBeTruthy();
    expect(buttons()).toEqual(["Настроить"]);
    manual.unmount();
    panel(["setScanSchedule", "deleteScanSchedule"], source);
    expect(buttons()).toEqual(["Изменить", "Отключить"]);
  });

  it("suggests the coming night by the local clock", () => {
    expect(localMinute(nextNight(new Date(2026, 10, 13, 1, 30)))).toBe("2026-11-13T02:00");
    expect(localMinute(nextNight(new Date(2026, 10, 13, 2, 0)))).toBe("2026-11-14T02:00");
    expect(localMinute(nextNight(new Date(2026, 10, 13, 23, 15)))).toBe("2026-11-14T02:00");
  });
});
