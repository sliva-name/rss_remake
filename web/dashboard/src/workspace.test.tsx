import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";
import { type Permission, PermissionsProvider } from "./permissions";
import { useFavorites, useOverviewLayout } from "./workspace";

vi.mock("./api", () => ({ api: { preference: vi.fn(), savePreference: vi.fn() } }));

const permissions: readonly Permission[] = ["getPreference", "savePreference"];

function renderPreference<T>(hook: () => T) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rendered = renderHook(hook, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>
        <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
      </QueryClientProvider>
    ),
  });
  return { ...rendered, client };
}

describe("personal settings", () => {
  beforeEach(() => {
    vi.mocked(api.preference).mockReset();
    vi.mocked(api.savePreference).mockReset();
  });

  it("keep a never saved setting the same object between renders, or effects that depend on it rerun forever", async () => {
    vi.mocked(api.preference).mockResolvedValue({ value: null });
    const { result, rerender } = renderPreference(() => useOverviewLayout());
    await waitFor(() => expect(result.current.canSave).toBe(true));
    const first = result.current.value;
    rerender();
    expect(result.current.value).toBe(first);
    expect(first).toEqual({ hidden: [], order: [] });
  });

  it("are not saved over when the stored value could not be read", async () => {
    vi.mocked(api.preference).mockRejectedValue(new Error("центр недоступен"));
    const { result, client } = renderPreference(() => useFavorites());
    await waitFor(() => expect(client.getQueryState(["preference", "favorites"])?.status).toBe("error"));
    expect(result.current.canSave).toBe(false);
    result.current.save([{ kind: "table", id: "t1", label: "users" }]);
    expect(api.savePreference).not.toHaveBeenCalled();
  });
});
