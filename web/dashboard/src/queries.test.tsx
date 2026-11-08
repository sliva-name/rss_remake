import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { api, type Schemas } from "./api";
import { type Permission, PermissionsProvider } from "./permissions";
import { queries, usePermittedQuery } from "./queries";

vi.mock("./api", () => ({ api: { sources: vi.fn() } }));

function renderWith(permissions: readonly Permission[], hook: () => unknown) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return renderHook(hook, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={client}>
        <PermissionsProvider permissions={permissions}>{children}</PermissionsProvider>
      </QueryClientProvider>
    ),
  });
}

describe("shared queries", () => {
  it("refresh an object when its list is invalidated, so a save invalidates one key", async () => {
    const client = new QueryClient();
    client.setQueryData(queries.source("s1").queryKey, {} as Schemas["Source"]);
    client.setQueryData(queries.agent("a1").queryKey, {} as Schemas["Agent"]);
    client.setQueryData(queries.policyVersions(3).queryKey, []);

    await client.invalidateQueries({ queryKey: queries.sources().queryKey });
    await client.invalidateQueries({ queryKey: queries.agents().queryKey });
    await client.invalidateQueries({ queryKey: queries.policy().queryKey });

    expect(client.getQueryState(queries.source("s1").queryKey)?.isInvalidated).toBe(true);
    expect(client.getQueryState(queries.agent("a1").queryKey)?.isInvalidated).toBe(true);
    expect(client.getQueryState(queries.policyVersions(3).queryKey)?.isInvalidated).toBe(true);
  });

  it("are not requested without their permission, and are with it", async () => {
    vi.mocked(api.sources).mockResolvedValue([]);
    const denied = renderWith([], () => usePermittedQuery(queries.sources()));
    expect(denied.result.current).toMatchObject({ fetchStatus: "idle" });
    expect(api.sources).not.toHaveBeenCalled();

    const allowed = renderWith(["listSources"], () => usePermittedQuery(queries.sources()));
    await waitFor(() => expect(allowed.result.current).toMatchObject({ isSuccess: true }));
    expect(api.sources).toHaveBeenCalledOnce();
  });
});
