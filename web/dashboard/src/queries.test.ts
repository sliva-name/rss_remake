import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import type { Schemas } from "./api";
import { queries } from "./queries";

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
});
