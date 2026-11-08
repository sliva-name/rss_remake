import { queryOptions, skipToken } from "@tanstack/react-query";

import { api, type TimeWindow } from "./api";

// Reads shared by several pages. The key and the request are declared once, so
// pages share one cache entry and an invalidation reaches every reader. Keys
// nest: invalidating ["sources"] refreshes each source as well.
export const queries = {
  sources: () => queryOptions({ queryKey: ["sources"], queryFn: api.sources }),
  source: (id: string) => queryOptions({ queryKey: ["sources", id], queryFn: () => api.source(id) }),
  agents: () => queryOptions({ queryKey: ["agents"], queryFn: api.agents }),
  agent: (id: string) => queryOptions({ queryKey: ["agents", id], queryFn: () => api.agent(id) }),
  environments: () => queryOptions({ queryKey: ["environments"], queryFn: api.environments }),
  tenants: () => queryOptions({ queryKey: ["tenants"], queryFn: api.tenants }),
  scans: () => queryOptions({ queryKey: ["scans"], queryFn: api.scans }),
  coverage: (windowHours: number) =>
    queryOptions({ queryKey: ["coverage", windowHours], queryFn: () => api.coverage(windowHours) }),
  inventory: () => queryOptions({ queryKey: ["inventory"], queryFn: api.inventory }),
  categories: (window: TimeWindow) =>
    queryOptions({ queryKey: ["categories", window.from, window.to], queryFn: () => api.categories(window) }),
  signals: () => queryOptions({ queryKey: ["signals"], queryFn: api.signals, refetchInterval: 60_000 }),
  // Without a published policy the answer is 404, which a retry will not change.
  policy: () => queryOptions({ queryKey: ["policy"], queryFn: api.policy, retry: false }),
  // The current version is part of the key, so a new publication lists itself.
  policyVersions: (current: number) =>
    queryOptions({ queryKey: ["policy", "versions", current], queryFn: api.policyVersions }),
  policyVersion: (version: number | null) =>
    queryOptions({
      queryKey: ["policy", "version", version],
      queryFn: version === null ? skipToken : () => api.policyVersion(version),
    }),
  table: (id: string) => queryOptions({ queryKey: ["table", id], queryFn: () => api.table(id) }),
  column: (id: string) => queryOptions({ queryKey: ["column", id], queryFn: () => api.column(id) }),
};
