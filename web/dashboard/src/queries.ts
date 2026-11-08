import { type QueryKey, queryOptions, skipToken, useQuery, type UseQueryOptions, type UseQueryResult } from "@tanstack/react-query";

import { api, type TimeWindow } from "./api";
import { type Permission, useCan } from "./permissions";

declare module "@tanstack/react-query" {
  interface Register {
    // The permission of the API operation behind the read.
    queryMeta: { needs?: Permission };
  }
}

// Reads shared by several pages. The key and the request are declared once, so
// pages share one cache entry and an invalidation reaches every reader. Keys
// nest: invalidating ["sources"] refreshes each source as well.
export const queries = {
  sources: () => queryOptions({ queryKey: ["sources"], queryFn: api.sources, meta: { needs: "listSources" } }),
  source: (id: string) => queryOptions({ queryKey: ["sources", id], queryFn: () => api.source(id), meta: { needs: "getSource" } }),
  agents: () => queryOptions({ queryKey: ["agents"], queryFn: api.agents, meta: { needs: "listAgents" } }),
  agent: (id: string) => queryOptions({ queryKey: ["agents", id], queryFn: () => api.agent(id), meta: { needs: "getAgent" } }),
  environments: () => queryOptions({ queryKey: ["environments"], queryFn: api.environments, meta: { needs: "listEnvironments" } }),
  tenants: () => queryOptions({ queryKey: ["tenants"], queryFn: api.tenants, meta: { needs: "listTenants" } }),
  scans: () => queryOptions({ queryKey: ["scans"], queryFn: api.scans, meta: { needs: "listScans" } }),
  coverage: (windowHours: number) =>
    queryOptions({ queryKey: ["coverage", windowHours], queryFn: () => api.coverage(windowHours), meta: { needs: "getAuditCoverage" } }),
  inventory: () => queryOptions({ queryKey: ["inventory"], queryFn: api.inventory, meta: { needs: "getCatalogSummary" } }),
  categories: (window: TimeWindow) =>
    queryOptions({ queryKey: ["categories", window.from, window.to], queryFn: () => api.categories(window), meta: { needs: "listAccessByCategory" } }),
  signals: () => queryOptions({ queryKey: ["signals"], queryFn: api.signals, refetchInterval: 60_000, meta: { needs: "listRiskSignals" } }),
  // Without a published policy the answer is 404, which a retry will not change.
  policy: () => queryOptions({ queryKey: ["policy"], queryFn: api.policy, retry: false, meta: { needs: "getPolicy" } }),
  // The current version is part of the key, so a new publication lists itself.
  policyVersions: (current: number) =>
    queryOptions({ queryKey: ["policy", "versions", current], queryFn: api.policyVersions, meta: { needs: "listPolicyVersions" } }),
  policyVersion: (version: number | null) =>
    queryOptions({
      queryKey: ["policy", "version", version],
      queryFn: version === null ? skipToken : () => api.policyVersion(version),
      meta: { needs: "getPolicyVersion" },
    }),
  table: (id: string) => queryOptions({ queryKey: ["table", id], queryFn: () => api.table(id), meta: { needs: "getCatalogTable" } }),
  column: (id: string) => queryOptions({ queryKey: ["column", id], queryFn: () => api.column(id), meta: { needs: "getCatalogColumn" } }),
};

// A read on a page that some users see without its permission. For them it
// stays idle instead of collecting a certain 403 (ADR-0010).
export function usePermittedQuery<TQueryFnData, TError = Error, TData = TQueryFnData, TQueryKey extends QueryKey = QueryKey>(
  options: UseQueryOptions<TQueryFnData, TError, TData, TQueryKey>,
): UseQueryResult<TData, TError> {
  const can = useCan();
  const needs = options.meta?.needs;
  return useQuery({ ...options, enabled: needs === undefined || can(needs) ? options.enabled : false });
}
