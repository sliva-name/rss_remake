import { accessToken, signIn } from "./auth";
import type { components } from "./schema";

export type Schemas = components["schemas"];

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

type Query = Record<string, string | number | undefined>;

function url(path: string, query?: Query): string {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== "") parameters.set(key, String(value));
  }
  const suffix = parameters.toString();
  return `/api/v1${path}${suffix ? `?${suffix}` : ""}`;
}

async function request<T>(method: string, path: string, query?: Query, body?: unknown): Promise<T> {
  const token = await accessToken();
  const response = await fetch(url(path, query), {
    method,
    headers: {
      Authorization: `Bearer ${token ?? ""}`,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    await signIn();
    throw new ApiError(401, "сессия истекла");
  }
  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Schemas["Problem"] | null;
    throw new ApiError(response.status, problem?.message ?? "запрос не выполнен");
  }
  return (response.status === 204 ? undefined : await response.json()) as T;
}

export const api = {
  me: () => request<Schemas["CurrentUser"]>("GET", "/me"),
  summary: () => request<Schemas["AccessSummary"]>("GET", "/analytics/summary"),
  principals: (category?: string) => request<Schemas["PrincipalAccess"][]>("GET", "/analytics/principals", { category }),
  categories: () => request<Schemas["CategoryAccess"][]>("GET", "/analytics/categories"),
  coverage: (windowHours: number) => request<Schemas["CoverageRow"][]>("GET", "/audit/coverage", { windowHours }),
  events: (query: Query) => request<Schemas["AuditEventPage"]>("GET", "/audit/events", query),
  catalog: (query: Query) => request<Schemas["CatalogPage"]>("GET", "/catalog/columns", query),
  inventory: () => request<Schemas["CategoryInventory"][]>("GET", "/catalog/summary"),
  changes: () => request<Schemas["CatalogChange"][]>("GET", "/catalog/changes", { limit: 20 }),
  sources: () => request<Schemas["Source"][]>("GET", "/sources"),
  source: (id: string) => request<Schemas["Source"]>("GET", `/sources/${id}`),
  agent: (id: string) => request<Schemas["Agent"]>("GET", `/agents/${id}`),
  tables: (query: Query) => request<Schemas["CatalogTablePage"]>("GET", "/catalog/tables", query),
  table: (id: string) => request<Schemas["CatalogTableDetail"]>("GET", `/catalog/tables/${id}`),
  column: (id: string) => request<Schemas["CatalogColumnDetail"]>("GET", `/catalog/columns/${id}`),
  createSource: (body: Schemas["NewSource"]) => request<Schemas["Source"]>("POST", "/sources", undefined, body),
  updateSource: (id: string, body: Schemas["SourceUpdate"]) => request<Schemas["Source"]>("PUT", `/sources/${id}`, undefined, body),
  deleteSource: (id: string) => request<void>("DELETE", `/sources/${id}`),
  agents: () => request<Schemas["Agent"][]>("GET", "/agents"),
  revokeAgent: (id: string) => request<void>("POST", `/agents/${id}/revoke`),
  scans: () => request<Schemas["Scan"][]>("GET", "/scans", { limit: 20 }),
  requestScan: (sourceId: string) => request<Schemas["Scan"]>("POST", "/scans", undefined, { sourceId }),
  environments: () => request<Schemas["Environment"][]>("GET", "/environments"),
  createEnvironment: (body: Schemas["NewEnvironment"]) =>
    request<Schemas["Environment"]>("POST", "/environments", undefined, body),
  createToken: (environmentId: string) =>
    request<Schemas["EnrollmentToken"]>("POST", "/enrollment-tokens", undefined, { environmentId }),
  tenants: () => request<Schemas["Tenant"][]>("GET", "/tenants"),
  createTenant: (name: string) => request<Schemas["Tenant"]>("POST", "/tenants", undefined, { name }),
};
