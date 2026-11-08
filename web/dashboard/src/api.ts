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

// A reporting window: ISO timestamps, end exclusive.
export interface TimeWindow {
  from: string;
  to: string;
}

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
  summary: (window: TimeWindow) => request<Schemas["AccessSummary"]>("GET", "/analytics/summary", { ...window }),
  timeline: (window: TimeWindow) => request<Schemas["TimelinePoint"][]>("GET", "/analytics/timeline", { ...window }),
  principals: (window: TimeWindow, filter: { category?: string; columnId?: string } = {}) =>
    request<Schemas["PrincipalAccess"][]>("GET", "/analytics/principals", { ...window, ...filter }),
  categories: (window: TimeWindow) => request<Schemas["CategoryAccess"][]>("GET", "/analytics/categories", { ...window }),
  coverage: (windowHours: number) => request<Schemas["CoverageRow"][]>("GET", "/audit/coverage", { windowHours }),
  events: (query: Query) => request<Schemas["AuditEventPage"]>("GET", "/audit/events", query),
  catalog: (query: Query) => request<Schemas["CatalogPage"]>("GET", "/catalog/columns", query),
  inventory: () => request<Schemas["CategoryInventory"][]>("GET", "/catalog/summary"),
  changes: (query: Query = {}) => request<Schemas["CatalogChange"][]>("GET", "/catalog/changes", { limit: 20, ...query }),
  search: (q: string) => request<Schemas["SearchResult"]>("GET", "/search", { q }),
  policy: () => request<Schemas["Policy"]>("GET", "/policy"),
  publishPolicy: (draft: Schemas["PolicyDraft"]) => request<Schemas["Policy"]>("PUT", "/policy", undefined, draft),
  sources: () => request<Schemas["Source"][]>("GET", "/sources"),
  source: (id: string) => request<Schemas["Source"]>("GET", `/sources/${id}`),
  agent: (id: string) => request<Schemas["Agent"]>("GET", `/agents/${id}`),
  tables: (query: Query) => request<Schemas["CatalogTablePage"]>("GET", "/catalog/tables", query),
  table: (id: string) => request<Schemas["CatalogTableDetail"]>("GET", `/catalog/tables/${id}`),
  column: (id: string) => request<Schemas["CatalogColumnDetail"]>("GET", `/catalog/columns/${id}`),
  createSource: (body: Schemas["NewSource"]) => request<Schemas["Source"]>("POST", "/sources", undefined, body),
  updateSource: (id: string, body: Schemas["SourceUpdate"]) => request<Schemas["Source"]>("PUT", `/sources/${id}`, undefined, body),
  deleteSource: (id: string) => request<void>("DELETE", `/sources/${id}`),
  activateSource: (id: string) => request<Schemas["Source"]>("POST", `/sources/${id}/activate`),
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
  preference: (key: Schemas["PreferenceKey"]) => request<Schemas["Preference"]>("GET", `/preferences/${key}`),
  savePreference: (key: Schemas["PreferenceKey"], value: unknown) => request<void>("PUT", `/preferences/${key}`, undefined, { value }),
  policyVersions: () => request<Schemas["PolicyVersion"][]>("GET", "/policy/versions"),
  policyVersion: (version: number) => request<Schemas["Policy"]>("GET", `/policy/versions/${version}`),
  signals: () => request<Schemas["RiskSignal"][]>("GET", "/analytics/signals"),
};

// The export goes through fetch rather than a plain link: the request carries
// the access token, which a link cannot. Resolves to whether the server cut
// the file at its limit.
export async function downloadEvents(query: Query, filename: string): Promise<{ truncated: boolean }> {
  const token = await accessToken();
  const response = await fetch(url("/audit/events/export", query), { headers: { Authorization: `Bearer ${token ?? ""}` } });
  if (response.status === 401) {
    await signIn();
    throw new ApiError(401, "сессия истекла");
  }
  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as Schemas["Problem"] | null;
    throw new ApiError(response.status, problem?.message ?? "выгрузка не удалась");
  }
  saveFile(await response.blob(), filename);
  return { truncated: response.headers.get("X-Dataguard-Truncated") === "true" };
}

export function saveFile(blob: Blob, filename: string) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}
