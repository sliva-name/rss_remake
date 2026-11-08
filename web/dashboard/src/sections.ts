import type { Permission } from "./permissions";

export interface Section {
  path: string;
  title: string;
  // The section is shown when any of these is allowed: each one fills a part of it.
  needs: readonly Permission[];
}

export const sections: readonly Section[] = [
  { path: "/overview", title: "Обзор", needs: ["getAccessSummary", "getAuditCoverage", "listAccessByCategory", "listCatalogChanges"] },
  { path: "/catalog", title: "Каталог данных", needs: ["listCatalogColumns"] },
  { path: "/access", title: "Обращения", needs: ["listAuditEvents"] },
  { path: "/identities", title: "Пользователи", needs: ["listAccessByPrincipal"] },
  { path: "/compliance", title: "Отчёты", needs: ["getCatalogSummary", "listAccessByCategory"] },
  { path: "/infrastructure", title: "Инфраструктура", needs: ["listSources", "getAuditCoverage", "listScans", "listAgents", "createEnrollmentToken"] },
  { path: "/tenants", title: "Организации", needs: ["listTenants"] },
];

export function visibleSections(can: (permission: Permission) => boolean): Section[] {
  return sections.filter((section) => section.needs.some(can));
}
