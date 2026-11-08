import type { Permission } from "./permissions";

export interface Section {
  path: string;
  title: string;
  // Sections are grouped by the task they serve, never by who uses them.
  group: string;
  // The section is shown when any of these is allowed: each one fills a part of it.
  needs: readonly Permission[];
  // Object pages that belong to the section, so navigation shows where the user is.
  owns: readonly string[];
}

export const sections: readonly Section[] = [
  { path: "/overview", title: "Обзор", group: "", needs: ["getAccessSummary", "getAuditCoverage", "listAccessByCategory", "listCatalogChanges"], owns: [] },
  { path: "/catalog", title: "Каталог данных", group: "Данные", needs: ["listCatalogColumns"], owns: ["/tables/", "/columns/", "/categories/"] },
  { path: "/access", title: "Обращения", group: "Доступ к данным", needs: ["listAuditEvents"], owns: [] },
  { path: "/identities", title: "Пользователи", group: "Доступ к данным", needs: ["listAccessByPrincipal"], owns: [] },
  { path: "/compliance", title: "Отчёты", group: "Доступ к данным", needs: ["getCatalogSummary", "listAccessByCategory"], owns: [] },
  { path: "/infrastructure", title: "Источники и агенты", group: "Инфраструктура", needs: ["listSources", "getAuditCoverage", "listScans", "listAgents", "createEnrollmentToken"], owns: ["/sources/", "/agents/"] },
  { path: "/tenants", title: "Организации", group: "Администрирование", needs: ["listTenants"], owns: [] },
];

export function visibleSections(can: (permission: Permission) => boolean): Section[] {
  return sections.filter((section) => section.needs.some(can));
}

// Visible sections under their group headings, in order. A group with nothing
// visible has no heading.
export function groupSections(visible: readonly Section[]): { group: string; sections: Section[] }[] {
  const groups: { group: string; sections: Section[] }[] = [];
  for (const section of visible) {
    const last = groups[groups.length - 1];
    if (last && last.group === section.group) last.sections.push(section);
    else groups.push({ group: section.group, sections: [section] });
  }
  return groups;
}

export function sectionOf(pathname: string): Section | undefined {
  return sections.find((section) => pathname.startsWith(section.path) || section.owns.some((prefix) => pathname.startsWith(prefix)));
}
