import {
  Building2,
  Database,
  History,
  Layers,
  LayoutDashboard,
  type LucideIcon,
  Plug,
  ScrollText,
  ServerCog,
  ShieldCheck,
  Siren,
  Tags,
  Users,
} from "lucide-react";

import type { Permission } from "./permissions";

export interface Section {
  path: string;
  title: string;
  icon: LucideIcon;
  // Sections are grouped by the task they serve, never by who uses them.
  group: string;
  // The section is shown when any of these is allowed: each one fills a part of it.
  needs: readonly Permission[];
  // Object pages that belong to the section, so navigation shows where the user is.
  owns: readonly string[];
}

export const sections: readonly Section[] = [
  { path: "/overview", title: "Обзор", icon: LayoutDashboard, group: "", needs: ["getAccessSummary", "getAuditCoverage", "listAccessByCategory", "listCatalogChanges", "getAccessTimeline"], owns: [] },
  { path: "/inventory", title: "Инвентаризация", icon: Database, group: "Данные", needs: ["listCatalogTables"], owns: ["/tables/", "/columns/"] },
  { path: "/classification", title: "Классификация", icon: Tags, group: "Данные", needs: ["listCatalogColumns", "getCatalogSummary", "listAccessByCategory"], owns: ["/categories/"] },
  { path: "/audit", title: "Журнал событий", icon: ScrollText, group: "Аудит", needs: ["listAuditEvents"], owns: [] },
  { path: "/principals", title: "Пользователи СУБД", icon: Users, group: "Аудит", needs: ["listAccessByPrincipal"], owns: [] },
  { path: "/signals", title: "Сигналы риска", icon: Siren, group: "Аудит", needs: ["listRiskSignals"], owns: [] },
  { path: "/sources", title: "Источники", icon: Plug, group: "Инфраструктура", needs: ["listSources", "getAuditCoverage"], owns: [] },
  { path: "/agents", title: "Агенты", icon: ServerCog, group: "Инфраструктура", needs: ["listAgents", "createEnrollmentToken"], owns: [] },
  { path: "/policy", title: "Политика", icon: ShieldCheck, group: "Контроль", needs: ["getPolicy"], owns: [] },
  { path: "/environments", title: "Среды", icon: Layers, group: "Администрирование", needs: ["listEnvironments"], owns: [] },
  { path: "/tenants", title: "Организации", icon: Building2, group: "Администрирование", needs: ["listTenants"], owns: [] },
  { path: "/journal", title: "Журнал действий", icon: History, group: "Администрирование", needs: ["listOperatorActions"], owns: [] },
];

// Earlier addresses keep working: links people saved or sent still open the
// same content, with its filters.
export const movedSections: Record<string, string> = {
  "/catalog": "/classification?tab=findings",
  "/access": "/audit",
  "/identities": "/principals",
  "/compliance": "/classification",
  "/infrastructure": "/sources",
};

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
  const exact = sections.find((section) => pathname === section.path);
  if (exact) return exact;
  return sections.find((section) => section.owns.some((prefix) => pathname.startsWith(prefix)) || pathname.startsWith(`${section.path}/`));
}
