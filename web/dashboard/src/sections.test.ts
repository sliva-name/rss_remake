import { describe, expect, it } from "vitest";

import type { Permission } from "./permissions";
import { groupSections, sectionOf, visibleSections } from "./sections";

const titles = (permissions: Permission[]) => visibleSections((permission) => permissions.includes(permission)).map((section) => section.title);

const auditor: Permission[] = [
  "getCurrentUser", "listEnvironments", "listAgents", "getAgent", "listSources", "getSource", "listScans", "listCatalogColumns", "getCatalogColumn",
  "listCatalogTables", "getCatalogTable", "getCatalogSummary", "listCatalogChanges", "listAuditEvents", "getAuditCoverage", "getAccessSummary",
  "getAccessTimeline", "search", "listAccessByPrincipal", "listAccessByCategory", "getPolicy",
];

describe("sections", () => {
  it("are the same list for everyone, filtered only by permissions", () => {
    expect(titles(auditor)).toEqual([
      "Обзор", "Инвентаризация", "Классификация", "Журнал событий", "Пользователи СУБД", "Источники", "Агенты", "Политика", "Среды",
    ]);
  });

  it("show a platform administrator without an organization only organizations", () => {
    expect(titles(["getCurrentUser", "listTenants", "createTenant"])).toEqual(["Организации"]);
  });

  it("join for a user who manages the platform and works in an organization", () => {
    expect(titles([...auditor, "listTenants"])).toContain("Организации");
    expect(titles([...auditor, "listTenants"])).toContain("Журнал событий");
  });

  it("keep a section that only one of its parts makes useful", () => {
    expect(titles(["getAuditCoverage"])).toEqual(["Обзор", "Источники"]);
    expect(titles(["createEnrollmentToken"])).toEqual(["Агенты"]);
  });

  it("hide everything from a user without permissions", () => {
    expect(titles(["getCurrentUser"])).toEqual([]);
  });

  it("are grouped by task, with no heading for a group the user cannot use", () => {
    const groups = groupSections(visibleSections((permission) => ["listAuditEvents", "listTenants"].includes(permission)));
    expect(groups.map((group) => [group.group, group.sections.map((section) => section.title)])).toEqual([
      ["Аудит", ["Журнал событий"]],
      ["Администрирование", ["Организации"]],
    ]);
  });

  it("know which section an object page belongs to", () => {
    expect(sectionOf("/columns/abc")?.title).toBe("Инвентаризация");
    expect(sectionOf("/categories/PERSONAL.EMAIL")?.title).toBe("Классификация");
    expect(sectionOf("/sources/abc")?.title).toBe("Источники");
    expect(sectionOf("/agents/abc")?.title).toBe("Агенты");
    expect(sectionOf("/audit")?.title).toBe("Журнал событий");
  });
});
