import { describe, expect, it } from "vitest";

import type { Permission } from "./permissions";
import { groupSections, sectionOf, visibleSections } from "./sections";

const titles = (permissions: Permission[]) => visibleSections((permission) => permissions.includes(permission)).map((section) => section.title);

const reader: Permission[] = [
  "getCurrentUser", "listEnvironments", "listAgents", "listSources", "listScans", "listCatalogColumns", "getCatalogSummary",
  "listCatalogChanges", "listAuditEvents", "getAuditCoverage", "getAccessSummary", "listAccessByPrincipal", "listAccessByCategory", "getPolicy",
];

describe("sections", () => {
  it("are the same list for everyone, filtered only by permissions", () => {
    expect(titles(reader)).toEqual(["Обзор", "Каталог данных", "Обращения", "Пользователи", "Отчёты", "Источники и агенты"]);
  });

  it("show a platform administrator without an organization only organizations", () => {
    expect(titles(["getCurrentUser", "listTenants", "createTenant"])).toEqual(["Организации"]);
  });

  it("join for a user who manages the platform and works in an organization", () => {
    expect(titles([...reader, "listTenants"])).toContain("Организации");
    expect(titles([...reader, "listTenants"])).toContain("Обращения");
  });

  it("keep a section that only one of its parts makes useful", () => {
    expect(titles(["getAuditCoverage"])).toEqual(["Обзор", "Источники и агенты"]);
  });

  it("hide everything from a user without permissions", () => {
    expect(titles(["getCurrentUser"])).toEqual([]);
  });

  it("are grouped by task, with no heading for a group the user cannot use", () => {
    const groups = groupSections(visibleSections((permission) => ["listAuditEvents", "listTenants"].includes(permission)));
    expect(groups.map((group) => [group.group, group.sections.map((section) => section.title)])).toEqual([
      ["Доступ к данным", ["Обращения"]],
      ["Администрирование", ["Организации"]],
    ]);
  });

  it("know which section an object page belongs to", () => {
    expect(sectionOf("/columns/abc")?.title).toBe("Каталог данных");
    expect(sectionOf("/agents/abc")?.title).toBe("Источники и агенты");
    expect(sectionOf("/access")?.title).toBe("Обращения");
  });
});
