import { describe, expect, it } from "vitest";

import type { Permission } from "./permissions";
import { visibleSections } from "./sections";

const titles = (permissions: Permission[]) => visibleSections((permission) => permissions.includes(permission)).map((section) => section.title);

const reader: Permission[] = [
  "getCurrentUser", "listEnvironments", "listAgents", "listSources", "listScans", "listCatalogColumns", "getCatalogSummary",
  "listCatalogChanges", "listAuditEvents", "getAuditCoverage", "getAccessSummary", "listAccessByPrincipal", "listAccessByCategory", "getPolicy",
];

describe("sections", () => {
  it("are the same list for everyone, filtered only by permissions", () => {
    expect(titles(reader)).toEqual(["Обзор", "Каталог данных", "Обращения", "Пользователи", "Отчёты", "Инфраструктура"]);
  });

  it("show a platform administrator without an organization only organizations", () => {
    expect(titles(["getCurrentUser", "listTenants", "createTenant"])).toEqual(["Организации"]);
  });

  it("join for a user who manages the platform and works in an organization", () => {
    expect(titles([...reader, "listTenants"])).toContain("Организации");
    expect(titles([...reader, "listTenants"])).toContain("Обращения");
  });

  it("keep a section that only one of its parts makes useful", () => {
    expect(titles(["getAuditCoverage"])).toEqual(["Обзор", "Инфраструктура"]);
  });

  it("hide everything from a user without permissions", () => {
    expect(titles(["getCurrentUser"])).toEqual([]);
  });
});
