import { describe, expect, it } from "vitest";

import { paths } from "./links";

describe("links", () => {
  it("carry only the filters that are set", () => {
    expect(paths.events({ columnId: "c1", principal: "", category: undefined })).toBe("/audit?columnId=c1");
    expect(paths.events({})).toBe("/audit");
  });

  it("encode what a user typed", () => {
    expect(paths.events({ principal: "иванов & ко" })).toBe("/audit?principal=%D0%B8%D0%B2%D0%B0%D0%BD%D0%BE%D0%B2+%26+%D0%BA%D0%BE");
    expect(paths.findings({ category: "PERSONAL.EMAIL", sourceId: "s1" })).toBe("/classification?tab=findings&category=PERSONAL.EMAIL&sourceId=s1");
    expect(paths.inventory({ category: "GOVERNMENT.TAX_ID" })).toBe("/inventory?category=GOVERNMENT.TAX_ID");
  });
});
