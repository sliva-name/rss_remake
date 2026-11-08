import { describe, expect, it } from "vitest";

import { paths } from "./links";

describe("links", () => {
  it("carry only the filters that are set", () => {
    expect(paths.events({ columnId: "c1", principal: "", category: undefined })).toBe("/access?columnId=c1");
    expect(paths.events({})).toBe("/access");
  });

  it("encode what a user typed", () => {
    expect(paths.events({ principal: "иванов & ко" })).toBe("/access?principal=%D0%B8%D0%B2%D0%B0%D0%BD%D0%BE%D0%B2+%26+%D0%BA%D0%BE");
    expect(paths.catalog({ category: "PERSONAL.EMAIL", sourceId: "s1" })).toBe("/catalog?category=PERSONAL.EMAIL&sourceId=s1");
  });
});
