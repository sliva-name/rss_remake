import { describe, expect, it } from "vitest";

import { returnPath } from "./auth";

describe("return after sign-in", () => {
  it("comes back to the page that was opened", () => {
    expect(returnPath("/columns/7?x=1")).toBe("/columns/7?x=1");
  });

  it("never leaves the application", () => {
    for (const value of ["//evil.example/", "/\\evil.example", "https://evil.example/", "javascript:alert(1)", "", undefined, 42]) {
      expect(returnPath(value)).toBe("/");
    }
  });
});
