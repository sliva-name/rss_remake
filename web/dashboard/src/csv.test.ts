import { describe, expect, it } from "vitest";

import { cell, toCsv } from "./csv";

describe("csv", () => {
  it("never lets a spreadsheet run a value as a formula", () => {
    for (const value of ["=HYPERLINK(\"x\")", "+1", "-2", "@SUM(A1)"]) {
      expect(cell(value).replace(/^"/, "").startsWith("'")).toBe(true);
    }
    expect(cell("dg_app")).toBe("dg_app");
  });

  it("quotes separators and quotes", () => {
    expect(toCsv(["a", "b"], [["x, y", 'say "hi"']])).toBe('a,b\r\n"x, y","say ""hi"""');
  });
});
