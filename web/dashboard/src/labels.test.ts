import { describe, expect, it } from "vitest";

import { evidenceLevel, identity, percent } from "./labels";

describe("labels", () => {
  it("never renders a missing measurement as zero", () => {
    expect(percent(undefined)).toBe("нет данных");
    expect(percent(0)).toBe("0%");
  });

  it("does not claim a read for a mere reference", () => {
    expect(evidenceLevel("EVIDENCE_LEVEL_REFERENCED")).toBe("Упомянуто в запросе");
  });

  it("does not guess an identity", () => {
    expect(identity("IDENTITY_CONFIDENCE_UNKNOWN")).toBe("Не идентифицирован");
    expect(identity("")).toBe("Не идентифицирован");
  });
});
