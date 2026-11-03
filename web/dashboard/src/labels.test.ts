import { describe, expect, it } from "vitest";

import { evidenceLevel, explain, failure, identity, percent, sourceStatus } from "./labels";

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

  it("says what to do about a refusal", () => {
    expect(failure("TARGET_NOT_ALLOWED").action).toContain("allowed.hosts");
    expect(sourceStatus("TARGET_NOT_ALLOWED", "2026-11-03T10:00:00Z")).toEqual({ label: "Адрес не разрешён агенту", tone: "bad" });
    expect(explain("SOURCE_DELETED")).toBe("Источник удалён. Ничего делать не нужно: скан отменён вместе с источником.");
  });

  it("shows an unknown code as is rather than hiding it", () => {
    expect(failure("SOMETHING_NEW")).toEqual({ problem: "SOMETHING_NEW", action: "" });
    expect(explain("SOMETHING_NEW")).toBe("SOMETHING_NEW");
  });
});
