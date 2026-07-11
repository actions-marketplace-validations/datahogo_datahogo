import { describe, it, expect } from "vitest";
import { toSarif } from "./sarif.js";
import type { FindingData } from "@datahogo/core";

function makeFinding(overrides: Partial<FindingData> = {}): FindingData {
  return {
    vulnerability_id: 42,
    severity: "high",
    category: "injection",
    title: "SQL Injection",
    file_path: "src/db.ts",
    line_number: 10,
    status: "open",
    ...overrides,
  };
}

describe("toSarif", () => {
  it("produces a valid SARIF 2.1.0 envelope", () => {
    const sarif = toSarif([makeFinding()], "0.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("datahogo");
    expect(sarif.runs[0].tool.driver.version).toBe("0.1.0");
  });

  it("maps severities to SARIF levels", () => {
    const sarif = toSarif(
      [
        makeFinding({ severity: "critical" }),
        makeFinding({ severity: "high" }),
        makeFinding({ severity: "medium" }),
        makeFinding({ severity: "low" }),
        makeFinding({ severity: "info" }),
      ],
      "0.1.0",
    );
    const levels = sarif.runs[0].results.map((r) => r.level);
    expect(levels).toEqual(["error", "error", "warning", "note", "note"]);
  });

  it("deduplicates rules by vulnerability id", () => {
    const sarif = toSarif(
      [makeFinding(), makeFinding({ line_number: 20 }), makeFinding({ vulnerability_id: 7, title: "XSS" })],
      "0.1.0",
    );
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2);
    expect(sarif.runs[0].results).toHaveLength(3);
  });

  it("falls back to line 1 and 'unknown' uri when location is missing", () => {
    const sarif = toSarif([makeFinding({ file_path: undefined, line_number: undefined })], "0.1.0");
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe("unknown");
    expect(loc.region.startLine).toBe(1);
  });

  it("includes fix description in the message when present", () => {
    const sarif = toSarif([makeFinding({ fix_description: "Use parameterized queries" })], "0.1.0");
    expect(sarif.runs[0].results[0].message.text).toContain("Fix: Use parameterized queries");
  });
});
