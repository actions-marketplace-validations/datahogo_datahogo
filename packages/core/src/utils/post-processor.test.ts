import { describe, it, expect } from "vitest";
import { postProcessFindings } from "./post-processor";
import type { FindingData } from "../engines/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<FindingData>): FindingData {
  return {
    vulnerability_id: 1,
    severity: "medium",
    category: "web-owasp",
    title: "Test Finding",
    status: "open",
    context: "production",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Step 1: Framework-Aware Suppressions
// ---------------------------------------------------------------------------

describe("postProcessFindings — framework suppressions", () => {
  it("marks Next.js unsafe-inline CSP finding as a framework requirement", () => {
    const findings: FindingData[] = [
      makeFinding({
        vulnerability_id: 63,
        title: "Content Security Policy allows 'unsafe-inline' in script-src",
        severity: "high",
        category: "headers",
      }),
    ];

    const result = postProcessFindings(findings, ["nextjs"]);
    expect(result[0].is_framework_requirement).toBe(true);
    expect(result[0].framework_note).toContain("Next.js App Router");
  });

  it("marks robots.txt info finding as a framework requirement for Next.js", () => {
    const findings: FindingData[] = [
      makeFinding({
        vulnerability_id: 99,
        title: "robots.txt exposes site structure",
        severity: "info",
        category: "config",
      }),
    ];

    const result = postProcessFindings(findings, ["nextjs"]);
    expect(result[0].is_framework_requirement).toBe(true);
    expect(result[0].framework_note).toContain("robots.txt");
  });

  it("does NOT mark unsafe-inline as framework requirement when Next.js is not detected", () => {
    const findings: FindingData[] = [
      makeFinding({
        vulnerability_id: 63,
        title: "Content Security Policy allows 'unsafe-inline' in script-src",
        severity: "high",
        category: "headers",
      }),
    ];

    const result = postProcessFindings(findings, ["express"]);
    expect(result[0].is_framework_requirement).toBeUndefined();
  });

  it("marks Supabase sb- cookie findings as framework requirements", () => {
    const cookieFinding = makeFinding({
      vulnerability_id: 67,
      title: "Cookie missing Secure flag",
      severity: "medium",
      category: "cookies",
      code_snippet: "sb-abcdef-auth-token=...",
    });

    const result = postProcessFindings([cookieFinding], ["supabase"]);
    expect(result[0].is_framework_requirement).toBe(true);
    expect(result[0].framework_note).toContain("Supabase Auth");
  });

  it("does NOT mark a non-Supabase cookie finding as framework requirement", () => {
    const cookieFinding = makeFinding({
      vulnerability_id: 67,
      title: "Cookie missing Secure flag",
      severity: "medium",
      category: "cookies",
      code_snippet: "session=abc123",
    });

    const result = postProcessFindings([cookieFinding], ["supabase"]);
    expect(result[0].is_framework_requirement).toBeUndefined();
  });

  it("marks next-intl NEXT_LOCALE cookie as framework requirement", () => {
    const localeCookieFinding = makeFinding({
      vulnerability_id: 68,
      title: "Cookie missing HttpOnly flag",
      severity: "medium",
      category: "cookies",
      code_snippet: "NEXT_LOCALE=en",
    });

    const result = postProcessFindings([localeCookieFinding], ["next-intl"]);
    expect(result[0].is_framework_requirement).toBe(true);
    expect(result[0].framework_note).toContain("next-intl");
  });

  it("handles an empty technologies list without errors", () => {
    const findings: FindingData[] = [
      makeFinding({ vulnerability_id: 63, title: "unsafe-inline in CSP" }),
    ];
    const result = postProcessFindings(findings, []);
    expect(result[0].is_framework_requirement).toBeUndefined();
  });

  it("handles an empty findings list without errors", () => {
    const result = postProcessFindings([], ["nextjs"]);
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Step 2: Cross-Engine Deduplication
// ---------------------------------------------------------------------------

describe("postProcessFindings — cross-engine dedup", () => {
  it("merges same vulnerability_id when one finding has no file_path", () => {
    const withPath = makeFinding({
      vulnerability_id: 4,
      title: "X-Powered-By Header Not Disabled",
      category: "config",
      severity: "low",
      file_path: "next.config.ts",
    });
    const withoutPath = makeFinding({
      vulnerability_id: 4,
      title: "X-Powered-By Header Disclosed",
      category: "headers",
      severity: "low",
    });

    const result = postProcessFindings([withPath, withoutPath], []);
    // Should keep only the one with a file_path.
    expect(result.filter((f) => f.vulnerability_id === 4)).toHaveLength(1);
    expect(result.find((f) => f.vulnerability_id === 4)?.file_path).toBe("next.config.ts");
  });

  it("keeps both findings when both have different file_paths (different root cause)", () => {
    const finding1 = makeFinding({
      vulnerability_id: 10,
      title: "SQL Injection risk",
      file_path: "src/lib/db.ts",
    });
    const finding2 = makeFinding({
      vulnerability_id: 10,
      title: "SQL Injection risk",
      file_path: "src/api/route.ts",
    });

    const result = postProcessFindings([finding1, finding2], []);
    expect(result.filter((f) => f.vulnerability_id === 10)).toHaveLength(2);
  });

  it("keeps both no-path findings when vulnerability_ids differ", () => {
    const f1 = makeFinding({ vulnerability_id: 1, title: "Finding A" });
    const f2 = makeFinding({ vulnerability_id: 2, title: "Finding B" });

    const result = postProcessFindings([f1, f2], []);
    expect(result).toHaveLength(2);
  });

  it("keeps the no-path finding when there is no with-path counterpart", () => {
    const urlFinding = makeFinding({
      vulnerability_id: 50,
      title: "Missing HSTS header",
      category: "headers",
      severity: "high",
      // no file_path — URL scanner finding
    });

    const result = postProcessFindings([urlFinding], []);
    expect(result).toHaveLength(1);
    expect(result[0].vulnerability_id).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// Step 3: Contextual Notes
// ---------------------------------------------------------------------------

describe("postProcessFindings — contextual notes", () => {
  it("adds description_simple for framework requirement findings", () => {
    const finding = makeFinding({
      vulnerability_id: 63,
      title: "unsafe-inline in CSP",
      category: "headers",
      severity: "high",
    });

    const result = postProcessFindings([finding], ["nextjs"]);
    expect(result[0].description_simple).toBeTruthy();
    expect(result[0].description_simple).toContain("Next.js App Router");
  });

  it("adds description_simple for headers/info findings", () => {
    const finding = makeFinding({
      vulnerability_id: 200,
      title: "Optional header not set",
      category: "headers",
      severity: "info",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].description_simple).toBe(
      "This is informational — no action required.",
    );
  });

  it("adds description_simple for low-severity low-confidence findings", () => {
    const finding = makeFinding({
      vulnerability_id: 201,
      title: "Possible weak pattern",
      severity: "low",
      confidence: "low",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].description_simple).toContain("low-confidence observation");
  });

  it("does NOT overwrite an existing description_simple", () => {
    const finding = makeFinding({
      vulnerability_id: 202,
      title: "Optional header",
      category: "headers",
      severity: "info",
      description_simple: "Already set by the engine.",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].description_simple).toBe("Already set by the engine.");
  });

  it("does NOT add a note to medium severity non-framework production findings", () => {
    const finding = makeFinding({
      vulnerability_id: 203,
      title: "Eval usage detected",
      category: "patterns",
      severity: "medium",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].description_simple).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Step 4: Classification
// ---------------------------------------------------------------------------

describe("postProcessFindings — classification", () => {
  it("classifies framework requirements as informational", () => {
    const finding = makeFinding({
      vulnerability_id: 63,
      title: "unsafe-inline in CSP",
      severity: "high",
    });

    const result = postProcessFindings([finding], ["nextjs"]);
    expect(result[0].classification).toBe("informational");
  });

  it("classifies info-severity findings as informational", () => {
    const finding = makeFinding({
      vulnerability_id: 99,
      title: "robots.txt present",
      severity: "info",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].classification).toBe("informational");
  });

  it("classifies medium severity findings as actionable", () => {
    const finding = makeFinding({
      vulnerability_id: 10,
      title: "Missing rate limiting",
      severity: "medium",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].classification).toBe("actionable");
  });

  it("classifies high severity findings as actionable", () => {
    const finding = makeFinding({
      vulnerability_id: 20,
      title: "SQL Injection",
      severity: "high",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].classification).toBe("actionable");
  });

  it("classifies critical severity findings as actionable", () => {
    const finding = makeFinding({
      vulnerability_id: 1,
      title: "Hardcoded secret",
      severity: "critical",
    });

    const result = postProcessFindings([finding], []);
    expect(result[0].classification).toBe("actionable");
  });
});

// ---------------------------------------------------------------------------
// Full pipeline integration test
// ---------------------------------------------------------------------------

describe("postProcessFindings — full pipeline integration", () => {
  it("processes a realistic mixed set of findings end-to-end", () => {
    const findings: FindingData[] = [
      // Should be a framework requirement + informational
      makeFinding({
        vulnerability_id: 63,
        title: "Content Security Policy allows 'unsafe-inline' in script-src",
        severity: "high",
        category: "headers",
      }),
      // Config engine (has file_path) — should survive cross-engine dedup
      makeFinding({
        vulnerability_id: 4,
        title: "X-Powered-By Header Not Disabled",
        severity: "low",
        category: "config",
        file_path: "next.config.ts",
      }),
      // URL scanner (no file_path, same vuln_id) — should be removed by cross-engine dedup
      makeFinding({
        vulnerability_id: 4,
        title: "X-Powered-By Header Disclosed",
        severity: "low",
        category: "headers",
      }),
      // Real actionable finding
      makeFinding({
        vulnerability_id: 30,
        title: "Hardcoded API key",
        severity: "critical",
        category: "secrets",
        file_path: "src/lib/client.ts",
      }),
      // Info finding with no path — should get contextual note
      makeFinding({
        vulnerability_id: 200,
        title: "Optional security header not set",
        severity: "info",
        category: "headers",
      }),
    ];

    const result = postProcessFindings(findings, ["nextjs", "supabase"]);

    // unsafe-inline is a framework requirement
    const cspFinding = result.find((f) => f.vulnerability_id === 63);
    expect(cspFinding?.is_framework_requirement).toBe(true);
    expect(cspFinding?.classification).toBe("informational");

    // X-Powered-By: only the one with file_path should survive
    const xpbFindings = result.filter((f) => f.vulnerability_id === 4);
    expect(xpbFindings).toHaveLength(1);
    expect(xpbFindings[0].file_path).toBe("next.config.ts");

    // Hardcoded API key is actionable
    const secretFinding = result.find((f) => f.vulnerability_id === 30);
    expect(secretFinding?.classification).toBe("actionable");

    // Info header finding gets a contextual note
    const infoFinding = result.find((f) => f.vulnerability_id === 200);
    expect(infoFinding?.description_simple).toBe(
      "This is informational — no action required.",
    );
    expect(infoFinding?.classification).toBe("informational");

    // Total findings: 63, 4(kept), 30, 200 = 4 (not 5, because dedup removed the URL scanner vuln 4)
    expect(result).toHaveLength(4);
  });
});
