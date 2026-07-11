import { describe, it, expect, vi, beforeEach } from "vitest";
import type { FindingData } from "../../engines/types.js";

// Mock all four engines before importing the agent so the mocks are in place.
vi.mock("../../engines/patterns.js", () => ({
  analyzePatterns: vi.fn(() => [] as FindingData[]),
}));
vi.mock("../../engines/secrets.js", () => ({
  runSecretsEngine: vi.fn(() => [] as FindingData[]),
}));
vi.mock("../../engines/dependencies.js", () => ({
  analyzeDependencies: vi.fn(() => [] as FindingData[]),
}));
vi.mock("../../engines/config.js", () => ({
  analyzeConfig: vi.fn(() => [] as FindingData[]),
}));

// Import engine mocks AFTER vi.mock declarations so we can configure return values.
import { analyzePatterns } from "../../engines/patterns.js";
import { runSecretsEngine } from "../../engines/secrets.js";
import { analyzeDependencies } from "../../engines/dependencies.js";
import { analyzeConfig } from "../../engines/config.js";
import { JavaScriptScanAgent } from "./javascript-agent.js";

// Typed references to the mocked functions.
const mockAnalyzePatterns = vi.mocked(analyzePatterns);
const mockRunSecretsEngine = vi.mocked(runSecretsEngine);
const mockAnalyzeDependencies = vi.mocked(analyzeDependencies);
const mockAnalyzeConfig = vi.mocked(analyzeConfig);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

function makeFinding(overrides: Partial<FindingData> = {}): FindingData {
  return {
    vulnerability_id: 1,
    severity: "high",
    category: "web-owasp",
    title: "Test Finding",
    status: "open",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const agent = new JavaScriptScanAgent();

beforeEach(() => {
  // Reset all mocks to return empty arrays before each test.
  mockAnalyzePatterns.mockReturnValue([]);
  mockRunSecretsEngine.mockReturnValue([]);
  mockAnalyzeDependencies.mockReturnValue([]);
  mockAnalyzeConfig.mockReturnValue([]);
});

describe("JavaScriptScanAgent", () => {
  // -------------------------------------------------------------------------
  // detect()
  // -------------------------------------------------------------------------

  describe("detect()", () => {
    it("returns true when package.json is present", async () => {
      const files = makeFiles({ "package.json": '{"name":"my-app"}' });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns false when package.json is absent", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0",
        "main.py": "print('hello')",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for an empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // scan() — engine delegation
  // -------------------------------------------------------------------------

  describe("scan() — engine delegation", () => {
    it("wraps analyzePatterns results correctly", async () => {
      const finding = makeFinding({
        title: "eval() with Dynamic Input",
        severity: "critical",
        file_path: "src/utils.ts",
        line_number: 42,
        description_technical: "Dynamic eval detected",
        fix_description: "Avoid eval()",
        owasp_ref: "A03:2021",
      });
      mockAnalyzePatterns.mockReturnValue([finding]);

      const files = makeFiles({ "package.json": "{}" });
      const results = await agent.scan(files);

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe("eval() with Dynamic Input");
      expect(results[0].severity).toBe("CRITICAL");
      expect(results[0].file).toBe("src/utils.ts");
      expect(results[0].line).toBe(42);
      expect(results[0].description).toBe("Dynamic eval detected");
      expect(results[0].fix).toBe("Avoid eval()");
      expect(results[0].cwe).toBe("A03:2021");
    });

    it("wraps runSecretsEngine results correctly", async () => {
      const finding = makeFinding({
        title: "OpenAI API Key Hardcoded",
        severity: "critical",
        file_path: "src/lib/ai.ts",
        line_number: 5,
        description_simple: "Hardcoded secret found",
        fix_description: "Move to environment variable",
        owasp_ref: "A07:2021",
      });
      mockRunSecretsEngine.mockReturnValue([finding]);

      const files = makeFiles({ "package.json": "{}" });
      const results = await agent.scan(files);

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe("OpenAI API Key Hardcoded");
      expect(results[0].severity).toBe("CRITICAL");
      expect(results[0].file).toBe("src/lib/ai.ts");
      expect(results[0].line).toBe(5);
    });

    it("wraps analyzeDependencies results correctly", async () => {
      const finding = makeFinding({
        title: "Vulnerable dependency: lodash",
        severity: "high",
        file_path: "package.json",
        line_number: 12,
        description_technical: "Prototype pollution in lodash < 4.17.21",
        fix_description: "Upgrade to lodash >= 4.17.21",
      });
      mockAnalyzeDependencies.mockReturnValue([finding]);

      const files = makeFiles({ "package.json": "{}" });
      const results = await agent.scan(files);

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe("Vulnerable dependency: lodash");
      expect(results[0].severity).toBe("HIGH");
      expect(results[0].file).toBe("package.json");
    });

    it("wraps analyzeConfig results correctly", async () => {
      const finding = makeFinding({
        title: "Container Running as Root",
        severity: "medium",
        file_path: "Dockerfile",
        line_number: 1,
        description_technical: "No USER instruction in Dockerfile",
        fix_description: "Add USER nonroot instruction",
        owasp_ref: "A05:2021",
      });
      mockAnalyzeConfig.mockReturnValue([finding]);

      const files = makeFiles({ "package.json": "{}" });
      const results = await agent.scan(files);

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe("Container Running as Root");
      expect(results[0].severity).toBe("MEDIUM");
    });

    it("combines findings from all four engines", async () => {
      mockAnalyzePatterns.mockReturnValue([makeFinding({ title: "Pattern" })]);
      mockRunSecretsEngine.mockReturnValue([makeFinding({ title: "Secret" })]);
      mockAnalyzeDependencies.mockReturnValue([makeFinding({ title: "Dep" })]);
      mockAnalyzeConfig.mockReturnValue([makeFinding({ title: "Config" })]);

      const files = makeFiles({ "package.json": "{}" });
      const results = await agent.scan(files);

      expect(results).toHaveLength(4);
      const titles = results.map((r) => r.title);
      expect(titles).toContain("Pattern");
      expect(titles).toContain("Secret");
      expect(titles).toContain("Dep");
      expect(titles).toContain("Config");
    });
  });

  // -------------------------------------------------------------------------
  // scan() — severity mapping
  // -------------------------------------------------------------------------

  describe("scan() — severity mapping", () => {
    const severityCases: Array<[FindingData["severity"], string]> = [
      ["critical", "CRITICAL"],
      ["high", "HIGH"],
      ["medium", "MEDIUM"],
      ["low", "LOW"],
      ["info", "INFO"],
    ];

    for (const [input, expected] of severityCases) {
      it(`maps "${input}" → "${expected}"`, async () => {
        mockAnalyzePatterns.mockReturnValue([makeFinding({ severity: input })]);

        const files = makeFiles({ "package.json": "{}" });
        const results = await agent.scan(files);

        expect(results[0].severity).toBe(expected);
      });
    }
  });

  // -------------------------------------------------------------------------
  // scan() — field defaults
  // -------------------------------------------------------------------------

  describe("scan() — field defaults", () => {
    it("defaults file to empty string when file_path is undefined", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({ file_path: undefined }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].file).toBe("");
    });

    it("defaults line to 1 when line_number is undefined", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({ line_number: undefined }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].line).toBe(1);
    });

    it("uses description_technical over description_simple", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          description_technical: "Technical details",
          description_simple: "Simple explanation",
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].description).toBe("Technical details");
    });

    it("falls back to description_simple when technical is absent", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          description_technical: undefined,
          description_simple: "Simple explanation",
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].description).toBe("Simple explanation");
    });

    it("falls back to title when both descriptions are absent", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          title: "The Title",
          description_technical: undefined,
          description_simple: undefined,
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].description).toBe("The Title");
    });

    it("uses fix_description over fix_code", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          fix_description: "Do this instead",
          fix_code: "const safe = ...",
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].fix).toBe("Do this instead");
    });

    it("falls back to fix_code when fix_description is absent", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          fix_description: undefined,
          fix_code: "const safe = ...",
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].fix).toBe("const safe = ...");
    });

    it("falls back to generic fix message when both fix fields are absent", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({ fix_description: undefined, fix_code: undefined }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].fix).toBe("Review and fix this issue");
    });

    it("omits cwe when owasp_ref is undefined", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({ owasp_ref: undefined }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].cwe).toBeUndefined();
    });

    it("maps owasp_ref to cwe when present", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({ owasp_ref: "A03:2021" }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results[0].cwe).toBe("A03:2021");
    });
  });

  // -------------------------------------------------------------------------
  // scan() — result structure
  // -------------------------------------------------------------------------

  describe("scan() — result structure", () => {
    it("every result has all required ScanResult fields with correct types", async () => {
      mockAnalyzePatterns.mockReturnValue([
        makeFinding({
          title: "Some Issue",
          severity: "high",
          file_path: "src/app.ts",
          line_number: 10,
          description_technical: "A technical description",
          fix_description: "Fix it like this",
          owasp_ref: "A01:2021",
        }),
      ]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));
      expect(results).toHaveLength(1);

      const r = results[0];
      expect(typeof r.title).toBe("string");
      expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(
        r.severity,
      );
      expect(typeof r.file).toBe("string");
      expect(typeof r.line).toBe("number");
      expect(r.line).toBeGreaterThan(0);
      expect(typeof r.description).toBe("string");
      expect(typeof r.fix).toBe("string");
    });

    it("returns zero findings for a clean project", async () => {
      // All mocks already return [] from beforeEach — no overrides needed.
      const files = makeFiles({
        "package.json": '{"name":"clean-app","dependencies":{}}',
        "src/index.ts": "export default function main() { return 42; }",
      });
      const results = await agent.scan(files);
      expect(results).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // getMetadata()
  // -------------------------------------------------------------------------

  describe("getMetadata()", () => {
    it("returns the correct agent name and version", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("javascript-agent");
      expect(meta.version).toBe("1.0.0");
    });

    it("returns the correct technologies list", () => {
      const meta = agent.getMetadata();
      expect(meta.technologies).toEqual([
        "nodejs",
        "nextjs",
        "react",
        "express",
        "fastify",
        "hono",
        "koa",
        "nestjs",
        "vue",
        "angular",
        "svelte",
      ]);
    });
  });

  // -------------------------------------------------------------------------
  // getChecks()
  // -------------------------------------------------------------------------

  describe("getChecks()", () => {
    const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

    it("returns non-empty array of check definitions", () => {
      expect(agent.getChecks().length).toBeGreaterThan(0);
    });

    it("every check has required fields", () => {
      for (const check of agent.getChecks()) {
        expect(check.id).toBeTruthy();
        expect(check.name).toBeTruthy();
        expect(VALID_SEVERITIES.has(check.severity)).toBe(true);
      }
    });

    it("check IDs are unique", () => {
      const ids = agent.getChecks().map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("check IDs follow js: prefix convention", () => {
      for (const check of agent.getChecks()) {
        expect(check.id).toMatch(/^js:/);
      }
    });

    it("scan findings have checkIds matching declared checks", async () => {
      const declaredIds = new Set(agent.getChecks().map((c) => c.id));

      // Configure each mocked engine to return one finding so every checkId
      // path through scan() is exercised.
      mockAnalyzePatterns.mockReturnValue([makeFinding({ title: "Pattern finding" })]);
      mockRunSecretsEngine.mockReturnValue([makeFinding({ title: "Secret finding" })]);
      mockAnalyzeDependencies.mockReturnValue([makeFinding({ title: "Dep finding" })]);
      mockAnalyzeConfig.mockReturnValue([makeFinding({ title: "Config finding" })]);

      const results = await agent.scan(makeFiles({ "package.json": "{}" }));

      // Every result must have a checkId that is one of the declared checks.
      for (const result of results) {
        expect(result.checkId).toBeDefined();
        expect(declaredIds.has(result.checkId!)).toBe(true);
      }
    });
  });
});
