import { describe, it, expect, vi } from "vitest";
import { runScan } from "./orchestrator";
import type { ScanParams } from "./orchestrator";

// Mock the URL scanner since it makes HTTP requests
vi.mock("./engines/url-scanner", () => ({
  scanUrl: vi.fn().mockResolvedValue([
    {
      vulnerability_id: 63,
      severity: "medium",
      category: "headers",
      title: "Missing Content Security Policy",
      status: "open",
    },
  ]),
}));

// Mock the secrets engine since it may have complex internals
vi.mock("./engines/secrets", () => ({
  runSecretsEngine: vi.fn().mockReturnValue([]),
}));

function makeParams(overrides: Partial<ScanParams> = {}): ScanParams {
  return {
    files: new Map(),
    ...overrides,
  };
}

describe("runScan", () => {
  describe("return structure", () => {
    it("returns all required fields", async () => {
      const result = await runScan(makeParams());
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("engineResults");
      expect(result).toHaveProperty("score");
      expect(result).toHaveProperty("summary");
      expect(result).toHaveProperty("failedEngines");
      expect(result).toHaveProperty("durationMs");
    });

    it("summary has correct shape", async () => {
      const result = await runScan(makeParams());
      expect(result.summary).toHaveProperty("total");
      expect(result.summary).toHaveProperty("critical");
      expect(result.summary).toHaveProperty("high");
      expect(result.summary).toHaveProperty("medium");
      expect(result.summary).toHaveProperty("low");
      expect(result.summary).toHaveProperty("info");
    });

    it("findings is an array", async () => {
      const result = await runScan(makeParams());
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it("engineResults is an array", async () => {
      const result = await runScan(makeParams());
      expect(Array.isArray(result.engineResults)).toBe(true);
    });

    it("durationMs is a positive number", async () => {
      const result = await runScan(makeParams());
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("score calculation", () => {
    it("returns 100 for no findings", async () => {
      const result = await runScan(makeParams());
      expect(result.score).toBe(100);
    });

    it("deducts points for critical findings (adjusted by confidence)", async () => {
      const files = new Map<string, string>();
      // Use eval() to trigger a critical finding from patterns engine
      files.set("src/bad.ts", "const x = eval(userInput);");
      const result = await runScan(makeParams({ files }));
      const criticalFindings = result.findings.filter(
        (f) => f.severity === "critical"
      );
      // Score penalty = 15 * confidence_multiplier per critical finding
      // Medium confidence = 0.7, so penalty = 10.5 per finding
      if (criticalFindings.length > 0) {
        expect(result.score).toBeLessThan(100);
      }
    });

    it("deducts points for high findings (adjusted by confidence)", async () => {
      const files = new Map<string, string>();
      files.set("src/hash.ts", 'crypto.createHash("md5").update(data).digest("hex");');
      const result = await runScan(makeParams({ files }));
      const highFindings = result.findings.filter((f) => f.severity === "high");
      // Score penalty = 10 * confidence_multiplier per high finding
      if (highFindings.length > 0) {
        expect(result.score).toBeLessThan(100);
      }
    });

    it("score never goes below 0", async () => {
      const files = new Map<string, string>();
      // Add many vulnerabilities to try to push score below 0
      for (let i = 0; i < 20; i++) {
        files.set(
          `src/bad${i}.ts`,
          `const result${i} = eval(userInput${i});`
        );
      }
      const result = await runScan(makeParams({ files }));
      expect(result.score).toBeGreaterThanOrEqual(0);
    });
  });

  describe("summary counts", () => {
    it("total matches number of findings", async () => {
      const files = new Map<string, string>();
      files.set("src/bad.ts", "const x = eval(userInput);");
      files.set("src/hash.ts", 'crypto.createHash("md5").update(data).digest("hex");');
      const result = await runScan(makeParams({ files }));
      expect(result.summary.total).toBe(result.findings.length);
    });

    it("severity counts add up to total", async () => {
      const files = new Map<string, string>();
      files.set("src/bad.ts", "const x = eval(userInput);");
      const result = await runScan(makeParams({ files }));
      const sumOfSeverities =
        result.summary.critical +
        result.summary.high +
        result.summary.medium +
        result.summary.low +
        result.summary.info;
      expect(sumOfSeverities).toBe(result.summary.total);
    });

    it("summary is all zeros for empty files", async () => {
      const result = await runScan(makeParams());
      expect(result.summary.total).toBe(0);
      expect(result.summary.critical).toBe(0);
      expect(result.summary.high).toBe(0);
      expect(result.summary.medium).toBe(0);
      expect(result.summary.low).toBe(0);
      expect(result.summary.info).toBe(0);
    });
  });

  describe("empty file map", () => {
    it("handles empty file map without errors", async () => {
      const result = await runScan(makeParams({ files: new Map() }));
      expect(result.findings).toHaveLength(0);
      expect(result.score).toBe(100);
    });
  });

  describe("engine execution", () => {
    it("always runs secrets, patterns, dependencies, and config engines", async () => {
      const result = await runScan(makeParams());
      const engineNames = result.engineResults.map((r) => r.engine);
      expect(engineNames).toContain("secrets");
      expect(engineNames).toContain("patterns");
      expect(engineNames).toContain("dependencies");
      expect(engineNames).toContain("config");
    });

    it("runs url-scanner when appUrl is provided", async () => {
      const result = await runScan(
        makeParams({ appUrl: "https://example.com" })
      );
      const engineNames = result.engineResults.map((r) => r.engine);
      expect(engineNames).toContain("url-scanner");
    });

    it("does not run url-scanner when appUrl is not provided", async () => {
      const result = await runScan(makeParams());
      const engineNames = result.engineResults.map((r) => r.engine);
      expect(engineNames).not.toContain("url-scanner");
    });

    it("runs db-rules when dbRulesInput is provided", async () => {
      const dbRules = `
CREATE TABLE users (id uuid PRIMARY KEY);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_select" ON users USING (auth.uid() = id);
`;
      const result = await runScan(makeParams({ dbRulesInput: dbRules }));
      const engineNames = result.engineResults.map((r) => r.engine);
      expect(engineNames).toContain("db-rules");
    });

    it("does not run db-rules when dbRulesInput is not provided", async () => {
      const result = await runScan(makeParams());
      const engineNames = result.engineResults.map((r) => r.engine);
      expect(engineNames).not.toContain("db-rules");
    });

    it("includes url-scanner findings when appUrl provided", async () => {
      const result = await runScan(
        makeParams({ appUrl: "https://example.com" })
      );
      // Our mocked scanUrl returns 1 finding
      const urlFindings = result.findings.filter(
        (f) => f.category === "headers"
      );
      expect(urlFindings.length).toBeGreaterThan(0);
    });

    it("includes db-rules findings when insecure rules provided", async () => {
      const dbRules = `CREATE TABLE users (id uuid PRIMARY KEY);`;
      const result = await runScan(makeParams({ dbRulesInput: dbRules }));
      const dbFindings = result.findings.filter(
        (f) => f.category === "supabase"
      );
      expect(dbFindings.length).toBeGreaterThan(0);
    });
  });

  describe("deduplication", () => {
    it("deduplicates findings with same vulnerability_id, file_path, and line_number", async () => {
      // Both patterns and config engine might produce findings for the same file
      // The deduplication uses vulnerability_id:file_path:line_number as key
      const files = new Map<string, string>();
      files.set("src/exec.ts", "const x = eval(userInput);");
      const result = await runScan(makeParams({ files }));

      // Check no duplicates exist
      const keys = result.findings.map(
        (f) => `${f.vulnerability_id}:${f.file_path ?? ""}:${f.line_number ?? 0}`
      );
      const uniqueKeys = new Set(keys);
      expect(keys.length).toBe(uniqueKeys.size);
    });
  });

  describe("failed engines tracking", () => {
    it("failedEngines is an array", async () => {
      const result = await runScan(makeParams());
      expect(Array.isArray(result.failedEngines)).toBe(true);
    });

    it("failedEngines is empty when all engines succeed", async () => {
      const result = await runScan(makeParams());
      expect(result.failedEngines).toHaveLength(0);
    });
  });

  describe("engine result structure", () => {
    it("each engine result has engine name, findings, and durationMs", async () => {
      const result = await runScan(makeParams());
      for (const engineResult of result.engineResults) {
        expect(engineResult).toHaveProperty("engine");
        expect(typeof engineResult.engine).toBe("string");
        expect(engineResult).toHaveProperty("findings");
        expect(Array.isArray(engineResult.findings)).toBe(true);
        expect(engineResult).toHaveProperty("durationMs");
        expect(typeof engineResult.durationMs).toBe("number");
      }
    });
  });

  // Regression guard: the multi-tech agent system must stay wired into
  // runScan. It once existed only as dead code that nothing invoked.
  describe("multi-tech agents integration", () => {
    it("runs the multi-tech agents engine as part of every scan", async () => {
      const result = await runScan(makeParams());
      const agentEngine = result.engineResults.find((e) => e.engine === "multi-tech-agents");
      expect(agentEngine).toBeDefined();
      expect(agentEngine?.error).toBeUndefined();
    });

    it("surfaces Python agent findings through runScan", async () => {
      const files = new Map([
        ["requirements.txt", "django==4.2"],
        ["myapp/settings.py", "DEBUG = True\n"],
      ]);
      const result = await runScan(makeParams({ files }));

      expect(result.scanLog?.agentsConfirmed).toContain("python-agent");
      const titles = result.findings.map((f) => f.title);
      expect(titles).toContain("Django DEBUG mode enabled");
    });

    it("excludes the javascript-agent adapter to avoid duplicated findings", async () => {
      const files = new Map([["package.json", '{"dependencies":{"express":"^4.17.0"}}']]);
      const result = await runScan(makeParams({ files }));
      expect(result.scanLog?.agentsConfirmed ?? []).not.toContain("javascript-agent");
    });

    it("maps agent findings to synthetic vulnerability ids outside the catalog range", async () => {
      const files = new Map([
        ["requirements.txt", "django==4.2"],
        ["myapp/settings.py", "DEBUG = True\n"],
      ]);
      const result = await runScan(makeParams({ files }));
      const agentFinding = result.findings.find((f) => f.title === "Django DEBUG mode enabled");
      expect(agentFinding).toBeDefined();
      expect(agentFinding!.vulnerability_id).toBeGreaterThanOrEqual(100000);
      expect(agentFinding!.severity).toBe("high");
    });
  });
});
