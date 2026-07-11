// Tests for the Semgrep engine.
// We mock execWithTimeout so no real Semgrep binary is needed and control
// stdout to exercise all JSON-parsing and finding-mapping branches.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---- module mocks (registered before any import) ----------------------

vi.mock("../utils/exec.js", () => ({
  execWithTimeout: vi.fn(),
}));

// -----------------------------------------------------------------------

import { runSemgrep } from "./semgrep.js";
import { execWithTimeout } from "../utils/exec.js";

const mockExec = vi.mocked(execWithTimeout);

const REPO_DIR = "/home/runner/work/my-app";

// ---- fixture factories ------------------------------------------------

interface SemgrepResultOptions {
  check_id?: string;
  path?: string;
  startLine?: number;
  message?: string;
  severity?: string;
  lines?: string;
  metadata?: Record<string, unknown>;
}

function makeSemgrepResult(overrides: SemgrepResultOptions = {}) {
  return {
    check_id:
      overrides.check_id ??
      "javascript.lang.security.audit.eval.eval-detected",
    path: overrides.path ?? `${REPO_DIR}/src/utils.ts`,
    start: { line: overrides.startLine ?? 10, col: 1, offset: 0 },
    end: { line: overrides.startLine ?? 10, col: 50, offset: 50 },
    extra: {
      message: overrides.message ?? "Detected eval() with dynamic input",
      severity: overrides.severity ?? "ERROR",
      lines: overrides.lines ?? "eval(userInput)",
      metadata: overrides.metadata,
    },
  };
}

function makeSemgrepOutput(
  results: ReturnType<typeof makeSemgrepResult>[]
) {
  return JSON.stringify({
    results,
    errors: [],
    version: "1.50.0",
  });
}

function setupRun(stdout: string, exitCode = 0) {
  mockExec.mockResolvedValue({ stdout, stderr: "", exitCode });
}

// -----------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

// -----------------------------------------------------------------------

describe("runSemgrep", () => {
  describe("when Semgrep finds no results", () => {
    it("returns empty array for empty stdout", async () => {
      setupRun("   ");

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when results array is empty", async () => {
      setupRun(makeSemgrepOutput([]));

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(0);
    });
  });

  describe("JSON parsing", () => {
    it("parses valid Semgrep JSON and returns one finding per result", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult(),
          makeSemgrepResult({ check_id: "react.dangerouslySetInnerHTML" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(2);
    });

    it("returns empty array for completely invalid JSON", async () => {
      setupRun("{ not valid json }}}");

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when JSON has no results key", async () => {
      setupRun(JSON.stringify({ errors: [], version: "1.50.0" }));

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when results is not an array", async () => {
      setupRun(JSON.stringify({ results: null, errors: [] }));

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("extracts JSON when stdout has non-JSON preamble text before the brace", async () => {
      // Semgrep sometimes emits preamble lines before the JSON block
      const json = makeSemgrepOutput([makeSemgrepResult()]);
      setupRun(`Some preamble text\n${json}`);

      const findings = await runSemgrep(REPO_DIR);

      expect(findings).toHaveLength(1);
    });
  });

  describe("custom rule mapping via datahogo_id metadata", () => {
    it("uses datahogo_id from metadata as vulnerability_id", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            metadata: { datahogo_id: 42, datahogo_category: "injection" },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(42);
    });

    it("uses datahogo_category from metadata as category", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            metadata: { datahogo_id: 75, datahogo_category: "injection" },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].category).toBe("injection");
    });

    it("falls back to web-owasp category when datahogo_category is absent", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            metadata: { datahogo_id: 10 },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].category).toBe("web-owasp");
    });

    it("includes owasp_ref from metadata when present", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            metadata: { datahogo_id: 5, owasp_ref: "A03:2021" },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].owasp_ref).toBe("A03:2021");
    });

    it("uses the first sentence of message as title for custom rules", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            message: "SQL injection detected. Sanitize inputs.",
            metadata: { datahogo_id: 5 },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].title).toBe("SQL injection detected");
    });
  });

  describe("community rule mapping via check_id prefix", () => {
    it("maps owasp. prefix to vulnerability_id 1", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "owasp.injection.command" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(1);
    });

    it("maps javascript.lang.security.audit.sqli prefix to vulnerability_id 5", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            check_id: "javascript.lang.security.audit.sqli.raw-query",
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(5);
    });

    it("maps javascript.lang.security.audit.xss prefix to vulnerability_id 7", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            check_id: "javascript.lang.security.audit.xss.reflected-xss",
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(7);
    });

    it("maps react. prefix to vulnerability_id 46 and react-nextjs category", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "react.dangerouslySetInnerHTML" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(46);
      expect(findings[0].category).toBe("react-nextjs");
    });

    it("maps nextjs. prefix to vulnerability_id 46 and react-nextjs category", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "nextjs.security.ssrf" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(46);
      expect(findings[0].category).toBe("react-nextjs");
    });

    it("maps javascript.jsonwebtoken prefix to vulnerability_id 56", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "javascript.jsonwebtoken.weak-alg" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(56);
    });

    it("maps javascript.lang.security.audit.eval prefix to vulnerability_id 61", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            check_id: "javascript.lang.security.audit.eval.eval-detected",
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(61);
    });
  });

  describe("keyword-based fallback mapping", () => {
    it("maps check_id containing 'sqli' to vulnerability_id 5", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.sqli-detection" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(5);
    });

    it("maps check_id containing 'xss' to vulnerability_id 7", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.xss-check" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(7);
    });

    it("maps check_id containing 'ssrf' to vulnerability_id 10", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.ssrf-detection" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(10);
    });

    it("maps check_id containing 'command' to vulnerability_id 75", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.command-injection" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(75);
    });

    it("maps check_id containing 'path-traversal' to vulnerability_id 106", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.path-traversal-check" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(106);
    });

    it("maps check_id containing 'cors' to vulnerability_id 4", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.cors-wildcard" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(4);
    });

    it("maps check_id containing 'secret' to vulnerability_id 53", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.hardcoded-secret" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(53);
    });

    it("maps check_id containing 'jwt' to vulnerability_id 56", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.jwt-none-alg" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(56);
    });

    it("maps check_id containing 'auth' to vulnerability_id 1", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.missing-auth" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(1);
    });

    it("maps check_id containing 'crypto' to vulnerability_id 2", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "custom.weak-crypto" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(2);
    });

    it("falls back to generic vulnerability_id 199 for unknown check_ids", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ check_id: "totally.unknown.rule.foo.bar" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(199);
      expect(findings[0].category).toBe("best-practices");
    });
  });

  describe("severity mapping", () => {
    it("maps ERROR to high severity", async () => {
      setupRun(makeSemgrepOutput([makeSemgrepResult({ severity: "ERROR" })]));

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].severity).toBe("high");
    });

    it("maps WARNING to medium severity", async () => {
      setupRun(
        makeSemgrepOutput([makeSemgrepResult({ severity: "WARNING" })])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].severity).toBe("medium");
    });

    it("maps INFO to low severity", async () => {
      setupRun(makeSemgrepOutput([makeSemgrepResult({ severity: "INFO" })]));

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].severity).toBe("low");
    });

    it("falls back to medium for unknown severity strings", async () => {
      setupRun(
        makeSemgrepOutput([makeSemgrepResult({ severity: "UNKNOWN_LEVEL" })])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].severity).toBe("medium");
    });

    it("custom-rule findings also derive severity from Semgrep severity field", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            severity: "INFO",
            metadata: { datahogo_id: 99 },
          }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].severity).toBe("low");
    });
  });

  describe("file path relativisation", () => {
    it("strips repoDir prefix from absolute paths", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ path: `${REPO_DIR}/src/api/route.ts` }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].file_path).toBe("src/api/route.ts");
    });

    it("leaves paths unchanged when they do not start with repoDir", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ path: "relative/path/file.ts" }),
        ])
      );

      const findings = await runSemgrep(REPO_DIR);

      expect(findings[0].file_path).toBe("relative/path/file.ts");
    });
  });

  describe("finding structure", () => {
    it("includes all required FindingData fields", async () => {
      setupRun(makeSemgrepOutput([makeSemgrepResult()]));

      const [finding] = await runSemgrep(REPO_DIR);

      expect(finding).toHaveProperty("vulnerability_id");
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("category");
      expect(finding).toHaveProperty("title");
      expect(finding).toHaveProperty("description_technical");
      expect(finding).toHaveProperty("file_path");
      expect(finding).toHaveProperty("line_number");
      expect(finding).toHaveProperty("code_snippet");
      expect(finding.status).toBe("open");
    });

    it("records the correct start line number", async () => {
      setupRun(makeSemgrepOutput([makeSemgrepResult({ startLine: 77 })]));

      const [finding] = await runSemgrep(REPO_DIR);

      expect(finding.line_number).toBe(77);
    });

    it("stores the matched source lines as code_snippet", async () => {
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({ lines: "eval(dangerousUserInput);" }),
        ])
      );

      const [finding] = await runSemgrep(REPO_DIR);

      expect(finding.code_snippet).toBe("eval(dangerousUserInput);");
    });

    it("prefixes description_technical with [Semgrep: check_id] for community rules", async () => {
      const checkId = "react.dangerouslySetInnerHTML";
      setupRun(
        makeSemgrepOutput([
          makeSemgrepResult({
            check_id: checkId,
            message: "Avoid dangerouslySetInnerHTML",
          }),
        ])
      );

      const [finding] = await runSemgrep(REPO_DIR);

      expect(finding.description_technical).toContain(`[Semgrep: ${checkId}]`);
    });
  });
});
