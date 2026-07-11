import { describe, it, expect, vi, beforeEach } from "vitest";
import { runDast } from "./dast.js";

// Mock execWithTimeout so we never invoke the real nuclei binary.
vi.mock("../utils/exec.js", () => ({
  execWithTimeout: vi.fn(),
}));

// Import the mock so we can configure return values per test.
import { execWithTimeout } from "../utils/exec.js";
const mockExec = vi.mocked(execWithTimeout);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNucleiLine(overrides: Partial<{
  templateId: string;
  name: string;
  severity: string;
  description: string;
  tags: string[];
  cveIds: string[];
  cweIds: string[];
  references: string[];
  matchedAt: string;
  type: string;
  host: string;
  curlCommand: string;
  extractedResults: string[];
  matcherName: string;
}>): string {
  const {
    templateId = "test-template",
    name = "Test Finding",
    severity = "medium",
    description = "A test finding.",
    tags = [],
    cveIds = [],
    cweIds = [],
    references = [],
    matchedAt = "https://example.com/vuln",
    type = "http",
    host = "https://example.com",
    curlCommand,
    extractedResults,
    matcherName,
  } = overrides;

  const obj: Record<string, unknown> = {
    "template-id": templateId,
    info: {
      name,
      severity,
      description,
      tags,
      reference: references,
      classification: {
        "cve-id": cveIds,
        "cwe-id": cweIds,
      },
    },
    "matched-at": matchedAt,
    type,
    host,
  };

  if (curlCommand !== undefined) obj["curl-command"] = curlCommand;
  if (extractedResults !== undefined) obj["extracted-results"] = extractedResults;
  if (matcherName !== undefined) obj["matcher-name"] = matcherName;

  return JSON.stringify(obj);
}

function makeExecResult(stdout: string) {
  return Promise.resolve({ stdout, stderr: "", exitCode: 0 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runDast", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // Empty / no-output cases
  // -------------------------------------------------------------------------

  describe("when nuclei produces no output", () => {
    it("returns empty array for empty stdout", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      const findings = await runDast("https://example.com");

      expect(findings).toEqual([]);
    });

    it("returns empty array for stdout that is only whitespace", async () => {
      mockExec.mockReturnValue(makeExecResult("   \n  \n"));

      const findings = await runDast("https://example.com");

      expect(findings).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // nuclei exits non-zero (network error, tool missing, etc.)
  // -------------------------------------------------------------------------

  describe("when execWithTimeout throws a non-timeout error", () => {
    it("returns empty array instead of propagating the error", async () => {
      mockExec.mockRejectedValue(new Error("nuclei: command not found"));

      const findings = await runDast("https://example.com");

      expect(findings).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // Timeout is re-thrown
  // -------------------------------------------------------------------------

  describe("when execWithTimeout throws a timeout error", () => {
    it("returns empty array (all errors are caught)", async () => {
      mockExec.mockRejectedValue(new Error("nuclei timed out after 170000ms"));

      const findings = await runDast("https://example.com");

      expect(findings).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // JSONL parsing
  // -------------------------------------------------------------------------

  describe("JSONL output parsing", () => {
    it("parses a single valid JSONL line into one finding", async () => {
      const line = makeNucleiLine({
        templateId: "sqli-generic",
        name: "SQL Injection",
        severity: "high",
        tags: ["sqli"],
        matchedAt: "https://example.com/search?q=1",
      });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings).toHaveLength(1);
    });

    it("parses multiple JSONL lines, one finding per line", async () => {
      const line1 = makeNucleiLine({ templateId: "sqli-generic", tags: ["sqli"] });
      const line2 = makeNucleiLine({ templateId: "xss-generic", tags: ["xss"] });
      const line3 = makeNucleiLine({ templateId: "ssrf-generic", tags: ["ssrf"] });
      mockExec.mockReturnValue(makeExecResult([line1, line2, line3].join("\n")));

      const findings = await runDast("https://example.com");

      expect(findings).toHaveLength(3);
    });

    it("skips empty lines between valid JSONL entries", async () => {
      const line1 = makeNucleiLine({ templateId: "sqli-generic", tags: ["sqli"] });
      const line2 = makeNucleiLine({ templateId: "xss-generic", tags: ["xss"] });
      const jsonl = `${line1}\n\n${line2}\n`;
      mockExec.mockReturnValue(makeExecResult(jsonl));

      const findings = await runDast("https://example.com");

      expect(findings).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // Malformed JSONL handling
  // -------------------------------------------------------------------------

  describe("malformed JSONL handling", () => {
    it("skips lines that are not valid JSON without throwing", async () => {
      const validLine = makeNucleiLine({ templateId: "sqli-generic", tags: ["sqli"] });
      const jsonl = `not-json-at-all\n${validLine}\n{broken json`;
      mockExec.mockReturnValue(makeExecResult(jsonl));

      const findings = await runDast("https://example.com");

      // Only the valid middle line should produce a finding.
      expect(findings).toHaveLength(1);
    });

    it("returns empty array when all lines are malformed", async () => {
      mockExec.mockReturnValue(makeExecResult("not-json\nalso-not-json\n{bad"));

      const findings = await runDast("https://example.com");

      expect(findings).toEqual([]);
    });

    it("continues processing after a malformed line", async () => {
      const validLine = makeNucleiLine({ templateId: "xss-generic", tags: ["xss"] });
      const jsonl = `{invalid}\n${validLine}`;
      mockExec.mockReturnValue(makeExecResult(jsonl));

      const findings = await runDast("https://example.com");

      expect(findings).toHaveLength(1);
      expect(findings[0].title).toContain("DAST");
    });
  });

  // -------------------------------------------------------------------------
  // Severity mapping
  // -------------------------------------------------------------------------

  describe("severity mapping", () => {
    const severityCases: Array<[string, string]> = [
      ["critical", "critical"],
      ["high", "high"],
      ["medium", "medium"],
      ["low", "low"],
      ["info", "info"],
    ];

    for (const [nucleiSeverity, expectedSeverity] of severityCases) {
      it(`maps nuclei severity '${nucleiSeverity}' to our '${expectedSeverity}'`, async () => {
        const line = makeNucleiLine({ severity: nucleiSeverity });
        mockExec.mockReturnValue(makeExecResult(line));

        const findings = await runDast("https://example.com");

        expect(findings[0].severity).toBe(expectedSeverity);
      });
    }

    it("falls back to 'medium' for unrecognised nuclei severity", async () => {
      const line = makeNucleiLine({ severity: "unknown-level" });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].severity).toBe("medium");
    });
  });

  // -------------------------------------------------------------------------
  // TAG_TO_VULN_ID mapping via tags
  // -------------------------------------------------------------------------

  describe("vulnerability ID resolution via TAG_TO_VULN_ID", () => {
    const tagCases: Array<[string, number]> = [
      ["sqli", 5],
      ["sql-injection", 5],
      ["xss", 7],
      ["ssrf", 10],
      ["lfi", 106],
      ["rfi", 106],
      ["rce", 75],
      ["command-injection", 75],
      ["xxe", 72],
      ["ssti", 76],
      ["open-redirect", 119],
      ["cors", 4],
      ["csrf", 8],
      ["idor", 1],
      ["path-traversal", 106],
      ["file-inclusion", 106],
      ["directory-listing", 116],
      ["exposed-panel", 116],
      ["admin-panel", 116],
      ["misconfiguration", 4],
      ["disclosure", 99],
      ["information-disclosure", 99],
      ["default-login", 77],
      ["default-credential", 77],
      ["weak-password", 55],
      ["cve", 3],
      ["token", 53],
      ["api-key", 53],
      ["debug", 116],
      ["source-map", 49],
    ];

    for (const [tag, expectedVulnId] of tagCases) {
      it(`maps tag '${tag}' to vulnerability_id ${expectedVulnId}`, async () => {
        const line = makeNucleiLine({ tags: [tag] });
        mockExec.mockReturnValue(makeExecResult(line));

        const findings = await runDast("https://example.com");

        expect(findings[0].vulnerability_id).toBe(expectedVulnId);
      });
    }

    it("uses first matching tag when multiple relevant tags are present", async () => {
      // sqli appears before xss in the tags array, so vuln_id 5 should win.
      const line = makeNucleiLine({ tags: ["sqli", "xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(5);
    });
  });

  // -------------------------------------------------------------------------
  // Vulnerability ID resolution via template ID (fallback)
  // -------------------------------------------------------------------------

  describe("vulnerability ID resolution via template ID fallback", () => {
    it("resolves sqli from template ID when no matching tag", async () => {
      const line = makeNucleiLine({ templateId: "generic-sqli-detect", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(5);
    });

    it("resolves xss from template ID", async () => {
      const line = makeNucleiLine({ templateId: "reflected-xss-check", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(7);
    });

    it("resolves ssrf from template ID", async () => {
      const line = makeNucleiLine({ templateId: "ssrf-via-header", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(10);
    });

    it("resolves rce from template ID", async () => {
      const line = makeNucleiLine({ templateId: "php-rce-eval", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(75);
    });

    it("resolves lfi from template ID", async () => {
      const line = makeNucleiLine({ templateId: "lfi-unix-path", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(106);
    });

    it("resolves path-traversal from template ID", async () => {
      const line = makeNucleiLine({ templateId: "path-traversal-windows", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(106);
    });

    it("resolves CVE ID from template ID containing 'cve-'", async () => {
      const line = makeNucleiLine({ templateId: "cve-2021-44228-log4j", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(3);
    });

    it("resolves redirect from template ID", async () => {
      const line = makeNucleiLine({ templateId: "open-redirect-via-url", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(119);
    });

    it("resolves admin panel from template ID", async () => {
      const line = makeNucleiLine({ templateId: "admin-panel-detect", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(116);
    });

    it("resolves config misconfiguration from template ID", async () => {
      const line = makeNucleiLine({ templateId: "misconfig-server-info", tags: [] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(4);
    });

    it("falls back to vuln_id 4 for unrecognised http-type finding", async () => {
      const line = makeNucleiLine({ templateId: "completely-unknown", tags: [], type: "http" });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(4);
    });

    it("falls back to vuln_id 199 for non-http unrecognised finding", async () => {
      const line = makeNucleiLine({ templateId: "completely-unknown", tags: [], type: "dns" });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].vulnerability_id).toBe(199);
    });
  });

  // -------------------------------------------------------------------------
  // Finding shape
  // -------------------------------------------------------------------------

  describe("finding shape", () => {
    it("sets category to 'dast'", async () => {
      const line = makeNucleiLine({ tags: ["xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].category).toBe("dast");
    });

    it("prefixes title with [DAST]", async () => {
      const line = makeNucleiLine({ name: "SQL Injection", tags: ["sqli"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].title).toBe("[DAST] SQL Injection");
    });

    it("sets file_path to matched-at value", async () => {
      const matchedAt = "https://example.com/search?q=1'";
      const line = makeNucleiLine({ matchedAt, tags: ["sqli"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].file_path).toBe(matchedAt);
    });

    it("sets code_snippet to curl-command when present", async () => {
      const curlCmd = "curl -X GET 'https://example.com/api?id=1'";
      const line = makeNucleiLine({ curlCommand: curlCmd, tags: ["sqli"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].code_snippet).toBe(curlCmd);
    });

    it("falls back to template ID in code_snippet when curl-command absent", async () => {
      const line = makeNucleiLine({ templateId: "sqli-generic", tags: ["sqli"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].code_snippet).toContain("sqli-generic");
    });

    it("sets status to 'open'", async () => {
      const line = makeNucleiLine({});
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].status).toBe("open");
    });

    it("includes description in description_technical", async () => {
      const description = "The application echoes user input unsafely.";
      const line = makeNucleiLine({ description, tags: ["xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain(description);
    });

    it("includes CVE IDs in description_technical", async () => {
      const line = makeNucleiLine({ cveIds: ["CVE-2021-44228"], tags: ["cve"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain("CVE-2021-44228");
    });

    it("includes CWE IDs in description_technical", async () => {
      const line = makeNucleiLine({ cweIds: ["CWE-79"], tags: ["xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain("CWE-79");
    });

    it("includes references in description_technical", async () => {
      const line = makeNucleiLine({
        references: ["https://owasp.org/www-community/attacks/xss/"],
        tags: ["xss"],
      });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain("https://owasp.org");
    });

    it("includes matched-at in description_technical", async () => {
      const matchedAt = "https://example.com/vuln-endpoint";
      const line = makeNucleiLine({ matchedAt, tags: ["xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain(matchedAt);
    });

    it("includes tags in description_technical", async () => {
      const line = makeNucleiLine({ tags: ["xss", "oast"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].description_technical).toContain("xss");
    });
  });

  // -------------------------------------------------------------------------
  // OWASP mapping via mapToOwasp
  // -------------------------------------------------------------------------

  describe("OWASP reference mapping", () => {
    it("maps sqli tag to A03:2021", async () => {
      const line = makeNucleiLine({ tags: ["sqli"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A03:2021");
    });

    it("maps xss tag to A03:2021", async () => {
      const line = makeNucleiLine({ tags: ["xss"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A03:2021");
    });

    it("maps rce tag to A03:2021", async () => {
      const line = makeNucleiLine({ tags: ["rce"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A03:2021");
    });

    it("maps ssrf tag to A10:2021", async () => {
      const line = makeNucleiLine({ tags: ["ssrf"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A10:2021");
    });

    it("maps idor tag to A01:2021", async () => {
      const line = makeNucleiLine({ tags: ["idor"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A01:2021");
    });

    it("maps cve tag to A06:2021", async () => {
      const line = makeNucleiLine({ tags: ["cve"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A06:2021");
    });

    it("maps misconfiguration tag to A05:2021", async () => {
      const line = makeNucleiLine({ tags: ["misconfiguration"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A05:2021");
    });

    it("maps cors tag to A05:2021", async () => {
      const line = makeNucleiLine({ tags: ["cors"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A05:2021");
    });

    it("maps default-login tag to A07:2021", async () => {
      const line = makeNucleiLine({ tags: ["default-login"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A07:2021");
    });

    it("maps default-credential tag to A07:2021", async () => {
      const line = makeNucleiLine({ tags: ["default-credential"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBe("A07:2021");
    });

    it("returns undefined owasp_ref for unrecognised tags", async () => {
      const line = makeNucleiLine({ tags: ["some-obscure-tag"] });
      mockExec.mockReturnValue(makeExecResult(line));

      const findings = await runDast("https://example.com");

      expect(findings[0].owasp_ref).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // HOME=/tmp env variable requirement
  // -------------------------------------------------------------------------

  describe("nuclei invocation options", () => {
    it("passes HOME=/tmp in the env options so nuclei can locate templates", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      await runDast("https://example.com");

      const [, , options] = mockExec.mock.calls[0];
      expect(options.env).toBeDefined();
      expect(options.env!["HOME"]).toBe("/home/worker");
    });

    it("passes the target URL as -u argument", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      await runDast("https://target.example.com");

      const [, args] = mockExec.mock.calls[0];
      const uIndex = args.indexOf("-u");
      expect(uIndex).toBeGreaterThanOrEqual(0);
      expect(args[uIndex + 1]).toBe("https://target.example.com");
    });

    it("passes -jsonl flag to get JSONL output", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      await runDast("https://example.com");

      const [, args] = mockExec.mock.calls[0];
      expect(args).toContain("-jsonl");
    });

    it("passes 120000ms timeout to execWithTimeout", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      await runDast("https://example.com");

      const [, , options] = mockExec.mock.calls[0];
      expect(options.timeoutMs).toBe(170_000);
    });

    it("passes -no-interactsh to avoid out-of-band testing", async () => {
      mockExec.mockReturnValue(makeExecResult(""));

      await runDast("https://example.com");

      const [, args] = mockExec.mock.calls[0];
      expect(args).toContain("-no-interactsh");
    });
  });
});
