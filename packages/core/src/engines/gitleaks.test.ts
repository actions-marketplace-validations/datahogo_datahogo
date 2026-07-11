// Tests for the Gitleaks engine.
// The engine shells out to the `gitleaks` binary and writes a JSON report to a
// temp file.  We mock `execWithTimeout` so no real binary is needed, and mock
// `node:fs/promises` so we can control the report file content.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---- hoisted mocks (available inside vi.mock factories) -----------------

const { mockExec, mockReadFile, mockRm } = vi.hoisted(() => ({
  mockExec: vi.fn(),
  mockReadFile: vi.fn(),
  mockRm: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../utils/exec.js", () => ({
  execWithTimeout: mockExec,
}));

vi.mock("../utils/fs.js", () => ({
  readFile: mockReadFile,
  rm: mockRm,
}));

// -----------------------------------------------------------------------

import { runGitleaks } from "./gitleaks.js";

// A repoDir used across all tests — paths in fixtures are absolute and start
// with this value so relativisation logic can be exercised.
const REPO_DIR = "/home/runner/work/my-app";

// ---- fixture factory --------------------------------------------------

interface GitleaksLeakOptions {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Match?: string;
  Secret?: string;
}

function makeGitleaksLeak(overrides: GitleaksLeakOptions = {}) {
  return {
    Description: overrides.Description ?? "Generic API Key",
    StartLine: overrides.StartLine ?? 12,
    EndLine: overrides.StartLine ?? 12,
    StartColumn: 1,
    EndColumn: 50,
    Match: overrides.Match ?? `API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456`,
    Secret: overrides.Secret ?? "sk-abcdefghijklmnopqrstuvwxyz123456",
    File: overrides.File ?? `${REPO_DIR}/src/config.ts`,
    SymlinkFile: "",
    Commit: "",
    Entropy: 4.5,
    Author: "",
    Email: "",
    Date: "",
    Message: "",
    Tags: [],
    RuleID: overrides.RuleID ?? "generic-api-key",
    Fingerprint: "abc123",
  };
}

function makeReport(leaks: ReturnType<typeof makeGitleaksLeak>[]) {
  return JSON.stringify(leaks);
}

// Helper: set up the mocks for a run that produces `reportJson` content
function setupRun(reportJson: string | null) {
  mockExec.mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });

  if (reportJson === null) {
    // Simulate no report file (no leaks, exit 0)
    mockReadFile.mockRejectedValue(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));
  } else {
    mockReadFile.mockResolvedValue(reportJson);
  }
}

// -----------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

// -----------------------------------------------------------------------

describe("runGitleaks", () => {
  describe("when gitleaks finds no secrets", () => {
    it("returns an empty array when the report file does not exist", async () => {
      setupRun(null);

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns an empty array when the report file is empty", async () => {
      setupRun("   ");

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns an empty array when the report is an empty JSON array", async () => {
      setupRun("[]");

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });
  });

  describe("when gitleaks finds secrets", () => {
    it("returns one finding per leak entry", async () => {
      const report = makeReport([
        makeGitleaksLeak({ RuleID: "generic-api-key" }),
        makeGitleaksLeak({ RuleID: "aws-access-key-id", Secret: "AKIAIOSFODNN7EXAMPLE" }),
      ]);
      setupRun(report);

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(2);
    });

    it("maps generic-api-key RuleID to vulnerability_id 53", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "generic-api-key" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(53);
    });

    it("maps aws-access-key-id to vulnerability_id 53 with critical severity", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "aws-access-key-id" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(53);
      expect(findings[0].severity).toBe("critical");
    });

    it("maps private-key to critical severity", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "private-key" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].severity).toBe("critical");
    });

    it("maps slack-webhook-url to high severity", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "slack-webhook-url" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].severity).toBe("high");
    });

    it("maps mailchimp-api-key to high severity", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "mailchimp-api-key" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].severity).toBe("high");
    });

    it("maps jwt rule to vulnerability_id 53 and high severity", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "jwt" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(53);
      expect(findings[0].severity).toBe("high");
    });

    it("maps password-in-url to vulnerability_id 55 and critical severity", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({
            RuleID: "password-in-url",
            Match: "postgres://admin:s3cr3t@host/db",
            Secret: "s3cr3t",
          }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(55);
      expect(findings[0].severity).toBe("critical");
    });

    it("maps postgresql-connection-string to vulnerability_id 101", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({
            RuleID: "postgresql-connection-string",
            Secret: "postgres://user:pass@host:5432/db",
          }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(101);
      expect(findings[0].category).toBe("database");
    });

    it("uses DEFAULT_MAPPING (id 53, critical) for unknown RuleIDs", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "some-unknown-rule-xyz" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].vulnerability_id).toBe(53);
      expect(findings[0].severity).toBe("critical");
    });
  });

  describe("file path relativisation", () => {
    it("strips the repoDir prefix from absolute file paths", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({ File: `${REPO_DIR}/src/config.ts` }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].file_path).toBe("src/config.ts");
    });

    it("leaves paths unchanged when they do not start with repoDir", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({ File: "relative/path/file.ts" }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].file_path).toBe("relative/path/file.ts");
    });

    it("handles files at the repo root level", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({ File: `${REPO_DIR}/.env` }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].file_path).toBe(".env");
    });
  });

  describe("secret masking", () => {
    it("replaces the secret value in the Match snippet with a redaction marker", async () => {
      const secret = "sk-abcdefghijklmnopqrstuvwxyz123456";
      setupRun(
        makeReport([
          makeGitleaksLeak({
            Match: `API_KEY=${secret}`,
            Secret: secret,
          }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].code_snippet).not.toContain(secret);
      expect(findings[0].code_snippet).toContain("REDACTED");
    });

    it("uses the first 6 characters of the secret as the visible prefix", async () => {
      const secret = "sk-abcdefghijklmnopqrstuvwxyz123456";
      setupRun(
        makeReport([
          makeGitleaksLeak({
            Match: `API_KEY=${secret}`,
            Secret: secret,
          }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      // First 6 chars of the secret appear in the snippet, full secret does not
      expect(findings[0].code_snippet).toContain("sk-abc");
      expect(findings[0].code_snippet).not.toContain(secret);
    });

    it("uses a blanket redaction marker for very short secrets (6 chars or fewer)", async () => {
      const secret = "12345";
      setupRun(
        makeReport([
          makeGitleaksLeak({
            Match: `PIN=${secret}`,
            Secret: secret,
          }),
        ])
      );

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].code_snippet).toContain("***REDACTED***");
    });
  });

  describe("finding structure", () => {
    it("includes all required FindingData fields", async () => {
      setupRun(makeReport([makeGitleaksLeak()]));

      const [finding] = await runGitleaks(REPO_DIR);

      expect(finding).toHaveProperty("vulnerability_id");
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("category");
      expect(finding).toHaveProperty("title");
      expect(finding).toHaveProperty("description_technical");
      expect(finding).toHaveProperty("file_path");
      expect(finding).toHaveProperty("line_number");
      expect(finding).toHaveProperty("code_snippet");
      expect(finding).toHaveProperty("owasp_ref");
      expect(finding.status).toBe("open");
    });

    it("sets owasp_ref to A07:2021", async () => {
      setupRun(makeReport([makeGitleaksLeak()]));

      const [finding] = await runGitleaks(REPO_DIR);

      expect(finding.owasp_ref).toBe("A07:2021");
    });

    it("uses the leak Description as the finding title", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({ Description: "AWS Access Key" }),
        ])
      );

      const [finding] = await runGitleaks(REPO_DIR);

      expect(finding.title).toBe("AWS Access Key");
    });

    it("includes the RuleID in the description_technical field", async () => {
      setupRun(
        makeReport([
          makeGitleaksLeak({ RuleID: "github-pat" }),
        ])
      );

      const [finding] = await runGitleaks(REPO_DIR);

      expect(finding.description_technical).toContain("github-pat");
    });

    it("reports the correct line number from StartLine", async () => {
      setupRun(makeReport([makeGitleaksLeak({ StartLine: 42 })]));

      const [finding] = await runGitleaks(REPO_DIR);

      expect(finding.line_number).toBe(42);
    });
  });

  describe("malformed JSON handling", () => {
    it("returns empty array for completely invalid JSON", async () => {
      setupRun("{ not valid json at all }}}");

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when JSON is not an array (unexpected shape)", async () => {
      setupRun(JSON.stringify({ error: "unexpected output" }));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });
  });

  describe("exit code handling", () => {
    it("treats exit code 1 (leaks found) as a successful run, not an error", async () => {
      // execWithTimeout resolves even on exit code 1 — our exec utility never
      // rejects on non-zero codes; only the report file content matters.
      mockExec.mockResolvedValue({ stdout: "", stderr: "", exitCode: 1 });
      mockReadFile.mockResolvedValue(makeReport([makeGitleaksLeak()]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(1);
    });

    it("propagates timeout errors thrown by execWithTimeout", async () => {
      mockExec.mockRejectedValue(new Error("gitleaks timed out after 30000ms"));

      await expect(runGitleaks(REPO_DIR)).rejects.toThrow("timed out");
    });

    it("propagates ENOENT errors (binary not installed)", async () => {
      mockExec.mockRejectedValue(new Error("ENOENT: gitleaks not found"));

      await expect(runGitleaks(REPO_DIR)).rejects.toThrow("ENOENT");
    });

    it("does NOT propagate other exec errors (non-timeout, non-ENOENT)", async () => {
      // Engine catches these, falls through to reading the report file (which does not exist)
      mockExec.mockRejectedValue(new Error("some other exec failure"));
      mockReadFile.mockRejectedValue(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings).toHaveLength(0);
    });
  });

  describe("cleanup", () => {
    it("always deletes the temp report file even when readFile throws", async () => {
      mockExec.mockResolvedValue({ stdout: "", stderr: "", exitCode: 0 });
      mockReadFile.mockRejectedValue(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));

      await runGitleaks(REPO_DIR);

      expect(mockRm).toHaveBeenCalledWith(expect.any(String), { force: true });
    });

    it("always deletes the temp report file after successful read", async () => {
      setupRun(makeReport([makeGitleaksLeak()]));

      await runGitleaks(REPO_DIR);

      expect(mockRm).toHaveBeenCalledWith(expect.any(String), { force: true });
    });
  });

  describe("supply-chain category rules", () => {
    it("maps npm-access-token to supply-chain category", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "npm-access-token" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].category).toBe("supply-chain");
    });

    it("maps pypi-upload-token to supply-chain category", async () => {
      setupRun(makeReport([makeGitleaksLeak({ RuleID: "pypi-upload-token" })]));

      const findings = await runGitleaks(REPO_DIR);

      expect(findings[0].category).toBe("supply-chain");
    });
  });
});
