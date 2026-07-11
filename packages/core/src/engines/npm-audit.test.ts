// Tests for the npm audit engine.
// We mock execWithTimeout so npm never runs for real, and mock node:fs/promises
// so we can control whether package-lock.json appears to exist.

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---- hoisted mocks (available inside vi.mock factories) -----------------

const { mockExec, mockAccess } = vi.hoisted(() => ({
  mockExec: vi.fn(),
  mockAccess: vi.fn(),
}));

vi.mock("../utils/exec.js", () => ({
  execWithTimeout: mockExec,
}));

vi.mock("../utils/fs.js", () => ({
  access: mockAccess,
}));

// -----------------------------------------------------------------------

import { runNpmAudit } from "./npm-audit.js";

const REPO_DIR = "/home/runner/work/my-app";

// ---- helpers ----------------------------------------------------------

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

// Simulate package-lock.json present
function lockfileExists() {
  mockAccess.mockResolvedValue(undefined);
}

// Simulate package-lock.json absent
function noLockfile() {
  mockAccess.mockRejectedValue(Object.assign(new Error("ENOENT"), { code: "ENOENT" }));
}

function setupAuditOutput(stdout: string, exitCode = 0) {
  mockExec.mockResolvedValue({ stdout, stderr: "", exitCode });
}

// ---- fixture factories ------------------------------------------------

interface NpmViaOptions {
  title?: string;
  severity?: string;
  url?: string;
  cwe?: string[];
  cvssScore?: number;
}

function makeVia(overrides: NpmViaOptions = {}) {
  return {
    source: 1001,
    name: "lodash",
    dependency: "lodash",
    title: overrides.title ?? "Prototype Pollution in lodash",
    url: overrides.url ?? "https://github.com/advisories/GHSA-xxxx",
    severity: overrides.severity ?? "high",
    cwe: overrides.cwe ?? ["CWE-1321"],
    cvss: {
      score: overrides.cvssScore ?? 7.4,
      vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    range: ">=4.17.0 <4.17.21",
  };
}

interface NpmVulnOptions {
  name?: string;
  severity?: string;
  isDirect?: boolean;
  via?: Array<ReturnType<typeof makeVia> | string>;
  range?: string;
  fixAvailable?: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

function makeVuln(overrides: NpmVulnOptions = {}) {
  return {
    name: overrides.name ?? "lodash",
    severity: overrides.severity ?? "high",
    isDirect: overrides.isDirect ?? true,
    via: overrides.via ?? [makeVia()],
    effects: [],
    range: overrides.range ?? ">=4.17.0 <4.17.21",
    nodes: [],
    fixAvailable: overrides.fixAvailable ?? true,
  };
}

interface AuditOutputOptions {
  vulnerabilities?: Record<string, ReturnType<typeof makeVuln>>;
}

function makeAuditOutput(overrides: AuditOutputOptions = {}) {
  const vulnerabilities = overrides.vulnerabilities ?? {
    lodash: makeVuln(),
  };
  return JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities,
    metadata: {
      vulnerabilities: {
        total: 1,
        critical: 0,
        high: 1,
        moderate: 0,
        low: 0,
        info: 0,
      },
    },
  });
}

// -----------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

// -----------------------------------------------------------------------

describe("runNpmAudit", () => {
  describe("when package-lock.json is absent", () => {
    it("returns empty array without calling npm", async () => {
      noLockfile();
      const files = makeFiles({ "package.json": "{}" });

      const findings = await runNpmAudit(REPO_DIR, files);

      expect(findings).toHaveLength(0);
      expect(mockExec).not.toHaveBeenCalled();
    });
  });

  describe("when npm audit finds no vulnerabilities", () => {
    it("returns empty array when output has no vulnerabilities key", async () => {
      lockfileExists();
      setupAuditOutput(JSON.stringify({ auditReportVersion: 2, metadata: {} }));

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when vulnerabilities object is empty", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput({ vulnerabilities: {} }));

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(0);
    });

    it("returns empty array when stdout is blank", async () => {
      lockfileExists();
      setupAuditOutput("   ");

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(0);
    });
  });

  describe("severity mapping", () => {
    it("maps npm critical to our critical severity", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-pkg": makeVuln({
              name: "some-pkg",
              severity: "critical",
              via: [makeVia({ severity: "critical" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("critical");
    });

    it("maps npm high to our high severity", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({
              severity: "high",
              via: [makeVia({ severity: "high" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("high");
    });

    it("maps npm moderate to our medium severity", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-pkg": makeVuln({
              name: "some-pkg",
              severity: "moderate",
              via: [makeVia({ severity: "moderate" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("medium");
    });

    it("maps npm low to our low severity", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-pkg": makeVuln({
              name: "some-pkg",
              severity: "low",
              via: [makeVia({ severity: "low" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("low");
    });

    it("maps npm info to our info severity", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-pkg": makeVuln({
              name: "some-pkg",
              severity: "info",
              via: [makeVia({ severity: "info" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("info");
    });

    it("falls back to medium for an unknown severity string", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-pkg": makeVuln({
              name: "some-pkg",
              severity: "unknown-level",
              via: [makeVia({ severity: "unknown-level" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].severity).toBe("medium");
    });
  });

  describe("advisory (via) details", () => {
    it("uses advisory title combined with package name as finding title", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({
              via: [makeVia({ title: "Prototype Pollution" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].title).toContain("Prototype Pollution");
      expect(findings[0].title).toContain("lodash");
    });

    it("includes advisory URL in description_technical", async () => {
      lockfileExists();
      const advisoryUrl = "https://github.com/advisories/GHSA-test-1234";
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({ via: [makeVia({ url: advisoryUrl })] }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].description_technical).toContain(advisoryUrl);
    });

    it("includes CWE identifiers in description_technical", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({ via: [makeVia({ cwe: ["CWE-1321", "CWE-400"] })] }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].description_technical).toContain("CWE-1321");
    });

    it("includes CVSS score in description_technical when present", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({ via: [makeVia({ cvssScore: 9.8 })] }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].description_technical).toContain("9.8");
    });

    it("produces one finding per advisory entry in via array", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({
              via: [
                makeVia({ title: "Prototype Pollution" }),
                makeVia({ title: "ReDoS in lodash" }),
              ],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(2);
    });
  });

  describe("transitive vulnerabilities (string-only via)", () => {
    it("reports transitive dependency with a finding when via is all strings", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "some-dep": makeVuln({
              name: "some-dep",
              via: ["parent-package"],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(1);
      expect(findings[0].title).toContain("some-dep");
    });

    it("marks transitive dependencies as such in description", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "transitive-dep": makeVuln({
              name: "transitive-dep",
              isDirect: false,
              via: ["parent-pkg"],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].description_technical).toContain("Transitive");
    });

    it("marks direct dependencies as such in description", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            "direct-dep": makeVuln({
              name: "direct-dep",
              isDirect: true,
              via: ["parent-pkg"],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].description_technical).toContain("Direct");
    });
  });

  describe("fix_description", () => {
    it("generates 'run npm audit fix' message when fixAvailable is true", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput({ vulnerabilities: { lodash: makeVuln({ fixAvailable: true }) } }));

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].fix_description).toContain("npm audit fix");
    });

    it("generates 'No fix available' message when fixAvailable is false", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput({ vulnerabilities: { lodash: makeVuln({ fixAvailable: false }) } }));

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].fix_description).toContain("No fix available");
    });

    it("generates version bump message for minor object fixAvailable", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({
              fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].fix_description).toContain("4.17.21");
      expect(findings[0].fix_description).toContain("npm audit fix");
    });

    it("generates '--force' message for major semver bump", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({
              fixAvailable: { name: "lodash", version: "5.0.0", isSemVerMajor: true },
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].fix_description).toContain("--force");
    });
  });

  describe("finding structure", () => {
    it("sets vulnerability_id to 3 for all dependency findings", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput());

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].vulnerability_id).toBe(3);
    });

    it("sets category to supply-chain", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput());

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].category).toBe("supply-chain");
    });

    it("sets file_path to package-lock.json", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput());

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].file_path).toBe("package-lock.json");
    });

    it("sets owasp_ref to A06:2021", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput());

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].owasp_ref).toBe("A06:2021");
    });

    it("sets status to open", async () => {
      lockfileExists();
      setupAuditOutput(makeAuditOutput());

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].status).toBe("open");
    });

    it("includes package name and range in code_snippet", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({ name: "lodash", range: ">=4.17.0 <4.17.21" }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings[0].code_snippet).toContain("lodash");
      expect(findings[0].code_snippet).toContain(">=4.17.0 <4.17.21");
    });
  });

  describe("non-zero exit code handling", () => {
    it("still returns findings when npm exits with code 1 (vulnerabilities found)", async () => {
      lockfileExists();
      // npm audit exits non-zero when vulns found, but execWithTimeout resolves
      mockExec.mockResolvedValue({
        stdout: makeAuditOutput(),
        stderr: "",
        exitCode: 1,
      });

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe("error handling", () => {
    it("propagates timeout errors from execWithTimeout", async () => {
      lockfileExists();
      mockExec.mockRejectedValue(new Error("npm timed out after 30000ms"));

      await expect(runNpmAudit(REPO_DIR, makeFiles({}))).rejects.toThrow("timed out");
    });

    it("propagates ENOENT errors (npm not installed)", async () => {
      lockfileExists();
      mockExec.mockRejectedValue(new Error("ENOENT: npm not found"));

      await expect(runNpmAudit(REPO_DIR, makeFiles({}))).rejects.toThrow("ENOENT");
    });

    it("returns empty array for malformed JSON output", async () => {
      lockfileExists();
      setupAuditOutput("{ bad json }}}");

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(0);
    });

    it("returns empty array for other exec errors (not timeout or ENOENT)", async () => {
      lockfileExists();
      mockExec.mockRejectedValue(new Error("some unexpected exec error"));

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(0);
    });
  });

  describe("multiple vulnerabilities", () => {
    it("returns one finding per package with advisory details", async () => {
      lockfileExists();
      setupAuditOutput(
        makeAuditOutput({
          vulnerabilities: {
            lodash: makeVuln({ name: "lodash" }),
            semver: makeVuln({
              name: "semver",
              severity: "critical",
              via: [makeVia({ title: "ReDoS in semver", severity: "critical" })],
            }),
          },
        })
      );

      const findings = await runNpmAudit(REPO_DIR, makeFiles({}));

      expect(findings).toHaveLength(2);

      const titles = findings.map((f) => f.title);
      expect(titles.some((t) => t.includes("lodash"))).toBe(true);
      expect(titles.some((t) => t.includes("semver"))).toBe(true);
    });
  });
});
