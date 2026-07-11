import { describe, it, expect } from "vitest";
import { analyzeDependencies } from "./dependencies";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

function makePackageJson(
  deps: Record<string, string> = {},
  devDeps: Record<string, string> = {}
): string {
  return JSON.stringify({
    name: "test-project",
    dependencies: deps,
    devDependencies: devDeps,
  });
}

describe("analyzeDependencies", () => {
  describe("known vulnerable packages", () => {
    it("detects node-serialize (no fix version, always flagged)", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "node-serialize": "^0.0.4" }),
      });
      const findings = analyzeDependencies(files);
      expect(findings.length).toBeGreaterThan(0);

      const nsFind = findings.find((f) => f.title.includes("node-serialize"));
      expect(nsFind).toBeDefined();
      expect(nsFind!.severity).toBe("critical");
      expect(nsFind!.category).toBe("supply-chain");
      expect(nsFind!.vulnerability_id).toBe(3);
      expect(nsFind!.owasp_ref).toBe("A06:2021");
    });

    it("detects vulnerable lodash version", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ lodash: "^4.17.15" }),
      });
      const findings = analyzeDependencies(files);
      const lodashFind = findings.find((f) => f.title.includes("lodash"));
      expect(lodashFind).toBeDefined();
      expect(lodashFind!.severity).toBe("high");
    });

    it("does not flag lodash at or above fix version", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ lodash: "^4.17.21" }),
      });
      const findings = analyzeDependencies(files);
      const lodashFind = findings.find((f) => f.title.includes("lodash"));
      expect(lodashFind).toBeUndefined();
    });

    it("does not flag lodash above fix version (major bump)", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ lodash: "^5.0.0" }),
      });
      const findings = analyzeDependencies(files);
      const lodashFind = findings.find((f) => f.title.includes("lodash"));
      expect(lodashFind).toBeUndefined();
    });

    it("detects vulnerable jsonwebtoken version", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ jsonwebtoken: "^8.5.1" }),
      });
      const findings = analyzeDependencies(files);
      const jwtFind = findings.find((f) => f.title.includes("jsonwebtoken"));
      expect(jwtFind).toBeDefined();
      expect(jwtFind!.severity).toBe("high");
    });

    it("does not flag jsonwebtoken at fix version", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ jsonwebtoken: "^9.0.0" }),
      });
      const findings = analyzeDependencies(files);
      const jwtFind = findings.find((f) => f.title.includes("jsonwebtoken"));
      expect(jwtFind).toBeUndefined();
    });

    it("detects vulnerable yaml package", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ yaml: "^1.10.2" }),
      });
      const findings = analyzeDependencies(files);
      const yamlFind = findings.find((f) => f.title.includes("yaml"));
      expect(yamlFind).toBeDefined();
      expect(yamlFind!.severity).toBe("critical");
    });

    it("detects vulnerable packages in devDependencies", () => {
      const files = makeFiles({
        "package.json": makePackageJson({}, { "node-serialize": "^0.0.4" }),
      });
      const findings = analyzeDependencies(files);
      const nsFind = findings.find((f) => f.title.includes("node-serialize"));
      expect(nsFind).toBeDefined();
    });

    it("includes fix description for packages with fixVersion", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ lodash: "^4.17.15" }),
      });
      const findings = analyzeDependencies(files);
      const lodashFind = findings.find((f) => f.title.includes("lodash"));
      expect(lodashFind!.fix_description).toContain("4.17.21");
    });

    it("tells to remove package when no fixVersion exists", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "node-serialize": "^0.0.4" }),
      });
      const findings = analyzeDependencies(files);
      const nsFind = findings.find((f) => f.title.includes("node-serialize"));
      expect(nsFind!.fix_description).toContain("Remove");
    });
  });

  describe("typosquatted / suspicious packages", () => {
    it("detects crossenv typosquat", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ crossenv: "^7.0.0" }),
      });
      const findings = analyzeDependencies(files);
      const suspicious = findings.find((f) => f.vulnerability_id === 137);
      expect(suspicious).toBeDefined();
      expect(suspicious!.severity).toBe("high");
      expect(suspicious!.title).toContain("Suspicious Package");
    });

    it("detects event-stream supply chain attack package", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "event-stream": "^3.3.4" }),
      });
      const findings = analyzeDependencies(files);
      const suspicious = findings.find((f) => f.vulnerability_id === 137);
      expect(suspicious).toBeDefined();
    });

    it("detects flatmap-stream", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "flatmap-stream": "^0.1.1" }),
      });
      const findings = analyzeDependencies(files);
      const suspicious = findings.find((f) => f.vulnerability_id === 137);
      expect(suspicious).toBeDefined();
    });

    it("detects colors-js typosquat", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "colors-js": "^1.0.0" }),
      });
      const findings = analyzeDependencies(files);
      const suspicious = findings.find((f) => f.vulnerability_id === 137);
      expect(suspicious).toBeDefined();
    });
  });

  describe("safe packages", () => {
    it("returns empty for safe packages", () => {
      const files = makeFiles({
        "package.json": makePackageJson({
          react: "^19.0.0",
          next: "^15.0.0",
          typescript: "^5.4.0",
        }),
      });
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });

    it("returns empty for empty dependencies", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ name: "test", dependencies: {} }),
      });
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });
  });

  describe("missing package.json", () => {
    it("returns empty when package.json is not in file map", () => {
      const files = makeFiles({
        "src/index.ts": "console.log('hello');",
      });
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });

    it("returns empty for empty file map", () => {
      const files = new Map<string, string>();
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });
  });

  describe("invalid package.json", () => {
    it("handles malformed JSON gracefully", () => {
      const files = makeFiles({
        "package.json": "{ not valid json }}}",
      });
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });

    it("handles empty string gracefully", () => {
      const files = makeFiles({
        "package.json": "",
      });
      const findings = analyzeDependencies(files);
      expect(findings).toHaveLength(0);
    });
  });

  describe("unpinned dependencies", () => {
    it("flags all-unpinned dependencies when count exceeds 5", () => {
      const deps: Record<string, string> = {};
      for (let i = 0; i < 6; i++) {
        deps[`safe-pkg-${i}`] = `^${i}.0.0`;
      }
      const files = makeFiles({
        "package.json": makePackageJson(deps),
      });
      const findings = analyzeDependencies(files);
      const unpinnedFind = findings.find((f) => f.vulnerability_id === 60);
      expect(unpinnedFind).toBeDefined();
      expect(unpinnedFind!.severity).toBe("medium");
    });

    it("does not flag when fewer than 6 unpinned deps", () => {
      const files = makeFiles({
        "package.json": makePackageJson({
          react: "^19.0.0",
          next: "^15.0.0",
        }),
      });
      const findings = analyzeDependencies(files);
      const unpinnedFind = findings.find((f) => f.vulnerability_id === 60);
      expect(unpinnedFind).toBeUndefined();
    });

    it("does not flag when some deps are pinned (not all unpinned)", () => {
      const deps: Record<string, string> = {};
      for (let i = 0; i < 6; i++) {
        deps[`safe-pkg-${i}`] = `^${i}.0.0`;
      }
      deps["pinned-pkg"] = "1.0.0";
      const files = makeFiles({
        "package.json": makePackageJson(deps),
      });
      const findings = analyzeDependencies(files);
      const unpinnedFind = findings.find((f) => f.vulnerability_id === 60);
      expect(unpinnedFind).toBeUndefined();
    });
  });

  describe("finding structure", () => {
    it("includes correct file_path and code_snippet", () => {
      const files = makeFiles({
        "package.json": makePackageJson({ "node-serialize": "^0.0.4" }),
      });
      const findings = analyzeDependencies(files);
      const nsFind = findings.find((f) => f.title.includes("node-serialize"));
      expect(nsFind!.file_path).toBe("package.json");
      expect(nsFind!.code_snippet).toContain("node-serialize");
      expect(nsFind!.status).toBe("open");
    });
  });
});
