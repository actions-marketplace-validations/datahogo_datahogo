// npm audit engine - runs npm audit for real-time CVE dependency scanning.
// Only runs when package-lock.json exists in the repo (required by npm audit).
// The hardcoded dependencies engine still runs for typosquatting detection.

import { execWithTimeout } from "../utils/exec.js";
import { access } from "../utils/fs.js";
import path from "node:path";
import type { FindingData, Severity } from "./types.js";

// npm audit --json output structure (v7+ format)
interface NpmAuditOutput {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, NpmVulnerability>;
  metadata?: {
    vulnerabilities: { total: number; critical: number; high: number; moderate: number; low: number; info: number };
  };
}

interface NpmVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<NpmVia | string>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

interface NpmVia {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  cwe: string[];
  cvss: { score: number; vectorString: string };
  range: string;
}

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "info",
};

export async function runNpmAudit(
  repoDir: string,
  files: Map<string, string>
): Promise<FindingData[]> {
  // npm audit requires package-lock.json
  const lockfilePath = path.join(repoDir, "package-lock.json");
  try {
    await access(lockfilePath);
  } catch {
    // No lockfile — can't run npm audit
    return [];
  }

  let stdout: string;
  try {
    // npm audit exits with non-zero when vulnerabilities are found — expected behavior
    const result = await execWithTimeout("npm", [
      "audit",
      "--json",
      "--omit=dev",
    ], {
      timeoutMs: 60_000,
      cwd: repoDir,
    });
    stdout = result.stdout;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("timed out") || message.includes("ENOENT")) {
      throw error;
    }
    // npm audit exits non-zero when vulns found — try to extract stdout from error
    return [];
  }

  if (!stdout.trim()) return [];

  let output: NpmAuditOutput;
  try {
    output = JSON.parse(stdout);
  } catch {
    return [];
  }

  if (!output.vulnerabilities) return [];

  const findings: FindingData[] = [];

  for (const [pkgName, vuln] of Object.entries(output.vulnerabilities)) {
    // Get the actual advisory details from `via` (skip string-only entries)
    const advisories = vuln.via.filter((v): v is NpmVia => typeof v !== "string");

    if (advisories.length === 0) {
      // Transitive vulnerability — still report but with less detail
      findings.push({
        vulnerability_id: 3,
        severity: SEVERITY_MAP[vuln.severity] ?? "medium",
        category: "supply-chain",
        title: `Vulnerable Dependency: ${pkgName}`,
        description_technical: `${pkgName} (${vuln.range}) has known vulnerabilities. ${vuln.isDirect ? "Direct dependency." : "Transitive dependency."}`,
        file_path: "package-lock.json",
        code_snippet: `"${pkgName}": "${vuln.range}"`,
        fix_description: formatFixAvailable(vuln.fixAvailable),
        owasp_ref: "A06:2021",
        status: "open",
      });
      continue;
    }

    for (const advisory of advisories) {
      const cweStr = advisory.cwe?.join(", ") || "";

      findings.push({
        vulnerability_id: 3,
        severity: SEVERITY_MAP[advisory.severity] ?? SEVERITY_MAP[vuln.severity] ?? "medium",
        category: "supply-chain",
        title: `${advisory.title}: ${pkgName}`,
        description_technical: [
          advisory.title,
          `Package: ${pkgName} (${vuln.range})`,
          vuln.isDirect ? "Direct dependency" : "Transitive dependency",
          advisory.url ? `Advisory: ${advisory.url}` : "",
          cweStr ? `CWE: ${cweStr}` : "",
          advisory.cvss?.score ? `CVSS: ${advisory.cvss.score}` : "",
        ].filter(Boolean).join("\n"),
        file_path: "package-lock.json",
        code_snippet: `"${pkgName}": "${vuln.range}"`,
        fix_description: formatFixAvailable(vuln.fixAvailable),
        owasp_ref: "A06:2021",
        status: "open",
      });
    }
  }

  return findings;
}

function formatFixAvailable(fix: NpmVulnerability["fixAvailable"]): string {
  if (fix === true) return "A fix is available. Run `npm audit fix` to apply.";
  if (fix === false) return "No fix available yet. Consider finding an alternative package.";
  if (typeof fix === "object") {
    return fix.isSemVerMajor
      ? `Update ${fix.name} to ${fix.version} (breaking change). Run \`npm audit fix --force\`.`
      : `Update ${fix.name} to ${fix.version}. Run \`npm audit fix\`.`;
  }
  return "";
}
