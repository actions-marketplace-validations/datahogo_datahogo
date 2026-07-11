// Dependencies analysis engine - checks for vulnerable packages
// In production, this calls npm audit and OSV. For now, checks package.json/lock.

import type { FindingData } from "./types.js";

// Known vulnerable packages (subset - in production, use npm audit + OSV API)
const KNOWN_VULNERABLE: Record<string, { severity: "critical" | "high" | "medium"; description: string; fixVersion?: string }> = {
  "node-serialize": {
    severity: "critical",
    description: "Remote code execution via deserialization",
  },
  "serialize-javascript": {
    severity: "high",
    description: "Cross-site scripting via crafted regex",
    fixVersion: "3.1.0",
  },
  "lodash": {
    severity: "high",
    description: "Prototype pollution in older versions",
    fixVersion: "4.17.21",
  },
  "minimist": {
    severity: "high",
    description: "Prototype pollution",
    fixVersion: "1.2.6",
  },
  "axios": {
    severity: "medium",
    description: "SSRF via server-side requests",
    fixVersion: "1.6.0",
  },
  "jsonwebtoken": {
    severity: "high",
    description: "Algorithm confusion vulnerability in older versions",
    fixVersion: "9.0.0",
  },
  "express": {
    severity: "medium",
    description: "Open redirect in older versions",
    fixVersion: "4.19.2",
  },
  "yaml": {
    severity: "critical",
    description: "Code execution via yaml.load unsafe",
    fixVersion: "2.0.0",
  },
};

// Packages that are suspicious or commonly typosquatted
const SUSPICIOUS_PACKAGES = [
  "crossenv", // typosquat of cross-env
  "event-stream", // known supply chain attack
  "flatmap-stream", // part of event-stream attack
  "eslint-scope", // known compromised version
  "electron-native-notify", // known malware
  "discord.js-user", // typosquat
  "colors-js", // typosquat of colors
  "node-ipc-2", // typosquat
];

export function analyzeDependencies(
  files: Map<string, string>
): FindingData[] {
  const findings: FindingData[] = [];

  const packageJsonContent = files.get("package.json");
  if (!packageJsonContent) return findings;

  try {
    const pkg = JSON.parse(packageJsonContent);
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    // Check for known vulnerable packages
    for (const [name, versionRange] of Object.entries(allDeps)) {
      const version = String(versionRange);
      const known = KNOWN_VULNERABLE[name];

      if (known) {
        // If fixVersion exists, check if current version might be vulnerable
        if (known.fixVersion && isVersionPotentiallyFixed(version, known.fixVersion)) {
          continue;
        }

        findings.push({
          vulnerability_id: 3,
          severity: known.severity,
          category: "supply-chain",
          title: `Vulnerable Package: ${name}`,
          description_technical: known.description,
          file_path: "package.json",
          code_snippet: `"${name}": "${version}"`,
          fix_description: known.fixVersion
            ? `Update to version ${known.fixVersion} or later`
            : "Remove this package and find a secure alternative",
          owasp_ref: "A06:2021",
          status: "open",
          confidence: known.fixVersion ? "medium" : "high",
        });
      }

      // Check for suspicious packages
      if (SUSPICIOUS_PACKAGES.includes(name)) {
        findings.push({
          vulnerability_id: 137,
          severity: "high",
          category: "supply-chain",
          title: `Suspicious Package: ${name}`,
          description_technical: "This package is known to be malicious or a typosquat of a popular package",
          file_path: "package.json",
          code_snippet: `"${name}": "${version}"`,
          fix_description: "Remove this package immediately and scan for compromises",
          status: "open",
          confidence: "high",
        });
      }
    }

    // Check for unpinned dependencies (using ^ or ~)
    const deps = pkg.dependencies || {};
    let unpinnedCount = 0;
    for (const [, versionRange] of Object.entries(deps)) {
      const version = String(versionRange);
      if (version.startsWith("^") || version.startsWith("~") || version === "*" || version === "latest") {
        unpinnedCount++;
      }
    }
    // Only flag if most deps are unpinned (common enough to not be noise)
    if (unpinnedCount > 5 && unpinnedCount === Object.keys(deps).length) {
      findings.push({
        vulnerability_id: 60,
        severity: "medium",
        category: "supply-chain",
        title: "All Dependencies Use Ranges Instead of Exact Versions",
        file_path: "package.json",
        code_snippet: `${unpinnedCount} dependencies use ^ or ~ version ranges`,
        fix_description: "Pin exact versions in package.json for reproducible builds",
        status: "open",
        confidence: "low",
      });
    }

  } catch {
    // Invalid JSON - skip
  }

  return findings;
}

function isVersionPotentiallyFixed(
  currentRange: string,
  fixVersion: string
): boolean {
  // Simple heuristic: extract version numbers and compare
  const current = extractVersion(currentRange);
  if (!current) return false;

  const fix = fixVersion.split(".").map(Number);
  const cur = current.split(".").map(Number);

  for (let i = 0; i < 3; i++) {
    if ((cur[i] || 0) > (fix[i] || 0)) return true;
    if ((cur[i] || 0) < (fix[i] || 0)) return false;
  }
  return true; // equal versions = fixed
}

function extractVersion(versionRange: string): string | null {
  // Handle full semver: ^4.17.21, ~4.17.21, >=4.17.21, 4.17.21
  const fullMatch = versionRange.match(/(\d+\.\d+\.\d+)/);
  if (fullMatch) return fullMatch[1];

  // Handle partial: ^4.17, ~4.17 → treat as 4.17.0
  const partialMatch = versionRange.match(/(\d+\.\d+)/);
  if (partialMatch) return `${partialMatch[1]}.0`;

  // Handle major only: ^4 → treat as 4.0.0
  const majorMatch = versionRange.match(/(\d+)/);
  if (majorMatch) return `${majorMatch[1]}.0.0`;

  return null;
}
