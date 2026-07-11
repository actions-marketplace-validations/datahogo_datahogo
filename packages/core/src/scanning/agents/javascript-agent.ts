// JavaScript ecosystem security scanner agent.
// An ADAPTER that wraps the existing engines (patterns, secrets, dependencies, config)
// and maps their FindingData[] output to the agent-based ScanResult[] interface.
// Called only when the repo contains a package.json.

import type { ScanAgent, ScanResult, AgentMetadata, Severity, CheckDefinition } from "../types.js";
import type { FindingData } from "../../engines/types.js";
import { analyzePatterns } from "../../engines/patterns.js";
import { runSecretsEngine } from "../../engines/secrets.js";
import { analyzeDependencies } from "../../engines/dependencies.js";
import { analyzeConfig } from "../../engines/config.js";

export class JavaScriptScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    return files.has("package.json");
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const patternFindings: FindingData[] = analyzePatterns(files);
    const secretFindings: FindingData[] = runSecretsEngine(files);
    const depFindings: FindingData[] = analyzeDependencies(files);
    const configFindings: FindingData[] = analyzeConfig(files);

    return [
      ...patternFindings.map((f) => mapFindingToScanResult(f, "js:patterns")),
      ...secretFindings.map((f) => mapFindingToScanResult(f, "js:secrets")),
      ...depFindings.map((f) => mapFindingToScanResult(f, "js:dependencies")),
      ...configFindings.map((f) => mapFindingToScanResult(f, "js:config")),
    ];
  }

  getMetadata(): AgentMetadata {
    return {
      name: "javascript-agent",
      version: "1.0.0",
      technologies: [
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
      ],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      { id: "js:patterns", name: "Code pattern analysis (250+ rules)", severity: "HIGH" },
      { id: "js:secrets", name: "Secrets and credentials detection", severity: "CRITICAL" },
      { id: "js:dependencies", name: "Dependency vulnerability analysis", severity: "HIGH" },
      { id: "js:config", name: "Configuration file analysis", severity: "MEDIUM" },
    ];
  }
}

/**
 * Map a FindingData (lowercase severity, optional fields) to a ScanResult
 * (uppercase severity, required fields with defaults).
 * The checkId ties the result back to a CheckDefinition for scan log tracking.
 */
function mapFindingToScanResult(finding: FindingData, checkId: string): ScanResult {
  const result: ScanResult = {
    title: finding.title,
    severity: finding.severity.toUpperCase() as Severity,
    file: finding.file_path ?? "",
    line: finding.line_number ?? 1,
    description:
      finding.description_technical ??
      finding.description_simple ??
      finding.title,
    fix:
      finding.fix_description ??
      finding.fix_code ??
      "Review and fix this issue",
    checkId,
  };

  if (finding.owasp_ref !== undefined) {
    result.cwe = finding.owasp_ref;
  }

  return result;
}
