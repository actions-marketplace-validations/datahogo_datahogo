// Scan orchestrator - runs all engines in parallel and aggregates results

import { runSecretsEngine } from "./engines/secrets.js";
import { analyzePatterns } from "./engines/patterns.js";
import { analyzeDependencies } from "./engines/dependencies.js";
import { analyzeConfig } from "./engines/config.js";
import { scanUrl } from "./engines/url-scanner.js";
import { analyzeDbRules } from "./engines/db-rules.js";
import { runGitleaks } from "./engines/gitleaks.js";
import { runSemgrep } from "./engines/semgrep.js";
import { runNpmAudit } from "./engines/npm-audit.js";
import { runDast } from "./engines/dast.js";
import { analyzeGitHubActions } from "./engines/github-actions.js";
import type { FindingData, FindingContext, FindingConfidence, EngineResult, Severity } from "./engines/types.js";
import type { ScanLog, ScanResult as AgentScanResult } from "./scanning/types.js";
import { runMultiTechScan } from "./scanning/orchestrator.js";
import { classifyFindings } from "./utils/context-classifier.js";
import { postProcessFindings } from "./utils/post-processor.js";
import { detectTechnologies } from "./scanning/tech-detector.js";

export interface ScanParams {
  files: Map<string, string>;
  repoDir?: string;
  appUrl?: string;
  dbRulesInput?: string;
}

export interface ScanResult {
  findings: FindingData[];
  engineResults: EngineResult[];
  score: number;
  summary: {
    // These counts are PRODUCTION-ONLY (what the user sees)
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    // All findings including non-production (for logs/debugging)
    allFindings: number;
    production: number;
    nonProduction: number;
    byContext: Record<string, number>;
    // Post-processor classification counts (production findings only)
    actionable: number;
    informational: number;
  };
  failedEngines: string[];
  durationMs: number;
  scanLog?: ScanLog;
}

export async function runScan(params: ScanParams): Promise<ScanResult> {
  const startTime = Date.now();
  const engineResults: EngineResult[] = [];
  let scanLog: ScanLog | undefined;

  // Run code analysis engines in parallel
  const codeEnginePromises = [
    // Regex-based engines (always run, work on Map<string, string>)
    runEngine("secrets", () => runSecretsEngine(params.files)),
    runEngine("patterns", () => analyzePatterns(params.files)),
    runEngine("dependencies", () => analyzeDependencies(params.files)),
    runEngine("config", () => analyzeConfig(params.files)),
    runEngine("github-actions", () => analyzeGitHubActions(params.files)),
    // Multi-tech agents (Python, Go, Java, PHP, C#, Mobile, Supabase).
    // The javascript-agent is excluded: it is an adapter around the legacy
    // engines above and would duplicate every JS finding.
    runEngine("multi-tech-agents", async () => {
      const report = await runMultiTechScan(params.files, { exclude: ["javascript-agent"] });
      scanLog = report.scanLog;
      return report.results.map(agentResultToFinding);
    }, 120_000),
    // External tool engines (only when filesystem is available)
    ...(params.repoDir ? [
      runEngine("gitleaks", () => runGitleaks(params.repoDir!)),
      runEngine("semgrep", () => runSemgrep(params.repoDir!)),
      runEngine("npm-audit", () => runNpmAudit(params.repoDir!, params.files)),
    ] : []),
  ];

  // Conditionally run URL scanner + DAST
  if (params.appUrl) {
    codeEnginePromises.push(
      runEngine("url-scanner", () => scanUrl(params.appUrl!)),
      runEngine("dast", () => runDast(params.appUrl!), 180_000) // DAST needs more time
    );
  }

  // Conditionally run DB rules parser
  if (params.dbRulesInput) {
    codeEnginePromises.push(
      runEngine("db-rules", () =>
        analyzeDbRules(params.dbRulesInput!, "auto")
      )
    );
  }

  const results = await Promise.allSettled(codeEnginePromises);

  for (const result of results) {
    if (result.status === "fulfilled") {
      engineResults.push(result.value);
    }
  }

  // Aggregate findings
  const allFindings: FindingData[] = [];
  const failedEngines: string[] = [];

  for (const engineResult of engineResults) {
    if (engineResult.error) {
      failedEngines.push(engineResult.engine);
    }
    allFindings.push(...engineResult.findings);
  }

  // Deduplicate findings by vulnerability_id + file_path + line_number
  const deduplicated = deduplicateFindings(allFindings);

  // Classify findings by context (production, test, example, etc.)
  const classified = classifyFindings(deduplicated);

  // Post-process: framework suppressions, cross-engine dedup, contextual notes,
  // and actionable/informational classification.
  const technologies = detectTechnologies(params.files).technologies;
  const postProcessed = postProcessFindings(classified, technologies);

  // Calculate score (only production findings penalize; framework requirements skipped)
  const score = calculateScore(postProcessed);

  // Build summary with context breakdown
  const summary = buildSummary(postProcessed);

  return {
    findings: postProcessed,
    engineResults,
    score,
    summary,
    failedEngines,
    durationMs: Date.now() - startTime,
    scanLog,
  };
}

// Agent findings carry their own title/description/fix inline, so they don't
// map to the numeric vulnerability catalog. We derive a stable synthetic id
// (>= 100000, outside the catalog range) from the checkId so deduplication
// by vulnerability_id + file + line keeps working.
function syntheticVulnId(key: string): number {
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = (hash * 31 + key.charCodeAt(i)) | 0;
  }
  return 100000 + (Math.abs(hash) % 100000);
}

function agentResultToFinding(result: AgentScanResult): FindingData {
  const category = result.checkId?.split(":")[0] ?? "multi-tech";
  return {
    vulnerability_id: syntheticVulnId(result.checkId ?? result.title),
    severity: result.severity.toLowerCase() as Severity,
    category,
    title: result.title,
    description_simple: result.description,
    file_path: result.file,
    line_number: result.line,
    fix_description: result.fix,
    owasp_ref: result.cwe,
    status: "open",
    confidence: result.confidence,
  };
}

const ENGINE_TIMEOUT_MS = 90_000; // 90s default per-engine safety timeout

async function runEngine(
  name: string,
  fn: () => FindingData[] | Promise<FindingData[]>,
  timeoutMs: number = ENGINE_TIMEOUT_MS
): Promise<EngineResult> {
  const startTime = Date.now();
  try {
    const findings = await Promise.race([
      fn(),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Engine ${name} timed out after ${timeoutMs}ms`)),
          timeoutMs
        )
      ),
    ]);
    return {
      engine: name,
      findings,
      durationMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      engine: name,
      findings: [],
      error: error instanceof Error ? error.message : "Unknown error",
      durationMs: Date.now() - startTime,
    };
  }
}

function deduplicateFindings(findings: FindingData[]): FindingData[] {
  // Fuzzy dedup: same vulnerability_id + file_path within ±2 lines = duplicate.
  // This handles Semgrep (AST node start) vs regex (first match line) differences.
  const result: FindingData[] = [];
  const seen = new Map<string, number[]>(); // baseKey → array of seen line numbers

  for (const finding of findings) {
    const baseKey = `${finding.vulnerability_id}:${finding.file_path ?? ""}`;
    const lineNum = finding.line_number ?? 0;

    const seenLines = seen.get(baseKey);
    if (seenLines) {
      const isDuplicate = seenLines.some((l) => Math.abs(l - lineNum) <= 2);
      if (isDuplicate) continue;
      seenLines.push(lineNum);
    } else {
      seen.set(baseKey, [lineNum]);
    }

    result.push(finding);
  }

  return result;
}

const CONTEXT_PENALTY: Record<FindingContext, number> = {
  production: 1.0,
  config: 0,    // Config/scripts/migrations are infrastructure, not production code
  test: 0,
  example: 0,
  rule: 0,
  vendored: 0,
};

const CONFIDENCE_MULTIPLIER: Record<FindingConfidence, number> = {
  high: 1.0,    // Semgrep AST-based, high confidence
  medium: 0.7,  // Regex pattern with good specificity
  low: 0.3,     // Absence checks, broad regex matches
};

function calculateScore(findings: FindingData[]): number {
  const penalties: Record<string, number> = {
    critical: 15,
    high: 10,
    medium: 5,
    low: 2,
    info: 0,
  };

  let score = 100;
  for (const finding of findings) {
    if (finding.status === "open") {
      // Framework requirements are expected behaviour — do not penalize the score.
      if (finding.is_framework_requirement) continue;

      const ctx = finding.context ?? "production";
      const contextMul = CONTEXT_PENALTY[ctx] ?? 1;
      const confidenceMul = CONFIDENCE_MULTIPLIER[finding.confidence ?? "medium"];
      score -= (penalties[finding.severity] ?? 0) * contextMul * confidenceMul;
    }
  }
  return Math.max(0, Math.round(score));
}

function buildSummary(findings: FindingData[]): ScanResult["summary"] {
  const summary: ScanResult["summary"] = {
    total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0,
    allFindings: 0,
    production: 0, nonProduction: 0,
    byContext: {},
    actionable: 0,
    informational: 0,
  };

  for (const finding of findings) {
    summary.allFindings++;
    const ctx = finding.context ?? "production";

    if (ctx === "production") {
      summary.production++;

      if (finding.classification === "informational") {
        summary.informational++;
      } else {
        // Only actionable findings count toward headline totals and severity breakdown
        summary.actionable++;
        summary.total++;
        if (finding.severity === "critical") summary.critical++;
        else if (finding.severity === "high") summary.high++;
        else if (finding.severity === "medium") summary.medium++;
        else if (finding.severity === "low") summary.low++;
        else if (finding.severity === "info") summary.info++;
      }
    } else {
      summary.nonProduction++;
    }
    summary.byContext[ctx] = (summary.byContext[ctx] ?? 0) + 1;
  }

  return summary;
}
