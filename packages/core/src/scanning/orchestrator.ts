// Multi-technology scan orchestrator.
// Uses TechDetector to identify technologies, instantiates the relevant
// ScanAgents, runs them in parallel, and aggregates into a ScanReport.

import { detectTechnologies } from "./tech-detector.js";
import { PythonScanAgent } from "./agents/python-agent.js";
import { JavaScriptScanAgent } from "./agents/javascript-agent.js";
import { GoScanAgent } from "./agents/go-agent.js";
import { JavaScanAgent } from "./agents/java-agent.js";
import { PHPScanAgent } from "./agents/php-agent.js";
import { CSharpScanAgent } from "./agents/csharp-agent.js";
import { MobileScanAgent } from "./agents/mobile-agent.js";
import { SupabaseScanAgent } from "./agents/supabase-agent.js";
import type {
  ScanAgent,
  ScanResult,
  ScanReport,
  Severity,
  ScanLog,
  AgentLogEntry,
  CheckResult,
} from "./types.js";

const SEVERITY_PENALTY: Record<Severity, number> = {
  CRITICAL: 15,
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

const AGENT_TIMEOUT_MS = 90_000; // 90s per agent

interface AgentRunResult {
  agentName: string;
  results: ScanResult[];
  durationMs: number;
  error?: string;
}

/**
 * Registry of all available scan agents.
 * Agents register themselves here; the orchestrator picks which ones to run.
 */
const agentRegistry: ScanAgent[] = [];

/** Register a scan agent. Called by each agent module on import. */
export function registerAgent(agent: ScanAgent): void {
  agentRegistry.push(agent);
}

/** Get all registered agents (for testing). */
export function getRegisteredAgents(): readonly ScanAgent[] {
  return agentRegistry;
}

/** Clear registry (for testing). */
export function clearAgentRegistry(): void {
  agentRegistry.length = 0;
}

// Register built-in agents
registerAgent(new PythonScanAgent());
registerAgent(new JavaScriptScanAgent());
registerAgent(new GoScanAgent());
registerAgent(new JavaScanAgent());
registerAgent(new PHPScanAgent());
registerAgent(new CSharpScanAgent());
registerAgent(new MobileScanAgent());
registerAgent(new SupabaseScanAgent());

/**
 * Run a full multi-technology scan.
 *
 * 1. Detect technologies in the repo
 * 2. Filter agents to only those whose technologies match
 * 3. Run matching agents in parallel (with timeout)
 * 4. Deduplicate and aggregate results into a ScanReport
 */
export async function runMultiTechScan(
  files: Map<string, string>,
  options: { exclude?: string[] } = {},
): Promise<ScanReport & { agentResults: AgentRunResult[]; scanLog: ScanLog }> {
  const startTime = Date.now();
  const detection = detectTechnologies(files);
  const excluded = options.exclude ?? [];

  // Find agents that support at least one detected technology
  const matchingAgents = agentRegistry.filter((agent) => {
    const meta = agent.getMetadata();
    if (excluded.includes(meta.name)) return false;
    return meta.technologies.some((tech) => detection.technologies.includes(tech as never));
  });
  const matchedNames = matchingAgents.map((a) => a.getMetadata().name);

  // Run detect() on matching agents to confirm (agents may have stricter checks)
  const confirmedAgents: ScanAgent[] = [];
  await Promise.all(
    matchingAgents.map(async (agent) => {
      try {
        const detected = await agent.detect(files);
        if (detected) confirmedAgents.push(agent);
      } catch {
        // If detect fails, skip this agent
      }
    }),
  );
  const confirmedNames = confirmedAgents.map((a) => a.getMetadata().name);

  // Run scan() on confirmed agents in parallel with timeout
  const agentResults = await Promise.all(
    confirmedAgents.map((agent) => runAgentWithTimeout(agent, files)),
  );

  // Build agent logs by diffing getChecks() against findings
  const agentLogs: AgentLogEntry[] = agentResults.map((ar) => {
    const agent = confirmedAgents.find((a) => a.getMetadata().name === ar.agentName);
    const meta = agent?.getMetadata();
    const checks = agent?.getChecks?.() ?? [];

    const checkResults: CheckResult[] = checks.map((check) => {
      const count = ar.results.filter((r) => r.checkId === check.id).length;
      return {
        checkId: check.id,
        status: count > 0 ? ("fail" as const) : ("pass" as const),
        findingCount: count,
      };
    });

    const passed = checkResults.filter((c) => c.status === "pass").length;
    const failed = checkResults.filter((c) => c.status === "fail").length;

    return {
      agentName: ar.agentName,
      agentVersion: meta?.version ?? "unknown",
      technologies: meta?.technologies ?? [],
      status: ar.error
        ? ar.error.includes("timed out") ? "timeout" as const : "error" as const
        : "completed" as const,
      durationMs: ar.durationMs,
      checkResults,
      totalChecks: checkResults.length,
      passed,
      failed,
      error: ar.error,
    };
  });

  const scanLog: ScanLog = {
    technologiesDetected: detection.technologies,
    technologyDetails: Object.fromEntries(detection.details),
    agentsMatched: matchedNames,
    agentsConfirmed: confirmedNames,
    agentLogs,
    totalDurationMs: Date.now() - startTime,
    summary: {
      totalChecks: agentLogs.reduce((s, a) => s + a.totalChecks, 0),
      passed: agentLogs.reduce((s, a) => s + a.passed, 0),
      failed: agentLogs.reduce((s, a) => s + a.failed, 0),
    },
  };

  // Aggregate all results
  const allResults = agentResults.flatMap((ar) => ar.results);
  const deduplicated = deduplicateResults(allResults);
  const score = calculateScore(deduplicated);

  return {
    score,
    results: deduplicated,
    techsDetected: detection.technologies,
    timestamp: new Date().toISOString(),
    agentResults,
    scanLog,
  };
}

async function runAgentWithTimeout(
  agent: ScanAgent,
  files: Map<string, string>,
): Promise<AgentRunResult> {
  const meta = agent.getMetadata();
  const start = Date.now();

  try {
    const results = await Promise.race([
      agent.scan(files),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Agent ${meta.name} timed out after ${AGENT_TIMEOUT_MS}ms`)),
          AGENT_TIMEOUT_MS,
        ),
      ),
    ]);

    return {
      agentName: meta.name,
      results,
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      agentName: meta.name,
      results: [],
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function deduplicateResults(results: ScanResult[]): ScanResult[] {
  const seen = new Map<string, number[]>();
  const deduped: ScanResult[] = [];

  for (const result of results) {
    const key = `${result.title}:${result.file}`;
    const seenLines = seen.get(key);

    if (seenLines) {
      if (seenLines.some((l) => Math.abs(l - result.line) <= 2)) continue;
      seenLines.push(result.line);
    } else {
      seen.set(key, [result.line]);
    }

    deduped.push(result);
  }

  return deduped;
}

function calculateScore(results: ScanResult[]): number {
  let score = 100;
  for (const result of results) {
    score -= SEVERITY_PENALTY[result.severity] ?? 0;
  }
  return Math.max(0, score);
}
