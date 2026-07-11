// Multi-technology scanning architecture — shared types.
// This is the new agent-based system. The existing engines/ directory
// handles the current Next.js-focused scanner and remains untouched.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ScanResult {
  title: string;
  severity: Severity;
  file: string;
  line: number;
  description: string;
  fix: string;
  cwe?: string;
  /** Links this finding back to a CheckDefinition.id for scan log tracking. */
  checkId?: string;
  /**
   * Confidence level for this finding.
   * high   — direct pattern match, no ambiguity (DEBUG=True, pickle.loads with user input)
   * medium — good signal but context-dependent (SQL f-string that might be parameterized)
   * low    — broad match or absence-based (missing auth decorator, Flask CORS default)
   */
  confidence?: "high" | "medium" | "low";
}

export interface AgentMetadata {
  name: string;
  version: string;
  technologies: string[];
}

export interface ScanReport {
  score: number;
  results: ScanResult[];
  techsDetected: string[];
  timestamp: string;
}

/**
 * ScanAgent interface — every technology-specific scanner implements this.
 * Agents are self-contained: they know how to detect their technology
 * and how to scan for vulnerabilities within it.
 */
export interface ScanAgent {
  /** Check if this agent's technology exists in the repo. */
  detect(files: Map<string, string>): Promise<boolean>;

  /** Run the security scan. Only called if detect() returned true. */
  scan(files: Map<string, string>): Promise<ScanResult[]>;

  /** Return metadata about this agent (name, version, supported techs). */
  getMetadata(): AgentMetadata;

  /** Return the list of checks this agent can perform (for scan log). */
  getChecks?(): CheckDefinition[];
}

/** Technology identifiers returned by TechDetector. */
export type Technology =
  | "nodejs"
  | "nextjs"
  | "react"
  | "express"
  | "fastify"
  | "hono"
  | "koa"
  | "nestjs"
  | "python"
  | "django"
  | "flask"
  | "fastapi"
  | "go"
  | "java"
  | "spring"
  | "kotlin"
  | "php"
  | "laravel"
  | "ruby"
  | "rails"
  | "dart"
  | "flutter"
  | "dotnet"
  | "rust"
  | "docker"
  | "firebase"
  | "supabase"
  | "react-native"
  | "expo"
  | "prisma"
  | "mongodb"
  | "redis"
  | "graphql"
  | "stripe"
  | "vue"
  | "angular"
  | "svelte";

// --- Scan Log types ---

/** A check that an agent can perform. */
export interface CheckDefinition {
  id: string;
  name: string;
  severity: Severity;
}

/** Result of a single check after a scan. */
export interface CheckResult {
  checkId: string;
  status: "pass" | "fail";
  findingCount: number;
}

/** Log entry for one agent's execution. */
export interface AgentLogEntry {
  agentName: string;
  agentVersion: string;
  technologies: string[];
  status: "completed" | "error" | "timeout" | "skipped";
  durationMs: number;
  checkResults: CheckResult[];
  totalChecks: number;
  passed: number;
  failed: number;
  error?: string;
}

/** Complete scan execution log. */
export interface ScanLog {
  technologiesDetected: string[];
  technologyDetails: Record<string, string>;
  agentsMatched: string[];
  agentsConfirmed: string[];
  agentLogs: AgentLogEntry[];
  totalDurationMs: number;
  summary: {
    totalChecks: number;
    passed: number;
    failed: number;
  };
}
