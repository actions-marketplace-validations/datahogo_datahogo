// Semgrep engine - runs Semgrep binary for AST-based code analysis.
// Uses both custom rules (worker/src/rules/) and community rulesets.
// Falls back gracefully if semgrep is not installed (regex patterns engine covers basics).

import { execWithTimeout } from "../utils/exec.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FindingData, Severity } from "./types.js";

// Resolve rules directory relative to this file's compiled location (dist/engines/)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_DIR = path.resolve(__dirname, "../rules");

// Community rulesets to use alongside custom rules
const COMMUNITY_CONFIGS = [
  "p/javascript",
  "p/typescript",
  "p/owasp-top-ten",
  "p/react",
  "p/nextjs",
];

// Semgrep JSON output structure
interface SemgrepOutput {
  results: SemgrepResult[];
  errors: SemgrepError[];
  version: string;
}

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number; offset: number };
  end: { line: number; col: number; offset: number };
  extra: {
    message: string;
    severity: string;
    lines: string;
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepError {
  message: string;
  level: string;
}

// Map Semgrep severity strings to our severity levels
const SEVERITY_MAP: Record<string, Severity> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
};

// Map community rule prefixes to our vulnerability IDs
const COMMUNITY_RULE_MAP: Record<string, { id: number; category: string }> = {
  // OWASP
  "owasp.": { id: 1, category: "web-owasp" },
  "javascript.lang.security.audit.sqli": { id: 5, category: "web-owasp" },
  "javascript.lang.security.audit.xss": { id: 7, category: "web-owasp" },
  "javascript.lang.security.audit.eval": { id: 61, category: "vibecoding" },
  "javascript.lang.security.audit.crypto": { id: 2, category: "web-owasp" },
  "javascript.lang.security.audit.path-traversal": { id: 106, category: "files" },
  "javascript.lang.security.audit.command-injection": { id: 75, category: "injection" },
  "javascript.lang.security.audit.prototype-pollution": { id: 128, category: "javascript" },
  // React
  "react.": { id: 46, category: "react-nextjs" },
  "typescript.react.security": { id: 46, category: "react-nextjs" },
  // Next.js
  "nextjs.": { id: 46, category: "react-nextjs" },
  // JWT
  "javascript.jsonwebtoken": { id: 56, category: "vibecoding" },
  "javascript.jwt": { id: 56, category: "vibecoding" },
  // Express/Node
  "javascript.express": { id: 1, category: "web-owasp" },
  "javascript.lang.security": { id: 128, category: "javascript" },
  // Crypto
  "javascript.lang.security.audit.weak-crypto": { id: 2, category: "cryptography" },
};

export async function runSemgrep(repoDir: string): Promise<FindingData[]> {
  const args = [
    "scan",
    "--json",
    "--config", RULES_DIR,
    ...COMMUNITY_CONFIGS.flatMap((config) => ["--config", config]),
    "--metrics=off",
    "--max-target-bytes", "500000",
    "--timeout", "30", // Per-rule timeout in seconds
    "--quiet", // Suppress progress output
    repoDir,
  ];

  const { stdout, stderr } = await execWithTimeout("semgrep", args, {
    timeoutMs: 60_000,
    maxBuffer: 20 * 1024 * 1024, // 20MB — Semgrep output can be large
  });

  if (!stdout.trim()) return [];

  let output: SemgrepOutput;
  try {
    output = JSON.parse(stdout);
  } catch {
    // If JSON parsing fails, try to extract JSON from mixed output
    const jsonStart = stdout.indexOf("{");
    if (jsonStart === -1) return [];
    try {
      output = JSON.parse(stdout.slice(jsonStart));
    } catch {
      return [];
    }
  }

  if (!output.results || !Array.isArray(output.results)) return [];

  return output.results.map((result) => mapResultToFinding(result, repoDir));
}

function mapResultToFinding(result: SemgrepResult, repoDir: string): FindingData {
  // Check for our custom datahogo_id in rule metadata
  const metadata = result.extra.metadata;
  const datahogoId = metadata?.datahogo_id as number | undefined;

  // Make file path relative to repo root
  const filePath = result.path.startsWith(repoDir)
    ? result.path.slice(repoDir.length + 1)
    : result.path;

  const severity = SEVERITY_MAP[result.extra.severity] ?? "medium";

  if (datahogoId) {
    // Custom rule with explicit mapping
    const category = (metadata?.datahogo_category as string) ?? "web-owasp";
    const owasp = metadata?.owasp_ref as string | undefined;

    return {
      vulnerability_id: datahogoId,
      severity,
      category,
      title: result.extra.message.split(".")[0] || result.check_id,
      description_technical: result.extra.message,
      file_path: filePath,
      line_number: result.start.line,
      code_snippet: result.extra.lines,
      owasp_ref: owasp,
      status: "open",
    };
  }

  // Community rule — map by check_id prefix
  const mapping = findCommunityMapping(result.check_id);

  return {
    vulnerability_id: mapping.id,
    severity,
    category: mapping.category,
    title: formatTitle(result.check_id, result.extra.message),
    description_technical: `[Semgrep: ${result.check_id}] ${result.extra.message}`,
    file_path: filePath,
    line_number: result.start.line,
    code_snippet: result.extra.lines,
    status: "open",
  };
}

function findCommunityMapping(checkId: string): { id: number; category: string } {
  // Try increasingly specific prefix matches
  for (const [prefix, mapping] of Object.entries(COMMUNITY_RULE_MAP)) {
    if (checkId.startsWith(prefix) || checkId.includes(prefix)) {
      return mapping;
    }
  }

  // Fallback: categorize by keywords in the check ID
  const lower = checkId.toLowerCase();
  if (lower.includes("sqli") || lower.includes("sql-injection")) return { id: 5, category: "web-owasp" };
  if (lower.includes("xss") || lower.includes("cross-site")) return { id: 7, category: "web-owasp" };
  if (lower.includes("ssrf")) return { id: 10, category: "web-owasp" };
  if (lower.includes("command") || lower.includes("exec")) return { id: 75, category: "injection" };
  if (lower.includes("path-traversal")) return { id: 106, category: "files" };
  if (lower.includes("auth")) return { id: 1, category: "web-owasp" };
  if (lower.includes("crypto") || lower.includes("hash")) return { id: 2, category: "cryptography" };
  if (lower.includes("jwt")) return { id: 56, category: "vibecoding" };
  if (lower.includes("cors")) return { id: 4, category: "web-owasp" };
  if (lower.includes("secret") || lower.includes("key") || lower.includes("token")) return { id: 53, category: "vibecoding" };

  // Generic fallback
  return { id: 199, category: "best-practices" };
}

function formatTitle(checkId: string, message: string): string {
  // Use first sentence of message if available
  const firstSentence = message.split(/[.!]/)[0];
  if (firstSentence && firstSentence.length > 10 && firstSentence.length < 100) {
    return firstSentence;
  }
  // Fallback: humanize the check_id
  return checkId
    .split(/[.-]/)
    .slice(-3)
    .join(" ")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
