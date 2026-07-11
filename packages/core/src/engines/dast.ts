// DAST engine - Dynamic Application Security Testing via Nuclei.
// Scans deployed URLs for real vulnerabilities (SQL injection, XSS, SSRF, etc.).
// Only runs when appUrl is provided in scan params.

import { execWithTimeout } from "../utils/exec.js";
import type { FindingData, Severity } from "./types.js";

// Nuclei JSONL output entry
interface NucleiResult {
  "template-id": string;
  "template-url"?: string;
  info: {
    name: string;
    severity: string;
    description?: string;
    tags?: string[];
    reference?: string[];
    classification?: {
      "cve-id"?: string[];
      "cwe-id"?: string[];
    };
  };
  "matched-at": string;
  "matcher-name"?: string;
  type: string;
  host: string;
  "curl-command"?: string;
  "extracted-results"?: string[];
}

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

// Map Nuclei template tags/IDs to our vulnerability catalog
const TAG_TO_VULN_ID: Record<string, number> = {
  sqli: 5,
  "sql-injection": 5,
  xss: 7,
  ssrf: 10,
  lfi: 106,
  rfi: 106,
  rce: 75,
  "command-injection": 75,
  xxe: 72,
  ssti: 76,
  "open-redirect": 119,
  cors: 4,
  csrf: 8,
  idor: 1,
  "path-traversal": 106,
  "file-inclusion": 106,
  "directory-listing": 116,
  "exposed-panel": 116,
  "admin-panel": 116,
  misconfiguration: 4,
  disclosure: 99,
  "information-disclosure": 99,
  "default-login": 77,
  "default-credential": 77,
  "weak-password": 55,
  cve: 3,
  token: 53,
  "api-key": 53,
  debug: 116,
  "source-map": 49,
};

export async function runDast(appUrl: string): Promise<FindingData[]> {
  const args = [
    "-u", appUrl,
    "-jsonl",
    "-severity", "critical,high,medium",
    "-t", "misconfiguration/",
    "-t", "exposed-panels/",
    "-t", "vulnerabilities/",
    "-t", "exposures/",
    "-silent",
    "-no-color",
    "-rate-limit", "100",
    "-timeout", "10",
    "-retries", "1",
    "-no-interactsh", // Don't use out-of-band testing service
    "-disable-update-check",
  ];

  let stdout: string;
  try {
    const result = await execWithTimeout("nuclei", args, {
      timeoutMs: 170_000, // 10s under orchestrator's 180s DAST timeout
      env: { HOME: "/home/worker" }, // Nuclei needs HOME for templates
    });
    stdout = result.stdout;
  } catch (error) {
    // Nuclei may fail for many reasons (missing binary, missing templates,
    // timeout, non-zero exit). Never mark DAST as failed — just return empty.
    console.warn(`[dast] Nuclei failed: ${error instanceof Error ? error.message : error}`);
    return [];
  }

  if (!stdout.trim()) return [];

  const findings: FindingData[] = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    try {
      const result: NucleiResult = JSON.parse(line);
      findings.push(mapNucleiToFinding(result));
    } catch {
      // Skip malformed lines
    }
  }

  return findings;
}

function mapNucleiToFinding(result: NucleiResult): FindingData {
  const severity = SEVERITY_MAP[result.info.severity] ?? "medium";
  const vulnId = resolveVulnerabilityId(result);
  const tags = result.info.tags ?? [];
  const cves = result.info.classification?.["cve-id"] ?? [];
  const cwes = result.info.classification?.["cwe-id"] ?? [];

  const technicalDetails = [
    result.info.description,
    cves.length > 0 ? `CVE: ${cves.join(", ")}` : "",
    cwes.length > 0 ? `CWE: ${cwes.join(", ")}` : "",
    result.info.reference?.length ? `References: ${result.info.reference.join(", ")}` : "",
    `Matched at: ${result["matched-at"]}`,
    tags.length > 0 ? `Tags: ${tags.join(", ")}` : "",
  ].filter(Boolean).join("\n");

  return {
    vulnerability_id: vulnId,
    severity,
    category: "dast",
    title: `[DAST] ${result.info.name}`,
    description_technical: technicalDetails,
    file_path: result["matched-at"],
    code_snippet: result["curl-command"] ?? `Template: ${result["template-id"]}`,
    owasp_ref: mapToOwasp(tags),
    status: "open",
  };
}

function resolveVulnerabilityId(result: NucleiResult): number {
  const tags = result.info.tags ?? [];

  // Check template tags first (most specific)
  for (const tag of tags) {
    const id = TAG_TO_VULN_ID[tag.toLowerCase()];
    if (id) return id;
  }

  // Check template ID for known patterns
  const templateId = result["template-id"].toLowerCase();
  if (templateId.includes("sqli")) return 5;
  if (templateId.includes("xss")) return 7;
  if (templateId.includes("ssrf")) return 10;
  if (templateId.includes("rce")) return 75;
  if (templateId.includes("lfi") || templateId.includes("path-traversal")) return 106;
  if (templateId.includes("redirect")) return 119;
  if (templateId.includes("cve-")) return 3;
  if (templateId.includes("panel") || templateId.includes("admin")) return 116;
  if (templateId.includes("config") || templateId.includes("misconfig")) return 4;

  // Fallback based on type
  if (result.type === "http") return 4; // Security misconfiguration
  return 199; // Generic best practice
}

function mapToOwasp(tags: string[]): string | undefined {
  const tagSet = new Set(tags.map((t) => t.toLowerCase()));
  if (tagSet.has("sqli") || tagSet.has("xss") || tagSet.has("rce") || tagSet.has("xxe") || tagSet.has("ssti")) return "A03:2021";
  if (tagSet.has("ssrf")) return "A10:2021";
  if (tagSet.has("idor") || tagSet.has("open-redirect")) return "A01:2021";
  if (tagSet.has("cve")) return "A06:2021";
  if (tagSet.has("misconfiguration") || tagSet.has("cors")) return "A05:2021";
  if (tagSet.has("default-login") || tagSet.has("default-credential")) return "A07:2021";
  return undefined;
}
