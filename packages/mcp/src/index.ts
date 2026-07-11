#!/usr/bin/env node
// @datahogo/mcp — exposes the Data Hogo scan engine as MCP tools.
//
// Runs entirely on the caller's machine (stdio transport): the host LLM
// (Claude, Cursor, etc.) does the explaining and fixing for free — this
// server only returns structured findings, never calls any AI API itself.

import path from "node:path";
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runScan, detectTechnologies, type FindingData, type Severity } from "@datahogo/core";
import { walkDirectory } from "./walk.js";
import { isProductionActionable, sortBySeverity, severityCounts, formatSeverityCounts, location } from "./format.js";

const require = createRequire(import.meta.url);
const VERSION: string = require("../package.json").version;

const MAX_FINDINGS_RETURNED = 20;

const SEVERITY_ENUM = z.enum(["critical", "high", "medium", "low", "info"]);
const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Findings from the most recent scan_project call, keyed by the compact id
// handed out in that call's response. In-memory only — scoped to this
// process's lifetime, which matches one stdio client connection.
const findingsCache = new Map<string, FindingData>();

function cacheFindings(findings: FindingData[]): void {
  findingsCache.clear();
  findings.forEach((f, i) => findingsCache.set(String(i + 1), f));
}

const server = new McpServer({ name: "datahogo", version: VERSION });

server.registerTool(
  "scan_project",
  {
    title: "Scan a local project for security issues",
    description:
      "Scans a local directory with Data Hogo's open-source security engine (300+ checks across JS/TS, Python, Go, Java, PHP, C#, mobile, Supabase). " +
      "Runs entirely locally — nothing is uploaded anywhere. Returns a security score and the highest-severity findings. " +
      "Call get_finding with a finding_id from the response to see full detail (description, fix) for a specific finding.",
    inputSchema: {
      path: z.string().default(".").describe("Directory to scan, absolute or relative to the current working directory."),
      min_severity: SEVERITY_ENUM.optional().describe("Only include findings at or above this severity. Defaults to showing everything down to low."),
    },
  },
  async ({ path: targetPath, min_severity }) => {
    const rootDir = path.resolve(targetPath ?? ".");
    const { files } = await walkDirectory(rootDir);

    if (files.size === 0) {
      return { content: [{ type: "text", text: `No scannable files found under ${rootDir}.` }] };
    }

    const techs = detectTechnologies(files).technologies;
    const result = await runScan({ files, repoDir: rootDir });

    const actionable = result.findings.filter(isProductionActionable);
    const threshold = min_severity ? SEVERITY_RANK[min_severity] : 1; // default: hide "info" noise
    const filtered = sortBySeverity(actionable).filter((f) => SEVERITY_RANK[f.severity] >= threshold);

    cacheFindings(filtered);

    const shown = filtered.slice(0, MAX_FINDINGS_RETURNED);
    const lines: string[] = [];
    lines.push(`Security Score: ${result.score}/100`);
    lines.push(`Stack: ${techs.join(", ") || "unknown"} — ${files.size} files scanned in ${result.durationMs}ms`);
    lines.push(`Findings by severity: ${formatSeverityCounts(severityCounts(filtered))}`);
    if (result.failedEngines.length > 0) {
      lines.push(`Engines that could not run: ${result.failedEngines.join(", ")}`);
    }
    lines.push("");

    if (shown.length === 0) {
      lines.push("No actionable findings at or above the requested severity.");
    } else {
      for (let i = 0; i < shown.length; i++) {
        const f = shown[i];
        lines.push(`[${i + 1}] ${f.severity.toUpperCase()} — ${f.title} (${location(f)})`);
      }
      if (filtered.length > shown.length) {
        lines.push(`... and ${filtered.length - shown.length} more. Re-run with a higher min_severity to narrow the list.`);
      }
      lines.push("");
      lines.push("Call get_finding with one of the numbers above to see the full description and suggested fix.");
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.registerTool(
  "get_finding",
  {
    title: "Get full detail for a specific finding",
    description: "Returns the full description, code location, and suggested fix for a finding_id returned by scan_project.",
    inputSchema: {
      finding_id: z.string().describe("The bracketed number shown next to a finding in the scan_project response, e.g. \"3\"."),
    },
  },
  async ({ finding_id }) => {
    const finding = findingsCache.get(finding_id);
    if (!finding) {
      return {
        content: [{ type: "text", text: `No finding with id "${finding_id}". Call scan_project first, then use one of the ids it returns.` }],
        isError: true,
      };
    }

    const description = finding.description_technical || finding.description_simple;
    const lines = [
      `${finding.severity.toUpperCase()} — ${finding.title}`,
      `Location: ${location(finding)}`,
      finding.owasp_ref ? `OWASP: ${finding.owasp_ref}` : undefined,
      description ? "" : undefined,
      description,
    ];
    if (finding.code_snippet) {
      lines.push(
        "",
        description ? "Code:" : "Code (explain what's wrong here and why, based on the title above):",
        "```",
        finding.code_snippet,
        "```"
      );
    }
    if (finding.fix_description || finding.fix_code) {
      lines.push("", "Suggested fix:");
      if (finding.fix_description) lines.push(finding.fix_description);
      if (finding.fix_code) lines.push("```", finding.fix_code, "```");
    }

    return { content: [{ type: "text", text: lines.filter((l) => l !== undefined).join("\n") }] };
  }
);

server.registerTool(
  "scan_url",
  {
    title: "Scan a deployed URL for security issues",
    description: "Checks a live URL for missing security headers, weak CSP, insecure cookies, mixed content, and exposed source maps/endpoints.",
    inputSchema: {
      url: z.string().url().describe("The URL to scan, including protocol (https://...)."),
    },
  },
  async ({ url }) => {
    const result = await runScan({ files: new Map(), appUrl: url });
    const findings = sortBySeverity(result.findings);

    if (findings.length === 0) {
      return { content: [{ type: "text", text: `No issues found scanning ${url}.` }] };
    }

    const lines = findings.map(
      (f) => `${f.severity.toUpperCase()} — ${f.title}${f.description_technical ? `: ${f.description_technical}` : ""}`
    );
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.registerTool(
  "check_db_rules",
  {
    title: "Check Supabase RLS policies or Firebase security rules",
    description: "Analyzes pasted Supabase Row Level Security SQL or Firebase/Firestore rules text for common misconfigurations (missing RLS, overly permissive policies, wildcard access).",
    inputSchema: {
      rules: z.string().describe("The raw SQL (RLS policies) or Firebase rules JSON/text to analyze."),
    },
  },
  async ({ rules }) => {
    const result = await runScan({ files: new Map(), dbRulesInput: rules });
    const findings = sortBySeverity(result.findings);

    if (findings.length === 0) {
      return { content: [{ type: "text", text: "No issues found in the provided rules." }] };
    }

    const lines = findings.map(
      (f) => `${f.severity.toUpperCase()} — ${f.title}${f.description_technical ? `: ${f.description_technical}` : ""}`
    );
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
