// Shared text formatting for MCP tool responses. Kept compact and
// token-conscious: full descriptions/snippets only appear in get_finding,
// never in the scan_project summary.

import type { FindingData, Severity } from "@datahogo/core";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function isProductionActionable(finding: FindingData): boolean {
  return (finding.context ?? "production") === "production" && finding.classification !== "informational";
}

export function sortBySeverity(findings: FindingData[]): FindingData[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

export function severityCounts(findings: FindingData[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function formatSeverityCounts(counts: Record<Severity, number>): string {
  return SEVERITY_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `${s}: ${counts[s]}`)
    .join(", ") || "none";
}

export function location(finding: FindingData): string {
  if (!finding.file_path) return finding.category;
  return finding.line_number ? `${finding.file_path}:${finding.line_number}` : finding.file_path;
}
