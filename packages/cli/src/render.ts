// Terminal output for scan results. Plain ANSI codes — no color library,
// to keep the dependency surface of a security tool minimal.

import type { ScanResult } from "@datahogo/core";
import type { FindingData, Severity } from "@datahogo/core";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

function paint(code: string, text: string): string {
  return useColor ? `[${code}m${text}[0m` : text;
}

const bold = (t: string) => paint("1", t);
const dim = (t: string) => paint("2", t);
const red = (t: string) => paint("31", t);
const yellow = (t: string) => paint("33", t);
const green = (t: string) => paint("32", t);
const cyan = (t: string) => paint("36", t);
const magenta = (t: string) => paint("35", t);

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: red(bold("CRITICAL")),
  high: magenta(bold("HIGH")),
  medium: yellow("MEDIUM"),
  low: cyan("LOW"),
  info: dim("INFO"),
};

function scoreColor(score: number): (t: string) => string {
  if (score >= 80) return green;
  if (score >= 50) return yellow;
  return red;
}

export function renderResults(
  result: ScanResult,
  options: { techs: string[]; fileCount: number; showAll: boolean },
): string {
  const lines: string[] = [];
  const production = result.findings.filter(
    (f) => (f.context ?? "production") === "production" && f.classification !== "informational",
  );
  const shown = options.showAll ? result.findings : production;

  lines.push("");
  lines.push(bold(`  Security Score: ${scoreColor(result.score)(String(result.score))} / 100`));
  lines.push(
    dim(
      `  ${options.fileCount} files scanned · ${options.techs.join(", ") || "no stack detected"} · ${result.durationMs}ms`,
    ),
  );
  lines.push("");

  if (shown.length === 0) {
    lines.push(green("  ✓ No actionable findings. Nice work."));
  }

  for (const severity of SEVERITY_ORDER) {
    const group = shown.filter((f) => f.severity === severity);
    if (group.length === 0) continue;

    lines.push(`  ${SEVERITY_LABEL[severity]} ${dim(`(${group.length})`)}`);
    for (const finding of group) {
      lines.push(`    ${bold(finding.title)}`);
      lines.push(`      ${dim(location(finding))}`);
      if (finding.fix_description) {
        lines.push(`      ${cyan("fix:")} ${finding.fix_description}`);
      }
    }
    lines.push("");
  }

  const informational = result.findings.length - production.length;
  if (!options.showAll && informational > 0) {
    lines.push(dim(`  ${informational} informational/non-production findings hidden — use --all to see them.`));
  }

  if (result.failedEngines.length > 0) {
    lines.push(yellow(`  ⚠ Engines that could not run: ${result.failedEngines.join(", ")}`));
  }

  lines.push("");
  return lines.join("\n");
}

function location(finding: FindingData): string {
  if (!finding.file_path) return finding.category;
  const line = finding.line_number ? `:${finding.line_number}` : "";
  return `${finding.file_path}${line}`;
}

export function renderBinaryHints(missing: string[]): string {
  if (missing.length === 0) return "";
  return dim(
    `  Tip: install ${missing.join(" and ")} for deeper analysis (run \`datahogo doctor\` for details).\n`,
  );
}
