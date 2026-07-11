// Post-processing pipeline for scan findings.
// Runs after all engines complete but before score calculation.
// Steps (in order):
//   1. Framework-aware suppressions — mark findings that are known framework
//      requirements so they don't penalize the score.
//   2. Cross-engine deduplication — merge findings for the same root cause
//      that survived the primary dedup (different file_path, same vuln_id).
//   3. Contextual notes — add description_simple for specific patterns.
//   4. Classification — label each finding as "actionable" or "informational".

import type { FindingData } from "../engines/types.js";

// ---------------------------------------------------------------------------
// Step 1: Framework-Aware Suppressions
// ---------------------------------------------------------------------------

interface FrameworkRule {
  vulnerability_id: number;
  /** Match if the finding's title contains this string (case-insensitive). */
  title_contains?: string;
  /** Match if code_snippet contains this exact cookie name. */
  cookie_name_starts?: string;
  /** Match if code_snippet contains exactly this cookie name. */
  cookie_name?: string;
  note: string;
}

// Keys are lowercased technology names as returned by detectTechnologies().
const FRAMEWORK_RULES: Record<string, FrameworkRule[]> = {
  nextjs: [
    {
      vulnerability_id: 63,
      title_contains: "unsafe-inline",
      note: "Next.js App Router requires 'unsafe-inline' in script-src for hydration. This cannot be removed without breaking the framework.",
    },
    {
      vulnerability_id: 99,
      title_contains: "robots.txt",
      note: "robots.txt is standard web practice and expected on production sites.",
    },
  ],
  supabase: [
    {
      vulnerability_id: 67,
      cookie_name_starts: "sb-",
      note: "Supabase Auth manages cookie security flags through its SDK configuration.",
    },
    {
      vulnerability_id: 68,
      cookie_name_starts: "sb-",
      note: "Supabase Auth cookies require client-side JavaScript access for session refresh.",
    },
  ],
  "next-intl": [
    {
      vulnerability_id: 67,
      cookie_name: "NEXT_LOCALE",
      note: "next-intl locale cookie requires client-side JavaScript access for locale synchronization.",
    },
    {
      vulnerability_id: 68,
      cookie_name: "NEXT_LOCALE",
      note: "next-intl locale cookie requires client-side JavaScript access for locale synchronization.",
    },
  ],
};

function matchesFrameworkRule(finding: FindingData, rule: FrameworkRule): boolean {
  if (finding.vulnerability_id !== rule.vulnerability_id) return false;

  if (rule.title_contains !== undefined) {
    if (!finding.title.toLowerCase().includes(rule.title_contains.toLowerCase())) {
      return false;
    }
  }

  if (rule.cookie_name_starts !== undefined) {
    const snippet = finding.code_snippet ?? finding.title ?? "";
    if (!snippet.includes(rule.cookie_name_starts)) return false;
  }

  if (rule.cookie_name !== undefined) {
    const snippet = finding.code_snippet ?? finding.title ?? "";
    if (!snippet.includes(rule.cookie_name)) return false;
  }

  return true;
}

function applyFrameworkSuppressions(
  findings: FindingData[],
  technologies: string[],
): FindingData[] {
  // Normalize tech names to lowercase for lookup.
  const normalizedTechs = technologies.map((t) => t.toLowerCase());

  // Collect applicable rules based on detected technologies.
  const applicableRules: FrameworkRule[] = [];
  for (const tech of normalizedTechs) {
    const rules = FRAMEWORK_RULES[tech];
    if (rules) {
      applicableRules.push(...rules);
    }
  }

  if (applicableRules.length === 0) return findings;

  return findings.map((finding) => {
    for (const rule of applicableRules) {
      if (matchesFrameworkRule(finding, rule)) {
        return {
          ...finding,
          is_framework_requirement: true,
          framework_note: rule.note,
        };
      }
    }
    return finding;
  });
}

// ---------------------------------------------------------------------------
// Step 2: Cross-Engine Deduplication
// ---------------------------------------------------------------------------
// The primary dedup in orchestrator.ts groups by vulnerability_id + file_path +
// line_number. That misses cases where two engines report the same root cause
// at different levels — e.g. the config engine points to next.config.ts while
// the URL scanner has no file_path at all. Group by vulnerability_id alone when
// one side lacks a file_path and keep whichever finding HAS a file_path.

function crossEngineDedup(findings: FindingData[]): FindingData[] {
  // Separate findings that have a file_path from those that don't.
  const withPath: FindingData[] = [];
  const withoutPath: FindingData[] = [];

  for (const f of findings) {
    if (f.file_path) {
      withPath.push(f);
    } else {
      withoutPath.push(f);
    }
  }

  // For each no-path finding, check if there is already a with-path finding
  // for the same vulnerability_id. If yes, skip the no-path finding (the
  // with-path one is more actionable). Otherwise keep it.
  const withPathVulnIds = new Set(withPath.map((f) => f.vulnerability_id));

  const filteredWithoutPath = withoutPath.filter(
    (f) => !withPathVulnIds.has(f.vulnerability_id),
  );

  return [...withPath, ...filteredWithoutPath];
}

// ---------------------------------------------------------------------------
// Step 3: Contextual Notes
// ---------------------------------------------------------------------------

function addContextualNotes(findings: FindingData[]): FindingData[] {
  return findings.map((finding) => {
    // Don't overwrite an existing description_simple.
    if (finding.description_simple) return finding;

    if (finding.is_framework_requirement && finding.framework_note) {
      return { ...finding, description_simple: finding.framework_note };
    }

    if (finding.category === "headers" && finding.severity === "info") {
      return {
        ...finding,
        description_simple: "This is informational — no action required.",
      };
    }

    if (finding.severity === "low" && finding.confidence === "low") {
      return {
        ...finding,
        description_simple:
          "This is a low-confidence observation. Verify manually before acting.",
      };
    }

    return finding;
  });
}

// ---------------------------------------------------------------------------
// Step 4: Classification
// ---------------------------------------------------------------------------

function classifyFindings(findings: FindingData[]): FindingData[] {
  return findings.map((finding) => {
    let classification: "actionable" | "informational";

    if (finding.is_framework_requirement) {
      classification = "informational";
    } else if (finding.severity === "info") {
      classification = "informational";
    } else {
      classification = "actionable";
    }

    return { ...finding, classification };
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Run all four post-processing steps on the aggregated findings.
 *
 * @param findings   Deduplicated, context-classified findings from all engines.
 * @param technologies  Technology list from detectTechnologies().technologies.
 * @returns          Processed findings ready for score calculation.
 */
export function postProcessFindings(
  findings: FindingData[],
  technologies: string[],
): FindingData[] {
  const step1 = applyFrameworkSuppressions(findings, technologies);
  const step2 = crossEngineDedup(step1);
  const step3 = addContextualNotes(step2);
  const step4 = classifyFindings(step3);
  return step4;
}
