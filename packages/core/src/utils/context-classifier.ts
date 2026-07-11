// Context classifier — determines if a finding is in production code,
// test files, examples, config, rule definitions, or vendored code.
// Used to separate real issues from noise in scan reports.

import type { FindingContext } from "../engines/types.js";

interface ClassifyInput {
  file_path?: string;
  code_snippet?: string;
}

// Order matters: first match wins.
// Use (^|\/) to match both "test/foo.ts" and "src/test/foo.ts".
const PATH_RULES: Array<{ pattern: RegExp; context: FindingContext }> = [
  // Test files
  { pattern: /\.test\.[cm]?[tj]sx?$/, context: "test" },
  { pattern: /\.spec\.[cm]?[tj]sx?$/, context: "test" },
  { pattern: /(^|\/)__tests__\//, context: "test" },
  { pattern: /(^|\/)__mocks__\//, context: "test" },
  { pattern: /(^|\/)fixtures?\//i, context: "test" },
  { pattern: /(^|\/)test\//, context: "test" },
  { pattern: /(^|\/)tests\//, context: "test" },
  { pattern: /(^|\/)e2e\//, context: "test" },
  { pattern: /(^|\/)cypress\//, context: "test" },
  { pattern: /(^|\/)playwright\//, context: "test" },
  { pattern: /\.stories\.[tj]sx?$/, context: "test" },
  { pattern: /vitest\.config/, context: "test" },
  { pattern: /jest\.config/, context: "test" },
  { pattern: /playwright\.config/, context: "test" },
  { pattern: /setup-e2e/, context: "test" },
  { pattern: /setup-test/, context: "test" },
  { pattern: /seed\.(ts|js|sql)$/i, context: "test" },
  { pattern: /(^|\/)seeds?\//, context: "test" },

  // Rule definitions and scanner engine code
  { pattern: /(^|\/)rules\/.*\.ya?ml$/, context: "rule" },
  { pattern: /\.semgrep\.ya?ml$/, context: "rule" },
  { pattern: /\.gitleaks\.toml$/, context: "rule" },
  { pattern: /worker\/src\/engines\//, context: "rule" },
  { pattern: /worker\/src\/scanning\//, context: "rule" },

  // Examples and documentation
  { pattern: /(^|\/)content\//, context: "example" },
  { pattern: /(^|\/)docs\//, context: "example" },
  { pattern: /(^|\/)examples?\//, context: "example" },
  { pattern: /(^|\/)demos?\//, context: "example" },
  { pattern: /(^|\/)tutorials?\//, context: "example" },
  { pattern: /(^|\/)samples?\//, context: "example" },
  { pattern: /\.example\.[^/]+$/, context: "example" },
  { pattern: /(^|\/)messages\/.*\.json$/, context: "example" },

  // Config, scripts, and infrastructure
  { pattern: /(^|\/)scripts\//, context: "config" },
  { pattern: /(^|\/)\.github\/workflows\//, context: "config" },
  { pattern: /(^|\/)\.circleci\//, context: "config" },
  { pattern: /\.gitlab-ci\.ya?ml$/, context: "config" },
  { pattern: /Jenkinsfile$/, context: "config" },
  { pattern: /(^|\/)infra\//, context: "config" },
  { pattern: /(^|\/)terraform\//, context: "config" },
  { pattern: /(^|\/)pulumi\//, context: "config" },
  { pattern: /(^|\/)supabase\/migrations\//, context: "config" },
  { pattern: /(^|\/)migrations\//, context: "config" },
  { pattern: /(^|\/)prisma\/migrations\//, context: "config" },

  // Vendored / generated
  { pattern: /(^|\/)vendor\//, context: "vendored" },
  { pattern: /(^|\/)generated\//, context: "vendored" },
  { pattern: /\.gen\.[tj]sx?$/, context: "vendored" },
  { pattern: /\.generated\.[tj]sx?$/, context: "vendored" },
  { pattern: /(^|\/)dist\//, context: "vendored" },
  { pattern: /(^|\/)node_modules\//, context: "vendored" },
];

export function classifyContext(input: ClassifyInput): FindingContext {
  const filePath = input.file_path ?? "";

  // No file path = URL scanner or DB rules findings = always production
  if (!filePath) return "production";

  for (const rule of PATH_RULES) {
    if (rule.pattern.test(filePath)) {
      return rule.context;
    }
  }

  return "production";
}

export function classifyFindings<T extends ClassifyInput & { context?: FindingContext }>(
  findings: T[]
): T[] {
  return findings.map((f) => ({
    ...f,
    context: classifyContext(f),
  }));
}
