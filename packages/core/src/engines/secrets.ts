// Secrets detection engine - detects hardcoded API keys, tokens, and credentials
// Uses regex patterns (Gitleaks integration would be added in production)

import type { FindingData } from "./types.js";

interface SecretPattern {
  id: number;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  pattern: RegExp;
  category: string;
  owasp?: string;
  confidence: "high" | "medium" | "low";
}

const SECRET_PATTERNS: SecretPattern[] = [
  // Supabase — format-specific, high confidence
  {
    id: 34,
    name: "Supabase Service Role Key Exposed",
    severity: "critical",
    pattern: /(?:service_role|SERVICE_ROLE|serviceRole)[\s]*[=:]\s*["']?eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/g,
    category: "supabase",
    owasp: "A07:2021",
    confidence: "high",
  },
  // Generic API key — requires assignment context
  {
    id: 53,
    name: "API Key Hardcoded",
    severity: "critical",
    pattern: /(?:api[_-]?key|apikey|api_secret|secret_key)[\s]*[=:]\s*["'][a-zA-Z0-9_\-]{20,}["']/gi,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "medium",
  },
  // OpenAI — format-specific prefix
  {
    id: 53,
    name: "OpenAI API Key Hardcoded",
    severity: "critical",
    pattern: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // AWS — format-specific prefix
  {
    id: 53,
    name: "AWS Access Key Hardcoded",
    severity: "critical",
    pattern: /AKIA[0-9A-Z]{16}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // GitHub — format-specific prefix
  {
    id: 53,
    name: "GitHub Token Hardcoded",
    severity: "critical",
    pattern: /(?:ghp|ghs|gho|ghu|github_pat)_[A-Za-z0-9_]{36,}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // Stripe — format-specific prefix
  {
    id: 53,
    name: "Stripe Secret Key Hardcoded",
    severity: "critical",
    pattern: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // Anthropic — format-specific prefix
  {
    id: 53,
    name: "Anthropic API Key Hardcoded",
    severity: "critical",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // Generic passwords — broad match, medium confidence
  {
    id: 55,
    name: "Password in Plaintext",
    severity: "critical",
    pattern: /(?:password|passwd|pwd)[\s]*[=:]\s*["'][^"']{8,}["']/gi,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "medium",
  },
  // Database connection strings — format-specific
  {
    id: 101,
    name: "Database Connection String Exposed",
    severity: "critical",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^"\s]+:[^"\s]+@(?!localhost|127\.0\.0\.1)[^"\s]+/g,
    category: "database",
    owasp: "A07:2021",
    confidence: "high",
  },
  // Private keys — format-specific
  {
    id: 53,
    name: "Private Key in Source Code",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "high",
  },
  // .env file committed
  {
    id: 62,
    name: "Secrets in Committed .env File",
    severity: "critical",
    pattern: /(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)[\s]*=[\s]*[^\s]{10,}/g,
    category: "vibecoding",
    owasp: "A07:2021",
    confidence: "medium",
  },
  // Firebase — public keys are expected, lower severity
  {
    id: 43,
    name: "Firebase Config in Code",
    severity: "low",
    pattern: /(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId)[\s]*:[\s]*["'][^"']+["']/g,
    category: "firebase",
    confidence: "low",
  },
];

// Files to skip for secrets scanning
const SKIP_FILES = [
  ".env.example",
  ".env.template",
  ".env.sample",
  ".env.defaults",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
];

// Path patterns that indicate test/example/docs (lower confidence, not skipped)
const TEST_DOC_PATHS = [
  /\/__tests__\//,
  /\/test\//,
  /\/tests\//,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\/fixtures?\//,
  /\/mocks?\//,
  /\/examples?\//,
  /\/docs?\//,
  /\/samples?\//,
  /README/i,
  /CHANGELOG/i,
];

const SKIP_EXTENSIONS = [
  ".md",
  ".txt",
  ".svg",
  ".png",
  ".jpg",
  ".gif",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
];

// Placeholder values to ignore
const PLACEHOLDER_VALUES = [
  "your_key_here",
  "your-api-key",
  "your_",
  "xxxx",
  "todo",
  "placeholder",
  "example",
  "changeme",
  "replace_me",
  "sk-xxx",
  "sk-...",
  "sk_test_",
  "sk-test",
  "INSERT_KEY_HERE",
  "put_your",
  "dummy",
  "fake",
  "sample",
  "test_key",
  "test_secret",
  "test_token",
  "000000",
  "111111",
  "aaaaaa",
];

export function detectSecrets(
  code: string,
  filePath: string
): FindingData[] {
  const fileName = filePath.split("/").pop() || "";

  // Skip non-relevant files
  if (SKIP_FILES.includes(fileName)) return [];
  if (SKIP_EXTENSIONS.some((ext) => filePath.endsWith(ext))) return [];

  // Detect if file is in test/docs/examples path (lower confidence)
  const isTestOrDoc = TEST_DOC_PATHS.some((p) => p.test(filePath));

  const findings: FindingData[] = [];
  const lines = code.split("\n");

  // Determine which patterns to use
  const isEnvFile = fileName === ".env" || fileName === ".env.local" || fileName === ".env.production";
  const patternsToUse = isEnvFile
    ? SECRET_PATTERNS.filter((p) => p.id === 62 || p.id === 101)
    : SECRET_PATTERNS.filter((p) => p.id !== 62);

  for (const pattern of patternsToUse) {
    // Reset regex lastIndex
    pattern.pattern.lastIndex = 0;

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      // Skip comments
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("<!--")) {
        continue;
      }

      // Reset before each line check
      pattern.pattern.lastIndex = 0;
      const match = pattern.pattern.exec(line);

      if (match) {
        const matchedValue = match[0];

        // Skip placeholders
        const isPlaceholder = PLACEHOLDER_VALUES.some((p) =>
          matchedValue.toLowerCase().includes(p.toLowerCase())
        );
        if (isPlaceholder) continue;

        // Skip if the value is referencing an env var
        if (matchedValue.includes("process.env.") || matchedValue.includes("${") || matchedValue.includes("os.environ") || matchedValue.includes("os.Getenv")) continue;

        // Extract a safe snippet (mask the actual secret)
        const snippet = maskSecret(line.trim());

        // Lower confidence for test/doc files
        const confidence = isTestOrDoc ? "low" : pattern.confidence;

        findings.push({
          vulnerability_id: pattern.id,
          severity: pattern.severity,
          category: pattern.category,
          title: pattern.name,
          file_path: filePath,
          line_number: lineNum + 1,
          code_snippet: snippet,
          owasp_ref: pattern.owasp,
          status: "open",
          confidence,
        });
      }
    }
  }

  return findings;
}

function maskSecret(line: string): string {
  // Mask long strings that look like secrets
  return line.replace(
    /["']([a-zA-Z0-9_\-./+=]{20,})["']/g,
    (_, match: string) => `"${match.substring(0, 6)}...REDACTED"`
  );
}

export function runSecretsEngine(
  files: Map<string, string>
): FindingData[] {
  const allFindings: FindingData[] = [];
  for (const [filePath, content] of files) {
    const findings = detectSecrets(content, filePath);
    allFindings.push(...findings);
  }
  return allFindings;
}
