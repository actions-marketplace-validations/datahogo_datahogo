// Python ecosystem security scanner agent.
// Detects Python projects (Django, FastAPI, Flask) and scans for
// framework-specific misconfigurations, SQL injection, unsafe pickle,
// committed .env files, and known vulnerable dependencies.

import type { ScanAgent, ScanResult, AgentMetadata, Severity, CheckDefinition } from "../types.js";

// Known vulnerable Python packages with CVE references.
// This is a curated subset — in production this would query OSV or PyPI advisory DB.
const KNOWN_VULNERABLE_PACKAGES: Record<string, { maxSafe: string; cve: string; severity: Severity; description: string }[]> = {
  django: [
    { maxSafe: "4.2.11", cve: "CVE-2024-27351", severity: "HIGH", description: "Potential ReDoS in django.utils.text.Truncator.words()" },
    { maxSafe: "3.2.24", cve: "CVE-2024-24680", severity: "HIGH", description: "Denial-of-service in intcomma template filter" },
    { maxSafe: "4.1.13", cve: "CVE-2023-46695", severity: "HIGH", description: "Potential DoS via large file uploads" },
  ],
  flask: [
    { maxSafe: "2.3.2", cve: "CVE-2023-30861", severity: "HIGH", description: "Session cookie set without Secure flag on HTTP" },
  ],
  requests: [
    { maxSafe: "2.31.0", cve: "CVE-2023-32681", severity: "MEDIUM", description: "Unintended leak of Proxy-Authorization header" },
  ],
  urllib3: [
    { maxSafe: "2.0.6", cve: "CVE-2023-43804", severity: "HIGH", description: "Cookie leak via HTTP redirect to different host" },
    { maxSafe: "1.26.17", cve: "CVE-2023-45803", severity: "MEDIUM", description: "Request body not stripped after redirect" },
  ],
  werkzeug: [
    { maxSafe: "3.0.1", cve: "CVE-2023-46136", severity: "HIGH", description: "DoS via multipart form data parsing" },
  ],
  cryptography: [
    { maxSafe: "41.0.6", cve: "CVE-2023-49083", severity: "HIGH", description: "NULL pointer dereference on PKCS7 certificates" },
  ],
  jinja2: [
    { maxSafe: "3.1.3", cve: "CVE-2024-22195", severity: "MEDIUM", description: "XSS via xmlattr filter" },
  ],
  pillow: [
    { maxSafe: "10.2.0", cve: "CVE-2023-50447", severity: "CRITICAL", description: "Arbitrary code execution via crafted PIL image" },
  ],
  pyyaml: [
    { maxSafe: "6.0.1", cve: "CVE-2020-14343", severity: "CRITICAL", description: "Arbitrary code execution via yaml.load() without SafeLoader" },
  ],
  sqlparse: [
    { maxSafe: "0.5.0", cve: "CVE-2024-4340", severity: "HIGH", description: "ReDoS via crafted SQL input" },
  ],
};

// Auth decorator names recognized as protecting a route.
const FLASK_AUTH_DECORATORS = [
  "login_required",
  "auth_required",
  "jwt_required",
  "requires_auth",
  "permission_required",
  "protected",
  "token_required",
];

// FastAPI dependency names recognized as auth guards.
const FASTAPI_AUTH_DEPS = [
  "get_current_user",
  "verify_token",
  "auth",
  "Security(",
];

// URL path segments that are conventionally public — skip auth checks for these.
const PUBLIC_PATH_SEGMENTS = [
  "/health",
  "/docs",
  "/openapi",
  "/redoc",
  "/public",
  "/webhook",
  "/callback",
  "/oauth",
  "/status",
  "/metrics",
  "/openapi.json",
  "/favicon",
  "/static",
  "/login",
  "/register",
];

type PythonFramework = "django" | "fastapi" | "flask" | "none";

/**
 * Project-level middleware signals detected once at scan start.
 * When global auth or rate-limiting middleware is found, per-route
 * missing-auth findings are demoted to confidence "low" rather than suppressed
 * entirely (suppression would hide the signal completely; low keeps it visible).
 */
interface ProjectContext {
  hasGlobalAuth: boolean;
  hasGlobalRateLimit: boolean;
}

export class PythonScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const filePath of files.keys()) {
      if (
        filePath === "requirements.txt" ||
        filePath === "Pipfile" ||
        filePath === "pyproject.toml" ||
        filePath === "setup.py" ||
        filePath.endsWith("requirements.txt")
      ) {
        return true;
      }
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const framework = detectFramework(files);

    // Detect project-level middleware once, before per-file checks.
    const projectContext = detectProjectMiddleware(files, framework);

    // 1. Dependency vulnerability check
    results.push(...checkVulnerableDependencies(files));

    // 2. Django-specific checks
    if (framework === "django") {
      results.push(...checkDjangoMisconfig(files));
    }

    // 3. FastAPI / Flask specific checks
    if (framework === "fastapi" || framework === "flask") {
      results.push(...checkApiFrameworkIssues(files, framework, projectContext));
    }

    // 4. SQL injection via cursor.execute() / .raw() with f-strings or .format()
    results.push(...checkSqlInjection(files));

    // 5. Committed .env files with secrets
    results.push(...checkCommittedEnvFiles(files));

    // 6. Unsafe pickle.loads usage
    results.push(...checkUnsafePickle(files));

    // 7. Insecure randomness in security contexts
    results.push(...checkInsecureRandom(files));

    // 8. yaml.load() without SafeLoader
    results.push(...checkUnsafeYamlLoad(files));

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "python-agent",
      version: "1.0.0",
      technologies: ["python", "django", "flask", "fastapi"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      {
        id: "python:vulnerable-dependency",
        name: "Vulnerable Python dependency (CVE in requirements.txt)",
        severity: "HIGH",
      },
      {
        id: "python:django-debug-enabled",
        name: "Django DEBUG mode enabled",
        severity: "HIGH",
      },
      {
        id: "python:django-secret-key-hardcoded",
        name: "Django SECRET_KEY hardcoded in source",
        severity: "CRITICAL",
      },
      {
        id: "python:django-allowed-hosts-wildcard",
        name: "Django ALLOWED_HOSTS accepts all domains",
        severity: "HIGH",
      },
      {
        id: "python:django-cors-wildcard",
        name: "Django CORS allows all origins",
        severity: "MEDIUM",
      },
      {
        id: "python:fastapi-missing-auth",
        name: "FastAPI endpoint without auth dependency",
        severity: "MEDIUM",
      },
      {
        id: "python:flask-missing-auth",
        name: "Flask route without authentication",
        severity: "MEDIUM",
      },
      {
        id: "python:fastapi-cors-wildcard",
        name: "FastAPI CORS allows all origins",
        severity: "MEDIUM",
      },
      {
        id: "python:flask-cors-wildcard",
        name: "Flask CORS allows all origins",
        severity: "MEDIUM",
      },
      {
        id: "python:sql-injection-execute-interpolation",
        name: "SQL injection via cursor.execute() with string interpolation",
        severity: "CRITICAL",
      },
      {
        id: "python:sql-injection-raw-interpolation",
        name: "SQL injection via Django .raw() with string interpolation",
        severity: "CRITICAL",
      },
      {
        id: "python:sql-injection-concatenation",
        name: "SQL injection via string concatenation in query",
        severity: "CRITICAL",
      },
      {
        id: "python:committed-env-secrets",
        name: "Secret committed in .env file",
        severity: "CRITICAL",
      },
      {
        id: "python:unsafe-pickle",
        name: "Unsafe pickle deserialization",
        severity: "CRITICAL",
      },
      {
        id: "python:insecure-random",
        name: "Insecure random for security-sensitive value",
        severity: "HIGH",
      },
      {
        id: "python:unsafe-yaml-load",
        name: "yaml.load() without SafeLoader",
        severity: "HIGH",
      },
    ];
  }
}

/** Detect which Python web framework (if any) the project uses. */
function detectFramework(files: Map<string, string>): PythonFramework {
  for (const [filePath, content] of files) {
    if (isManifestFile(filePath)) {
      const lower = content.toLowerCase();
      if (lower.includes("django")) return "django";
      if (lower.includes("fastapi")) return "fastapi";
      if (lower.includes("flask")) return "flask";
    }
  }
  return "none";
}

/**
 * Scan all Python files for project-level middleware that provides
 * global authentication or rate limiting. Used to reduce false positives
 * on per-route missing-auth findings.
 *
 * Django: presence of AuthenticationMiddleware, LoginRequiredMiddleware,
 *         RateLimitMiddleware, or CsrfViewMiddleware in MIDDLEWARE array.
 * Flask:  @app.before_request with a recognizable auth check.
 */
function detectProjectMiddleware(files: Map<string, string>, framework: PythonFramework): ProjectContext {
  let hasGlobalAuth = false;
  let hasGlobalRateLimit = false;

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    if (framework === "django") {
      // Check for Django MIDDLEWARE list entries
      if (/AuthenticationMiddleware|LoginRequiredMiddleware/.test(content)) {
        hasGlobalAuth = true;
      }
      if (/RateLimitMiddleware/.test(content)) {
        hasGlobalRateLimit = true;
      }
    }

    if (framework === "flask") {
      // Check for @app.before_request with auth logic
      // The decorator must be followed (within 10 lines) by an auth check
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (/@app\.before_request|@app\.before_each_request/.test(lines[i])) {
          const block = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
          if (/login_required|current_user|authenticate|verify_token|jwt_required|auth/.test(block)) {
            hasGlobalAuth = true;
          }
          if (/rate.?limit|throttle/.test(block)) {
            hasGlobalRateLimit = true;
          }
        }
      }
    }
  }

  return { hasGlobalAuth, hasGlobalRateLimit };
}

function isManifestFile(filePath: string): boolean {
  return (
    filePath === "requirements.txt" ||
    filePath === "Pipfile" ||
    filePath === "pyproject.toml" ||
    filePath === "setup.py" ||
    filePath.endsWith("/requirements.txt")
  );
}

function isPythonFile(filePath: string): boolean {
  return filePath.endsWith(".py");
}

/** Returns true when a URL path string contains a known public segment. */
function isPublicPath(routeLine: string): boolean {
  return PUBLIC_PATH_SEGMENTS.some((segment) => routeLine.includes(segment));
}

// --- Vulnerability checks ---

function checkVulnerableDependencies(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!filePath.endsWith("requirements.txt")) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#") || line.startsWith("-")) continue;

      const parsed = parseRequirementLine(line);
      if (!parsed) continue;

      const advisories = KNOWN_VULNERABLE_PACKAGES[parsed.name.toLowerCase()];
      if (!advisories) continue;

      for (const advisory of advisories) {
        if (parsed.version && isVersionLessThanOrEqual(parsed.version, advisory.maxSafe)) {
          results.push({
            checkId: "python:vulnerable-dependency",
            title: `Vulnerable dependency: ${parsed.name} (${advisory.cve})`,
            severity: advisory.severity,
            confidence: "high",
            file: filePath,
            line: i + 1,
            description: `${advisory.description}. Installed: ${parsed.version}, fix available above ${advisory.maxSafe}.`,
            fix: `Update ${parsed.name} to a version newer than ${advisory.maxSafe}: pip install --upgrade ${parsed.name}`,
            cwe: "CWE-1395",
          });
        }
      }
    }
  }

  return results;
}

function checkDjangoMisconfig(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // DEBUG = True — direct assignment, high confidence
      if (/^\s*DEBUG\s*=\s*True\b/.test(line)) {
        results.push({
          checkId: "python:django-debug-enabled",
          title: "Django DEBUG mode enabled",
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "DEBUG=True exposes detailed error pages with stack traces, local variables, and settings to anyone who triggers an error. Must be False in production.",
          fix: "Set DEBUG = False and use environment variables: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
          cwe: "CWE-215",
        });
      }

      // SECRET_KEY hardcoded (visible in source) — high confidence
      if (/^\s*SECRET_KEY\s*=\s*['"][^'"]{8,}['"]/.test(line)) {
        results.push({
          checkId: "python:django-secret-key-hardcoded",
          title: "Django SECRET_KEY hardcoded in source",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "The Django SECRET_KEY is hardcoded in source code. This key is used for cryptographic signing (sessions, CSRF tokens, password reset tokens). If leaked, attackers can forge any of these.",
          fix: "Move SECRET_KEY to an environment variable: SECRET_KEY = os.environ['SECRET_KEY']",
          cwe: "CWE-798",
        });
      }

      // ALLOWED_HOSTS = ['*'] — only when * is the sole element in the list.
      // Previous regex matched any array containing * anywhere (e.g. ['foo', '*']).
      // Corrected: require * to be the only element, optionally quoted.
      if (/^\s*ALLOWED_HOSTS\s*=\s*\[\s*['"]?\*['"]?\s*\]/.test(line)) {
        results.push({
          checkId: "python:django-allowed-hosts-wildcard",
          title: "Django ALLOWED_HOSTS accepts all domains",
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "ALLOWED_HOSTS=['*'] disables Django's host header validation, enabling HTTP Host header attacks (cache poisoning, password reset poisoning).",
          fix: "Set ALLOWED_HOSTS to your actual domain(s): ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']",
          cwe: "CWE-644",
        });
      }

      // CORS_ALLOW_ALL_ORIGINS = True — high confidence
      if (/^\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True\b/.test(line)) {
        results.push({
          checkId: "python:django-cors-wildcard",
          title: "Django CORS allows all origins",
          severity: "MEDIUM",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "CORS_ALLOW_ALL_ORIGINS=True allows any website to make authenticated requests to your API, potentially leaking user data.",
          fix: "Set CORS_ALLOWED_ORIGINS to specific domains: CORS_ALLOWED_ORIGINS = ['https://yourdomain.com']",
          cwe: "CWE-942",
        });
      }
    }
  }

  return results;
}

function checkApiFrameworkIssues(
  files: Map<string, string>,
  framework: "fastapi" | "flask",
  projectContext: ProjectContext,
): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (framework === "fastapi") {
        if (/^\s*@app\.(?:get|post|put|patch|delete)\s*\(/.test(line)) {
          // Skip known-public paths
          if (isPublicPath(line)) continue;

          // Look back up to 5 lines for auth decorators/dependencies
          const lookbackStart = Math.max(0, i - 5);
          const lookbackChunk = lines.slice(lookbackStart, i).join("\n");

          // Look ahead until next decorator or blank line (max 4 lines) for Depends()
          const aheadLines: string[] = [];
          for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
            if (/^\s*@/.test(lines[j]) || lines[j].trim() === "") break;
            aheadLines.push(lines[j]);
          }
          const aheadChunk = aheadLines.join("\n");

          const hasAuthLookback =
            FASTAPI_AUTH_DEPS.some((dep) => lookbackChunk.includes(dep)) ||
            /Depends\s*\(/.test(lookbackChunk);

          const hasAuthAhead =
            /Depends\s*\(/.test(aheadChunk) ||
            FASTAPI_AUTH_DEPS.some((dep) => aheadChunk.includes(dep));

          if (!hasAuthLookback && !hasAuthAhead) {
            // If a global auth middleware was found, demote to low confidence
            const confidence = projectContext.hasGlobalAuth ? "low" : "medium";
            results.push({
              checkId: "python:fastapi-missing-auth",
              title: "FastAPI endpoint without auth dependency",
              severity: "MEDIUM",
              confidence,
              file: filePath,
              line: i + 1,
              description: "This FastAPI endpoint does not use Depends() for authentication. Without an auth dependency, the endpoint is accessible to anyone.",
              fix: "Add an auth dependency: @app.get('/path')\nasync def handler(user: User = Depends(get_current_user)):",
              cwe: "CWE-306",
            });
          }
        }
      }

      if (framework === "flask") {
        if (/^\s*@app\.route\s*\(/.test(line)) {
          // Skip known-public paths
          if (isPublicPath(line)) continue;

          // Look back up to 5 lines for auth decorators
          const lookbackStart = Math.max(0, i - 5);
          const lookbackChunk = lines.slice(lookbackStart, i).join("\n");

          // Look ahead (up to 6 lines) for auth checks inside the handler
          const aheadChunk = lines.slice(i, Math.min(i + 6, lines.length)).join("\n");

          const authPattern = new RegExp(FLASK_AUTH_DECORATORS.join("|"));
          const handlerAuthPattern = /login_required|auth_required|jwt_required|token_required|current_user/;

          const hasAuth =
            authPattern.test(lookbackChunk) ||
            handlerAuthPattern.test(aheadChunk);

          if (!hasAuth) {
            const confidence = projectContext.hasGlobalAuth ? "low" : "medium";
            results.push({
              checkId: "python:flask-missing-auth",
              title: "Flask route without authentication",
              severity: "MEDIUM",
              confidence,
              file: filePath,
              line: i + 1,
              description: "This Flask route does not have an authentication decorator (@login_required) or auth check. It may be accessible without authentication.",
              fix: "Add @login_required decorator or check current_user in the handler.",
              cwe: "CWE-306",
            });
          }
        }
      }

      // Open CORS — low confidence because CORS(app) alone may be a default
      // that the developer intends to configure further, or only exposes
      // non-sensitive public endpoints.
      if (/CORS\s*\(\s*app\s*\)/.test(line) || /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/.test(line)) {
        results.push({
          checkId: framework === "fastapi" ? "python:fastapi-cors-wildcard" : "python:flask-cors-wildcard",
          title: `${framework === "fastapi" ? "FastAPI" : "Flask"} CORS allows all origins`,
          severity: "MEDIUM",
          confidence: "low",
          file: filePath,
          line: i + 1,
          description: "CORS is configured to allow all origins. This lets any website make authenticated cross-origin requests to your API.",
          fix: "Restrict origins: allow_origins=['https://yourdomain.com']",
          cwe: "CWE-942",
        });
      }
    }
  }

  return results;
}

function checkSqlInjection(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // cursor.execute() with f-string or .format()
      if (/cursor\.execute\s*\(\s*f['"]/.test(line) || /cursor\.execute\s*\([^)]*\.format\s*\(/.test(line)) {
        // Lower confidence if the same line or next 2 lines contain a %s placeholder
        // or a parameter tuple — this may indicate the f-string is only for the table/column
        // name and actual user values are parameterized (still bad practice, but less clear).
        const contextAhead = lines.slice(i, Math.min(i + 3, lines.length)).join("\n");
        const looksParameterized = /%s/.test(contextAhead) || /,\s*\(/.test(contextAhead);
        const confidence = looksParameterized ? "low" : "medium";

        results.push({
          checkId: "python:sql-injection-execute-interpolation",
          title: "SQL injection via cursor.execute() with string interpolation",
          severity: "CRITICAL",
          confidence,
          file: filePath,
          line: i + 1,
          description: "Using f-strings or .format() in cursor.execute() allows SQL injection. User-controlled input can break out of the query and execute arbitrary SQL.",
          fix: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
          cwe: "CWE-89",
        });
      }

      // .raw() with f-string or .format() (Django ORM)
      if (/\.raw\s*\(\s*f['"]/.test(line) || /\.raw\s*\([^)]*\.format\s*\(/.test(line)) {
        const contextAhead = lines.slice(i, Math.min(i + 3, lines.length)).join("\n");
        const looksParameterized = /%s/.test(contextAhead) || /,\s*\[/.test(contextAhead);
        const confidence = looksParameterized ? "low" : "medium";

        results.push({
          checkId: "python:sql-injection-raw-interpolation",
          title: "SQL injection via Django .raw() with string interpolation",
          severity: "CRITICAL",
          confidence,
          file: filePath,
          line: i + 1,
          description: "Using f-strings or .format() in Model.objects.raw() allows SQL injection. Django's raw() accepts parameterized queries natively.",
          fix: "Use parameterized raw queries: Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id])",
          cwe: "CWE-89",
        });
      }

      // execute() or .raw() with string concatenation (+ operator in the call)
      if (/(?:cursor\.execute|\.raw)\s*\(.*["'].*["']\s*\+/.test(line) || /(?:cursor\.execute|\.raw)\s*\(\s*\w+\s*\+/.test(line)) {
        results.push({
          checkId: "python:sql-injection-concatenation",
          title: "SQL injection via string concatenation in query",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "Concatenating strings into SQL queries allows injection attacks. Never build SQL from user input with + operator.",
          fix: "Use parameterized queries instead of string concatenation.",
          cwe: "CWE-89",
        });
      }
    }
  }

  return results;
}

function checkCommittedEnvFiles(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  // Template/example files are not real secrets — skip them entirely.
  const TEMPLATE_SUFFIXES = [".example", ".template", ".sample"];

  for (const [filePath, content] of files) {
    // Match .env files (not .env.example, .env.template, .env.sample)
    if (!/(?:^|\/)\.(env|env\.local|env\.production|env\.staging)$/.test(filePath)) continue;

    if (TEMPLATE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Skip blank lines and comments
      if (!line || line.startsWith("#")) continue;

      // Check for sensitive-looking keys with non-empty values
      if (/(?:SECRET|PASSWORD|TOKEN|KEY|PRIVATE|CREDENTIAL|API_KEY)\s*=\s*.{4,}/i.test(line)) {
        results.push({
          checkId: "python:committed-env-secrets",
          title: "Secret committed in .env file",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: "A .env file with secrets is committed to the repository. Anyone with repo access can read these credentials. Secrets may persist in git history even after deletion.",
          fix: "Remove the .env file from git: git rm --cached .env && echo '.env' >> .gitignore. Rotate all exposed credentials immediately.",
          cwe: "CWE-540",
        });
        // One finding per .env file is enough
        break;
      }
    }
  }

  return results;
}

function checkUnsafePickle(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // pickle.loads / pickle.load with any data source.
      // Confidence is medium because the data source determines actual risk:
      // loading from a local, developer-controlled file is far less dangerous
      // than loading from user input or a network source. Without data-flow
      // analysis we cannot distinguish the two, so we flag all cases but
      // acknowledge the ambiguity with medium confidence.
      if (/pickle\.loads?\s*\(/.test(line)) {
        results.push({
          checkId: "python:unsafe-pickle",
          title: "Unsafe pickle deserialization",
          severity: "CRITICAL",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description: "pickle.loads() can execute arbitrary code during deserialization. If the data comes from an untrusted source (user input, network, uploaded files), an attacker can achieve remote code execution.",
          fix: "Use safer alternatives: json.loads() for data, or hmac-sign pickled data. If pickle is required, use restrictedpickle or a custom Unpickler with find_class restrictions.",
          cwe: "CWE-502",
        });
      }
    }
  }

  return results;
}

function checkInsecureRandom(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // random.random/randint/choice used near security context
      if (/random\.(?:random|randint|choice|randrange|getrandbits|sample)\s*\(/.test(line)) {
        // Check surrounding lines for security context
        const contextStart = Math.max(0, i - 3);
        const contextEnd = Math.min(lines.length, i + 3);
        const context = lines.slice(contextStart, contextEnd).join("\n").toLowerCase();

        if (/token|secret|key|session|nonce|salt|otp|password|code|csrf|verify/.test(context)) {
          results.push({
            checkId: "python:insecure-random",
            title: "Insecure random for security-sensitive value",
            severity: "HIGH",
            confidence: "medium",
            file: filePath,
            line: i + 1,
            description: "The random module is not cryptographically secure. For tokens, passwords, OTPs, or session IDs, use secrets.token_hex(), secrets.token_urlsafe(), or os.urandom().",
            fix: "import secrets; token = secrets.token_urlsafe(32)",
            cwe: "CWE-330",
          });
        }
      }
    }
  }

  return results;
}

function checkUnsafeYamlLoad(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPythonFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // yaml.load() without SafeLoader / safe_load
      if (/yaml\.load\s*\(/.test(line) && !/SafeLoader|safe_load/.test(line)) {
        // Check next 2 lines for Loader=SafeLoader
        const ahead = lines.slice(i, Math.min(i + 3, lines.length)).join("\n");
        if (!/SafeLoader/.test(ahead)) {
          results.push({
            checkId: "python:unsafe-yaml-load",
            title: "yaml.load() without SafeLoader",
            severity: "HIGH",
            confidence: "high",
            file: filePath,
            line: i + 1,
            description: "yaml.load() without SafeLoader can execute arbitrary Python code during parsing. An attacker who controls the YAML input achieves remote code execution.",
            fix: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
            cwe: "CWE-502",
          });
        }
      }
    }
  }

  return results;
}

// --- Utility functions ---

interface ParsedRequirement {
  name: string;
  version: string | null;
}

function parseRequirementLine(line: string): ParsedRequirement | null {
  // Handle: package==1.2.3, package>=1.2.3, package~=1.2.3, package
  const match = line.match(/^([a-zA-Z0-9_-]+(?:\[[a-zA-Z0-9_,-]+\])?)\s*(?:[=~><!=]+\s*([0-9][0-9a-zA-Z.*-]*))?/);
  if (!match) return null;

  // Strip extras like package[extra]
  const name = match[1].replace(/\[.*\]/, "");
  const version = match[2] ?? null;
  return { name, version };
}

/** Simple semver comparison: is versionA <= versionB? */
function isVersionLessThanOrEqual(versionA: string, versionB: string): boolean {
  const partsA = versionA.split(".").map(Number);
  const partsB = versionB.split(".").map(Number);
  const maxLen = Math.max(partsA.length, partsB.length);

  for (let i = 0; i < maxLen; i++) {
    const a = partsA[i] ?? 0;
    const b = partsB[i] ?? 0;
    if (isNaN(a) || isNaN(b)) return false;
    if (a < b) return true;
    if (a > b) return false;
  }
  return true; // equal
}
