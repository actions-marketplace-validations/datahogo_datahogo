// PHP / Laravel ecosystem security scanner agent.
// Detects PHP projects via composer.json and scans for
// mass assignment, SQL injection, debug mode, dangerous functions,
// unsafe deserialization, XSS, missing auth middleware, SSRF,
// weak hashing, committed .env files, CORS wildcards, and missing CSRF.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

export class PHPScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const filePath of files.keys()) {
      if (filePath === "composer.json" || filePath.endsWith("/composer.json")) {
        return true;
      }
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Detect project-level global middleware once so individual checks can
    // suppress absence-based findings that are already covered globally.
    const hasGlobalAuth = detectGlobalAuthMiddleware(files);

    results.push(...checkMassAssignment(files));
    results.push(...checkSqlInjectionDbRaw(files));
    results.push(...checkAppDebug(files));
    results.push(...checkDangerousFunctions(files));
    results.push(...checkUnsafeUnserialize(files));
    results.push(...checkXssEcho(files));
    results.push(...checkRoutesWithoutAuth(files, hasGlobalAuth));
    results.push(...checkRawUserInputSql(files));
    results.push(...checkSsrf(files));
    results.push(...checkWeakPasswordHashing(files));
    results.push(...checkCommittedEnv(files));
    results.push(...checkCorsWildcard(files));
    results.push(...checkMissingCsrf(files, hasGlobalAuth));

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "php-agent",
      version: "1.0.0",
      technologies: ["php", "laravel"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      { id: "php:mass-assignment",        name: "Mass assignment without $fillable/$guarded",    severity: "HIGH"     },
      { id: "php:sql-injection-db-raw",   name: "SQL injection via DB::raw() with variable",     severity: "CRITICAL" },
      { id: "php:app-debug-true",         name: "APP_DEBUG=true exposes stack traces",           severity: "HIGH"     },
      { id: "php:dangerous-functions",    name: "Dangerous function call (eval/exec/system/…)",  severity: "CRITICAL" },
      { id: "php:unsafe-unserialize",     name: "Unsafe unserialize() with variable input",      severity: "CRITICAL" },
      { id: "php:xss-echo",              name: "XSS via echo or unescaped Blade output",         severity: "HIGH"     },
      { id: "php:routes-without-auth",   name: "Modifying route without auth middleware",        severity: "MEDIUM"   },
      { id: "php:sql-injection-raw-input", name: "SQL injection via raw $_GET/$_POST in query()", severity: "CRITICAL" },
      { id: "php:ssrf-file-get-contents", name: "SSRF via file_get_contents() with variable URL", severity: "HIGH"   },
      { id: "php:weak-password-hashing",  name: "Weak hashing algorithm: md5() or sha1()",      severity: "HIGH"     },
      { id: "php:committed-env-secrets",  name: "Secret credentials committed in .env file",     severity: "CRITICAL" },
      { id: "php:cors-wildcard",          name: "CORS configured with wildcard origin (*)",      severity: "MEDIUM"   },
      { id: "php:missing-csrf",           name: "Missing CSRF protection in Blade form",         severity: "MEDIUM"   },
    ];
  }
}

// --- File type helpers ---

function isPHPFile(filePath: string): boolean {
  return filePath.endsWith(".php");
}

function isBladeFile(filePath: string): boolean {
  return filePath.endsWith(".blade.php");
}

function isEnvFile(filePath: string): boolean {
  // Matches .env, .env.local, .env.production, etc.
  // Does NOT match .env.example or .env.template
  if (/\.env\.example$/.test(filePath)) return false;
  if (/\.env\.template$/.test(filePath)) return false;
  return /(?:^|\/)\.(env)(\.\w+)?$/.test(filePath);
}

function isArtisanCommand(filePath: string): boolean {
  return filePath.includes("app/Console/Commands/");
}

// --- Project-level global auth middleware detection ---
// Scans Kernel.php or bootstrap/app.php for framework-level auth middleware.
// If present, absence-based findings (missing auth on routes, missing CSRF)
// should not be raised — the middleware applies globally and we can't infer
// route-level coverage from static analysis alone.

function detectGlobalAuthMiddleware(files: Map<string, string>): boolean {
  for (const [filePath, content] of files) {
    if (
      !filePath.includes("app/Http/Kernel.php") &&
      !filePath.includes("bootstrap/app.php")
    ) continue;

    // Illuminate auth middleware or throttle/RateLimiter signals a mature setup
    if (/\\Illuminate\\Auth\\Middleware\\Authenticate/.test(content)) return true;
    if (/['"]auth['"]/.test(content) && /\$middlewareAliases\s*=/.test(content)) return true;
    if (/throttle:/.test(content)) return true;
    if (/RateLimiter/.test(content)) return true;

    // bootstrap/app.php with global middleware definition (Laravel 11+)
    if (/->withMiddleware\s*\(/.test(content) && /auth/.test(content)) return true;
  }
  return false;
}

// --- Check 1: Mass assignment without $fillable/$guarded ---

function checkMassAssignment(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath) || isBladeFile(filePath)) continue;
    if (!/extends\s+Model/.test(content)) continue;
    // Only count property declarations (protected/public/private $fillable),
    // not comments that mention $fillable in documentation text.
    if (/(?:protected|public|private)\s+\$fillable\b/.test(content)) continue;
    if (/(?:protected|public|private)\s+\$guarded\b/.test(content)) continue;

    // Report at the line where the class extends Model
    const lines = content.split("\n");
    let flagLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (/extends\s+Model/.test(lines[i])) {
        flagLine = i + 1;
        break;
      }
    }

    results.push({
      checkId: "php:mass-assignment",
      title: "Mass assignment vulnerability: missing $fillable or $guarded",
      severity: "HIGH",
      confidence: "medium",
      file: filePath,
      line: flagLine,
      description:
        "This Eloquent model extends Model but defines neither $fillable nor $guarded. " +
        "Without a whitelist or blacklist, any field from a request payload can be mass-assigned, " +
        "potentially allowing attackers to overwrite sensitive fields like 'is_admin' or 'role'.",
      fix: "Define $fillable or $guarded in your Eloquent model to prevent mass assignment.",
      cwe: "CWE-915",
    });
  }

  return results;
}

// --- Check 2: SQL injection via DB::raw() ---

// Returns true when a DB::raw() call contains parameterized placeholders OR
// is given a second binding argument, making it safe.
// Examples:
//   DB::raw("... WHERE x = ?", [$x])   → safe (has binding array)
//   DB::raw("... WHERE x = $x")        → unsafe (interpolated variable)
function isDbRawSafe(line: string, matchIndex: number): boolean {
  // Extract the full argument region after DB::raw( up to a reasonable window
  const afterMatch = line.slice(matchIndex);

  // If the expression contains a ? placeholder it is parameterized
  if (/\?/.test(afterMatch)) return true;

  // If there is a second argument (array binding) after the closing quote it is safe
  // e.g. DB::raw("...", [$x]) or DB::select("...", [$x])
  // We look for a pattern like: "...", [ or '...', [
  if (/['"][^'"]*['"]\s*,\s*\[/.test(afterMatch)) return true;

  return false;
}

function checkSqlInjectionDbRaw(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // DB::raw( with a variable inside, or DB::select(DB::raw( with variable
      const rawMatch = /DB::raw\s*\(/.exec(line);
      if (!rawMatch) continue;

      // Must have a variable ($ sign) somewhere after DB::raw(
      const afterRaw = line.slice(rawMatch.index);
      if (!/\$/.test(afterRaw)) continue;

      // Skip if the call is safe (parameterized or has binding array)
      if (isDbRawSafe(line, rawMatch.index)) continue;

      results.push({
        checkId: "php:sql-injection-db-raw",
        title: "SQL injection via DB::raw() with variable input",
        severity: "CRITICAL",
        confidence: "high",
        file: filePath,
        line: i + 1,
        description:
          "DB::raw() is used with a PHP variable directly interpolated into the SQL string. " +
          "If that variable contains user-controlled data, an attacker can inject arbitrary SQL " +
          "and read, modify, or delete data.",
        fix: "Use query builder bindings: DB::select('SELECT * FROM users WHERE id = ?', [$id])",
        cwe: "CWE-89",
      });
    }
  }

  return results;
}

// --- Check 3: APP_DEBUG=true in .env ---

function checkAppDebug(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isEnvFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (/^\s*APP_DEBUG\s*=\s*true\s*$/i.test(lines[i])) {
        results.push({
          checkId: "php:app-debug-true",
          title: "APP_DEBUG=true exposes stack traces in production",
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "APP_DEBUG=true causes Laravel to display full stack traces, local variable dumps, " +
            "and framework internals to any user who triggers an error. This leaks sensitive " +
            "configuration details and aids attacker reconnaissance.",
          fix: "Set APP_DEBUG=false in production .env file.",
          cwe: "CWE-215",
        });
      }
    }
  }

  return results;
}

// --- Check 4: Dangerous functions ---

// Matches function calls that are NOT inside a comment.
// We check that the line is not a comment line (// or #) before flagging.
const DANGEROUS_FUNCTIONS = ["eval", "exec", "system", "shell_exec", "passthru", "popen"];
const DANGEROUS_FUNC_REGEX = new RegExp(
  `\\b(${DANGEROUS_FUNCTIONS.join("|")})\\s*\\(`,
);

// Patterns that indicate user-controlled input is passed to eval/exec
const USER_INPUT_PATTERN = /\$_(POST|GET|REQUEST|COOKIE|SERVER)\b|\$request->|->input\s*\(|->get\s*\(/;

function checkDangerousFunctions(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    // exec/shell_exec in Artisan console commands are expected — lower confidence
    const isConsoleCommand = isArtisanCommand(filePath);

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();

      // Skip comment lines
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      // Strip inline comments before matching
      const codeOnly = trimmed.replace(/\/\/.*$/, "").replace(/#.*$/, "");

      const match = DANGEROUS_FUNC_REGEX.exec(codeOnly);
      if (!match) continue;

      const funcName = match[1];

      // Determine confidence based on context
      let confidence: "high" | "medium" | "low";

      if (funcName === "eval" && USER_INPUT_PATTERN.test(codeOnly)) {
        // eval() with clear user-controlled input
        confidence = "high";
      } else if (funcName === "eval") {
        // eval() with other variables — still dangerous but less certain about user input
        confidence = "medium";
      } else if (isConsoleCommand) {
        // exec/shell_exec/etc. in Artisan commands — legitimate deployment tooling
        confidence = "low";
      } else {
        // Other dangerous function calls
        confidence = "medium";
      }

      results.push({
        checkId: "php:dangerous-functions",
        title: `Dangerous function call: ${funcName}()`,
        severity: "CRITICAL",
        confidence,
        file: filePath,
        line: i + 1,
        description:
          `${funcName}() executes arbitrary OS commands or evaluates arbitrary code. ` +
          "If user input reaches this call, an attacker can achieve remote code execution (RCE).",
        fix: "Avoid dangerous functions. Use safer alternatives or validate input strictly.",
        cwe: "CWE-78",
      });
    }
  }

  return results;
}

// --- Check 5: Unsafe unserialize ---

function checkUnsafeUnserialize(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      // unserialize( with any variable argument
      if (/\bunserialize\s*\(\s*\$/.test(lines[i])) {
        // If it is superglobal user input, confidence is higher
        const isUserInput = /\$_(POST|GET|REQUEST|COOKIE)\[/.test(lines[i]);
        results.push({
          checkId: "php:unsafe-unserialize",
          title: "Unsafe unserialize() call with variable input",
          severity: "CRITICAL",
          confidence: isUserInput ? "high" : "medium",
          file: filePath,
          line: i + 1,
          description:
            "unserialize() can execute arbitrary PHP code during object reconstruction via " +
            "__wakeup() or __destruct() magic methods. Passing user-controlled data to " +
            "unserialize() is a common PHP object injection vulnerability.",
          fix: "Use json_decode() instead. If unserialize is needed, use allowed_classes option.",
          cwe: "CWE-502",
        });
      }
    }
  }

  return results;
}

// --- Check 6: XSS via echo without escaping ---

// Safe output-escaping wrappers. We check the surrounding 50-character window
// (not just the identical position) to handle multi-function calls like nl2br(e($var)).
const SAFE_ECHO_WRAPPERS = [
  /htmlspecialchars\s*\(/,
  /\be\s*\(/,         // Laravel's e() helper
  /strip_tags\s*\(/,
  /nl2br\s*\(\s*e\s*\(/, // nl2br(e($var))
];

function hasSafeEscaping(line: string): boolean {
  return SAFE_ECHO_WRAPPERS.some((pattern) => pattern.test(line));
}

function checkXssEcho(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");

    if (isBladeFile(filePath)) {
      // In Blade: flag {!! $var !!} (unescaped output)
      for (let i = 0; i < lines.length; i++) {
        if (/\{!!\s*\$/.test(lines[i])) {
          results.push({
            checkId: "php:xss-echo",
            title: "XSS via unescaped Blade output: {!! $var !!}",
            severity: "HIGH",
            confidence: "medium",
            file: filePath,
            line: i + 1,
            description:
              "{!! ... !!} outputs raw unescaped HTML in Blade templates. If the variable " +
              "contains user input, an attacker can inject arbitrary HTML or JavaScript " +
              "and execute code in victims' browsers.",
            fix: "Use htmlspecialchars() or {{ }} in Blade templates for auto-escaping.",
            cwe: "CWE-79",
          });
        }
      }
    } else {
      // In plain PHP: flag echo $var without any safe escaping wrapper
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

        if (!/\becho\s+\$/.test(lines[i])) continue;

        // Check if the line contains any recognised safe escaping wrapper
        if (hasSafeEscaping(lines[i])) continue;

        results.push({
          checkId: "php:xss-echo",
          title: "XSS via echo without output escaping",
          severity: "HIGH",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "echo is used to output a PHP variable directly without escaping. If the variable " +
            "contains user-supplied data, an attacker can inject arbitrary HTML or JavaScript.",
          fix: "Use htmlspecialchars() or {{ }} in Blade templates for auto-escaping.",
          cwe: "CWE-79",
        });
      }
    }
  }

  return results;
}

// --- Check 7: Routes without auth middleware ---

const MODIFYING_METHODS = ["post", "put", "patch", "delete"];
void MODIFYING_METHODS; // referenced indirectly via the regex below

// Paths that legitimately do not require authentication
const EXEMPT_PATHS = [
  "/login",
  "/register",
  "/webhook",
  "/callback",
  "/oauth",
  "/stripe",
  "/health",
  "/api/public",
];

// All middleware patterns that indicate an auth guard is present
const AUTH_MIDDLEWARE_PATTERNS = [
  /middleware\s*\(\s*['"]auth['"]\s*\)/,         // ->middleware('auth')
  /middleware\s*\(\s*['"]auth:api['"]\s*\)/,      // ->middleware('auth:api')
  /middleware\s*\(\s*['"]auth:sanctum['"]\s*\)/,  // ->middleware('auth:sanctum')
  /middleware\s*\(\s*['"]auth:web['"]\s*\)/,      // ->middleware('auth:web')
  /middleware\s*\(\s*\[['"]auth['"]/.source,       // ->middleware(['auth', ...])
];

// Compiled single regex for speed — any match = auth is present
const AUTH_MIDDLEWARE_REGEX = new RegExp(
  AUTH_MIDDLEWARE_PATTERNS.map((p) => (p instanceof RegExp ? p.source : p)).join("|"),
);

// File-level Route::middleware('auth')->group( wraps all routes in the file
const FILE_LEVEL_AUTH_REGEX = /Route::middleware\s*\(\s*['"]auth(?::[a-z]+)?['"]\s*\)\s*->\s*group\s*\(/;

function checkRoutesWithoutAuth(
  files: Map<string, string>,
  hasGlobalAuth: boolean,
): ScanResult[] {
  const results: ScanResult[] = [];

  // When global auth middleware is configured project-wide, we cannot determine
  // coverage from static analysis of route files alone, so suppress these findings.
  if (hasGlobalAuth) return results;

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;
    // Only scan route files
    if (!filePath.includes("routes/web.php") && !filePath.includes("routes/api.php")) continue;

    // If the entire file is wrapped in Route::middleware('auth')->group(, skip it
    if (FILE_LEVEL_AUTH_REGEX.test(content)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match Route::post|put|patch|delete(
      const methodMatch = /Route::(post|put|patch|delete)\s*\(/i.exec(line);
      if (!methodMatch) continue;

      // Check if path is an exempt endpoint.
      // We look for the exempt segment anywhere inside a quoted URL argument,
      // so '/webhook', '/webhook/github', '/stripe/webhook' all match '/webhook' and '/stripe'.
      const isExempt = EXEMPT_PATHS.some((p) => {
        // Match the segment as a path component (after a quote or slash) to avoid
        // spurious matches like '/oauthother' matching '/oauth'.
        const escapedP = p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        return new RegExp(`['"](?:[^'"]*)?${escapedP}(?:[^'"]*)?['"]`).test(line);
      });
      if (isExempt) continue;

      // Look at the same line and the next 5 lines for any auth middleware pattern
      const contextLines = lines.slice(i, Math.min(i + 6, lines.length)).join("\n");
      if (AUTH_MIDDLEWARE_REGEX.test(contextLines)) continue;

      results.push({
        checkId: "php:routes-without-auth",
        title: `Route::${methodMatch[1]}() without auth middleware`,
        severity: "MEDIUM",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          `A ${methodMatch[1].toUpperCase()} route is defined without an 'auth' middleware guard. ` +
          "Unauthenticated users may be able to perform state-changing operations.",
        fix: "Add auth middleware: Route::post('/path', ...)->middleware('auth')",
        cwe: "CWE-306",
      });
    }
  }

  return results;
}

// --- Check 8: SQL injection via raw $_GET/$_POST in query ---

function checkRawUserInputSql(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      // Line contains both superglobal input and a raw query call
      if (
        /\$_(GET|POST|REQUEST)\[/.test(lines[i]) &&
        /query\s*\(/.test(lines[i])
      ) {
        results.push({
          checkId: "php:sql-injection-raw-input",
          title: "SQL injection via raw user input in query()",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "User-supplied data from $_GET, $_POST, or $_REQUEST is used directly inside a " +
            "query() call without parameterization. An attacker can inject arbitrary SQL.",
          fix: "Use prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
          cwe: "CWE-89",
        });
      }
    }
  }

  return results;
}

// --- Check 9: SSRF via file_get_contents / curl with variable URL ---

// Returns true if URL validation appears within `windowLines` lines before the
// file_get_contents() call.
function hasUrlValidationBefore(lines: string[], currentIndex: number, windowLines = 5): boolean {
  const start = Math.max(0, currentIndex - windowLines);
  const context = lines.slice(start, currentIndex + 1).join("\n");

  // filter_var with FILTER_VALIDATE_URL
  if (/filter_var\s*\([^,]+,\s*FILTER_VALIDATE_URL\)/.test(context)) return true;

  // parse_url + domain validation pattern
  if (/parse_url\s*\(/.test(context) && /host/.test(context)) return true;

  return false;
}

function checkSsrf(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      if (!/\bfile_get_contents\s*\(\s*\$/.test(lines[i])) continue;

      // Check whether the URL is validated within 5 lines above
      const isValidated = hasUrlValidationBefore(lines, i);
      const confidence: "high" | "medium" | "low" = isValidated ? "low" : "high";

      results.push({
        checkId: "php:ssrf-file-get-contents",
        title: "SSRF via file_get_contents() with variable URL",
        severity: "HIGH",
        confidence,
        file: filePath,
        line: i + 1,
        description:
          "file_get_contents() is called with a variable URL. If that variable originates " +
          "from user input, an attacker can make the server fetch arbitrary internal or " +
          "external resources (SSRF — Server-Side Request Forgery).",
        fix: "Validate and whitelist URLs before fetching. Use allow-lists for domains.",
        cwe: "CWE-918",
      });
    }
  }

  return results;
}

// --- Check 10: Weak password hashing ---

function checkWeakPasswordHashing(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      if (/\bmd5\s*\(\s*\$/.test(lines[i]) || /\bsha1\s*\(\s*\$/.test(lines[i])) {
        results.push({
          checkId: "php:weak-password-hashing",
          title: "Weak hashing algorithm: md5() or sha1() used",
          severity: "HIGH",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "MD5 and SHA1 are cryptographically broken algorithms with known collision attacks " +
            "and fast GPU cracking speeds. They are unsuitable for password hashing and should " +
            "not be used for any security-sensitive purpose.",
          fix: "Use password_hash() and password_verify() for passwords.",
          cwe: "CWE-328",
        });
      }
    }
  }

  return results;
}

// --- Check 11: Committed .env with secrets ---

// Matches .env variable names that CONTAIN a sensitive word anywhere in the key name,
// with a non-empty value of at least 4 characters. Case-insensitive.
// Examples that match: DB_PASSWORD, STRIPE_API_SECRET, APP_KEY, MY_PRIVATE_KEY
const SECRET_KEY_PATTERN = /^[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL|APP_KEY|DB_PASSWORD)[A-Z0-9_]*\s*=\s*.{4,}$/i;

function checkCommittedEnv(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isEnvFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#")) continue;

      if (SECRET_KEY_PATTERN.test(line)) {
        results.push({
          checkId: "php:committed-env-secrets",
          title: "Secret credentials committed in .env file",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "A .env file containing sensitive credentials is tracked in the repository. " +
            "Anyone with read access to the repo — including collaborators and CI systems — " +
            "can read these credentials. They may also persist in git history after deletion.",
          fix: "Add .env to .gitignore. Rotate all exposed credentials.",
          cwe: "CWE-540",
        });
        // One finding per .env file is sufficient
        break;
      }
    }
  }

  return results;
}

// --- Check 12: CORS wildcard ---

function checkCorsWildcard(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isPHPFile(filePath) && !isEnvFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

      if (
        /CORS_ALLOWED_ORIGINS.*\*/.test(line) ||
        /allowedOrigins.*\[\s*['"]?\*['"]?\s*\]/.test(line) ||
        /Access-Control-Allow-Origin.*\*/.test(line)
      ) {
        results.push({
          checkId: "php:cors-wildcard",
          title: "CORS configured with wildcard origin (*)",
          severity: "MEDIUM",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "CORS is configured to allow requests from any origin (*). This lets any website " +
            "make cross-origin requests to your API, potentially leaking authenticated user data " +
            "if credentials are included in requests.",
          fix: "Restrict CORS to specific origins.",
          cwe: "CWE-942",
        });
      }
    }
  }

  return results;
}

// --- Check 13: Missing CSRF protection in Blade forms ---

function checkMissingCsrf(files: Map<string, string>, hasGlobalAuth: boolean): ScanResult[] {
  const results: ScanResult[] = [];

  // When global middleware handles CSRF (VerifyCsrfToken is typically registered
  // in Kernel.php alongside auth middleware), we can suppress these findings.
  if (hasGlobalAuth) return results;

  for (const [filePath, content] of files) {
    if (!isBladeFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      // Find opening <form tags
      if (!/<form\b/i.test(lines[i])) continue;

      // Look at the next 5 lines for @csrf or csrf_field()
      const contextLines = lines.slice(i, Math.min(i + 6, lines.length)).join("\n");
      if (/@csrf\b/.test(contextLines) || /csrf_field\s*\(\s*\)/.test(contextLines)) continue;

      // Only flag forms that are likely to submit (skip forms with method="get" or no method)
      // We flag by default; GET forms don't need CSRF but POST forms do
      if (/method\s*=\s*['"]?get['"]?/i.test(lines[i])) continue;

      results.push({
        checkId: "php:missing-csrf",
        title: "Missing CSRF protection in Blade form",
        severity: "MEDIUM",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          "A <form> element in a Blade template does not include @csrf or csrf_field(). " +
          "Without CSRF protection, an attacker can trick authenticated users into " +
          "submitting forms to your application from an external website.",
        fix: 'Add @csrf inside your form: <form method="POST"> @csrf ... </form>',
        cwe: "CWE-352",
      });
    }
  }

  return results;
}
