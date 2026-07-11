// Go ecosystem security scanner agent.
// Detects Go projects (go.mod) and scans for common security vulnerabilities:
// SQL injection, command injection, hardcoded credentials, weak crypto,
// template HTML bypass, path traversal, CORS misconfig, and more.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

// Extend ScanResult locally with a confidence field.
// The base ScanResult type does not carry confidence; we attach it as an
// optional property so callers that care can use it for filtering.
export type Confidence = "high" | "medium" | "low";

export interface GoScanResult extends ScanResult {
  confidence: Confidence;
}

export class GoScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const filePath of files.keys()) {
      if (filePath === "go.mod" || filePath.endsWith("/go.mod")) {
        return true;
      }
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    for (const [filePath, content] of files) {
      if (!isGoFile(filePath)) continue;

      results.push(...checkSqlInjection(filePath, content));
      results.push(...checkErrorInResponse(filePath, content));
      results.push(...checkHttpWithoutTls(filePath, content));
      results.push(...checkCommandInjection(filePath, content));
      results.push(...checkTemplateHtmlBypass(filePath, content));
      results.push(...checkHardcodedCredentials(filePath, content));
      results.push(...checkWeakHashAlgorithm(filePath, content));
      results.push(...checkHttpHandlerWithoutAuth(filePath, content));
      results.push(...checkCorsWildcard(filePath, content));
      results.push(...checkPathTraversal(filePath, content));
      results.push(...checkUnsafeYamlDeserialization(filePath, content));
      results.push(...checkHttpClientWithoutTimeout(filePath, content));
      results.push(...checkInsecureRandom(filePath, content));
      results.push(...checkSensitiveDataLogged(filePath, content));
    }

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "go-agent",
      version: "1.0.0",
      technologies: ["go"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      { id: "go:sql-injection",           name: "SQL injection via fmt.Sprintf in query",                  severity: "CRITICAL" },
      { id: "go:error-in-response",        name: "Error details exposed in HTTP response",                  severity: "MEDIUM"   },
      { id: "go:http-without-tls",         name: "HTTP server without TLS",                                 severity: "MEDIUM"   },
      { id: "go:command-injection",        name: "Potential command injection via exec.Command",             severity: "CRITICAL" },
      { id: "go:template-html-bypass",     name: "Template HTML bypass via template.HTML()",                severity: "HIGH"     },
      { id: "go:hardcoded-credentials",    name: "Hardcoded credential in source code",                     severity: "CRITICAL" },
      { id: "go:weak-hash-md5",            name: "Weak hash algorithm: MD5",                                severity: "HIGH"     },
      { id: "go:weak-hash-sha1",           name: "Weak hash algorithm: SHA-1",                              severity: "HIGH"     },
      { id: "go:handler-without-auth",     name: "HTTP handler registered without authentication middleware", severity: "MEDIUM"  },
      { id: "go:cors-wildcard",            name: "CORS wildcard: Access-Control-Allow-Origin set to *",     severity: "MEDIUM"   },
      { id: "go:path-traversal",           name: "Potential path traversal in file operation",              severity: "HIGH"     },
      { id: "go:unsafe-yaml",             name: "Unsafe YAML deserialization into interface{}",             severity: "HIGH"     },
      { id: "go:http-client-no-timeout",   name: "HTTP client created without timeout",                     severity: "MEDIUM"   },
      { id: "go:http-default-client",      name: "http.Get/http.Post uses default client with no timeout",  severity: "MEDIUM"   },
      { id: "go:insecure-random",          name: "math/rand used for security-sensitive value",              severity: "HIGH"     },
      { id: "go:sensitive-data-logged",    name: "Sensitive data in log output",                             severity: "MEDIUM"   },
    ];
  }
}

// --- Helper ---

/** Returns true if the file path ends with .go. */
export function isGoFile(path: string): boolean {
  return path.endsWith(".go");
}

// --- Check 1: SQL injection via fmt.Sprintf in queries (CWE-89) ---
//
// Confidence rules:
//   high  — %s or %v in the format string (injectable string value)
//   low   — %d only (type-safe integer, cannot break SQL syntax)

function checkSqlInjection(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (
      line.includes("db.Query(fmt.Sprintf(") ||
      line.includes("db.Exec(fmt.Sprintf(") ||
      line.includes("db.QueryRow(fmt.Sprintf(")
    ) {
      // %s or %v allows injecting arbitrary strings; %d is type-safe (integer only).
      const hasInjectableVerb = /%[^d\s"']/.test(line) || line.includes("%s") || line.includes("%v");
      const confidence: Confidence = hasInjectableVerb ? "high" : "low";

      results.push({
        checkId: "go:sql-injection",
        title: "SQL injection via fmt.Sprintf in query",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "Using fmt.Sprintf() to build SQL queries allows injection attacks. User-controlled input interpolated into the query string can break out and execute arbitrary SQL.",
        fix: 'Use parameterized queries: db.Query("SELECT * FROM users WHERE id = $1", id)',
        cwe: "CWE-89",
        confidence,
      });
    }
  }

  return results;
}

// --- Check 2: Error details in HTTP response (CWE-209) ---

function checkErrorInResponse(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // fmt.Fprintf(w, ..., err) or http.Error(w, err.Error(), ...)
    const hasFprintfWithErr =
      line.includes("fmt.Fprintf(w,") && line.includes("err");
    const hasHttpErrorWithErrMsg = line.includes("http.Error(w, err.Error()");

    if (hasFprintfWithErr || hasHttpErrorWithErrMsg) {
      results.push({
        checkId: "go:error-in-response",
        title: "Error details exposed in HTTP response",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          "Internal error details are being sent to the client. This can leak implementation details, file paths, or database schema information that aids attackers.",
        fix: "Return generic error messages to clients. Log detailed errors server-side.",
        cwe: "CWE-209",
        confidence: "medium",
      });
    }
  }

  return results;
}

// --- Check 3: HTTP without TLS (CWE-319) ---

function checkHttpWithoutTls(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match http.ListenAndServe( but NOT http.ListenAndServeTLS(
    if (
      line.includes("http.ListenAndServe(") &&
      !line.includes("http.ListenAndServeTLS(")
    ) {
      results.push({
        checkId: "go:http-without-tls",
        title: "HTTP server without TLS",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          "The server is configured to listen over plain HTTP. Data transmitted between the client and server is unencrypted and vulnerable to interception.",
        fix: "Use http.ListenAndServeTLS() or a reverse proxy with TLS termination.",
        cwe: "CWE-319",
        confidence: "medium",
      });
    }
  }

  return results;
}

// --- Check 4: Command injection (CWE-78) ---
//
// Go's exec.Command separates the executable from its arguments, so passing a
// plain variable as an argument is NOT inherently dangerous — the OS never
// invokes a shell. We only flag genuinely dangerous patterns:
//
//   high   — string concatenation (`+`) used inside the exec.Command call, OR
//             a known request-input source (r.FormValue, r.URL, chi.URLParam,
//             mux.Vars) appears on the SAME line as exec.Command
//   medium — fmt.Sprintf used to build the command string
//
// Simple variable refs with no concat and no same-line request input are
// intentionally NOT flagged (e.g. exec.Command("git", tag)).

// Patterns that mean user data is on this exact line.
const CMD_SAME_LINE_INPUT =
  /r\.FormValue\s*\(|r\.URL\s*\.|chi\.URLParam\s*\(|mux\.Vars\s*\(/;

function checkCommandInjection(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.includes("exec.Command(")) continue;

    // Only string literals — completely safe.
    const afterCommand = line.slice(line.indexOf("exec.Command(") + "exec.Command(".length);
    const isOnlyStringLiterals = /^"[^"]*"(?:\s*,\s*"[^"]*")*\s*\)/.test(afterCommand.trim());
    if (isOnlyStringLiterals) continue;

    // fmt.Sprintf used to build the command or args — medium confidence.
    if (line.includes("fmt.Sprintf(")) {
      results.push({
        checkId: "go:command-injection",
        title: "Potential command injection via exec.Command",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "exec.Command() receives a string built with fmt.Sprintf(). If user-controlled input reaches the format arguments, an attacker can influence the command executed.",
        fix: "Never build command strings with fmt.Sprintf. Pass arguments as separate exec.Command parameters and validate them with an allowlist.",
        cwe: "CWE-78",
        confidence: "medium",
      });
      continue;
    }

    // String concatenation (`+`) inside the exec.Command call arguments.
    if (afterCommand.includes("+")) {
      results.push({
        checkId: "go:command-injection",
        title: "Potential command injection via exec.Command",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "exec.Command() is called with string concatenation in its arguments. Concatenating user-controlled input here allows an attacker to inject additional shell arguments or commands.",
        fix: "Pass all arguments as separate exec.Command parameters. Validate each argument against an allowlist.",
        cwe: "CWE-78",
        confidence: "high",
      });
      continue;
    }

    // A known request-input source appears on the same line as exec.Command.
    if (CMD_SAME_LINE_INPUT.test(line)) {
      results.push({
        checkId: "go:command-injection",
        title: "Potential command injection via exec.Command",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "exec.Command() is called with a value read directly from the HTTP request on the same line. If unsanitized, an attacker can supply arbitrary command arguments.",
        fix: "Validate and sanitize all request-derived input before passing to exec.Command. Use allowlists.",
        cwe: "CWE-78",
        confidence: "high",
      });
    }

    // Simple variable reference with no concat and no same-line request input:
    // e.g. exec.Command("git", tag) — NOT flagged. This is the safe Go idiom.
  }

  return results;
}

// --- Check 5: Template HTML bypass (CWE-79) ---
//
// template.HTML() marks a string as safe, bypassing auto-escaping. If the
// argument is already sanitized via a known library we skip the finding.
//
//   medium — template.HTML() with an unsanitized argument
//   (skipped entirely if sanitize/bluemonday/policy.Sanitize/html.EscapeString
//    appears in the same argument expression)

// Patterns that indicate the value has already been sanitized.
// Case-insensitive so both `sanitize` and `Sanitize` match.
const TEMPLATE_HTML_SAFE_PATTERNS =
  /sanitize|bluemonday|policy\.sanitize|html\.escapestring/i;

// How many lines before/after the template.HTML( call to scan for sanitizer evidence.
const TEMPLATE_HTML_CONTEXT_WINDOW = 3;

function checkTemplateHtmlBypass(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.includes("template.HTML(")) continue;

    // Check the call line AND a small surrounding context for sanitizer evidence.
    // This covers cases where a sanitized value is assigned on the previous line
    // or where bluemonday is imported and clearly used in the same block.
    const windowStart = Math.max(0, i - TEMPLATE_HTML_CONTEXT_WINDOW);
    const windowEnd = Math.min(lines.length - 1, i + TEMPLATE_HTML_CONTEXT_WINDOW);
    const contextChunk = lines.slice(windowStart, windowEnd + 1).join("\n");
    if (TEMPLATE_HTML_SAFE_PATTERNS.test(contextChunk)) continue;

    results.push({
      checkId: "go:template-html-bypass",
      title: "Template HTML bypass via template.HTML()",
      severity: "HIGH",
      file: filePath,
      line: i + 1,
      description:
        "template.HTML() marks a string as safe HTML, bypassing Go's html/template auto-escaping. If user-controlled input is wrapped in template.HTML(), it can lead to XSS attacks.",
      fix: "Avoid template.HTML(). Use text/template escaping or sanitize input with bluemonday.",
      cwe: "CWE-79",
      confidence: "medium",
    });
  }

  return results;
}

// --- Check 6: Hardcoded credentials (CWE-798) ---

// Matches: password = "...", secret: "...", token = "...", apiKey = "...", api_key = "..."
const HARDCODED_CRED_PATTERN =
  /(?:password|secret|token|apikey|api_key)\s*[:=]\s*"[^"]{8,}"/i;

// Skip lines that use environment or config sources.
const CRED_SAFE_SOURCES = /os\.Getenv|viper\.Get|flag\.String/;

function checkHardcodedCredentials(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comment lines
    if (trimmed.startsWith("//")) continue;

    // Skip lines pulling from env/config
    if (CRED_SAFE_SOURCES.test(line)) continue;

    if (HARDCODED_CRED_PATTERN.test(line)) {
      results.push({
        checkId: "go:hardcoded-credentials",
        title: "Hardcoded credential in source code",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "A credential (password, secret, token, or API key) appears to be hardcoded in source code. Anyone with repository access can read this value.",
        fix: "Use environment variables or a secrets manager instead of hardcoded credentials.",
        cwe: "CWE-798",
        confidence: "high",
      });
    }
  }

  return results;
}

// --- Check 7: Weak hash algorithm (CWE-328) ---

function checkWeakHashAlgorithm(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const usesMd5 =
      line.includes("crypto/md5") ||
      line.includes("md5.New()") ||
      line.includes("md5.Sum(");

    const usesSha1 =
      line.includes("crypto/sha1") ||
      line.includes("sha1.New()") ||
      line.includes("sha1.Sum(");

    if (usesMd5) {
      results.push({
        checkId: "go:weak-hash-md5",
        title: "Weak hash algorithm: MD5",
        severity: "HIGH",
        file: filePath,
        line: i + 1,
        description:
          "MD5 is cryptographically broken and should not be used for security-sensitive operations. Collision attacks are practical and preimage resistance is weakened.",
        fix: "Use crypto/sha256 or crypto/sha512 for hashing. For passwords, use bcrypt or argon2.",
        cwe: "CWE-328",
        confidence: "high",
      });
    }

    if (usesSha1) {
      results.push({
        checkId: "go:weak-hash-sha1",
        title: "Weak hash algorithm: SHA-1",
        severity: "HIGH",
        file: filePath,
        line: i + 1,
        description:
          "SHA-1 is cryptographically deprecated and should not be used for security-sensitive operations. Collision attacks have been demonstrated in practice.",
        fix: "Use crypto/sha256 or crypto/sha512 for hashing. For passwords, use bcrypt or argon2.",
        cwe: "CWE-328",
        confidence: "high",
      });
    }
  }

  return results;
}

// --- Check 8: HTTP handler without auth middleware (CWE-306) ---
//
// Instead of skipping the entire file when ANY auth-like keyword appears, we
// now check whether the SPECIFIC handler path has middleware wrapping it.
// A handler is considered protected if the line itself — or the 3 lines
// immediately following it — contain an auth-middleware reference wrapping
// that same path.
//
//   low — absence-based finding: the handler appears unprotected

// Paths that are public by convention and do not need auth checks.
const PUBLIC_PATH_PATTERN =
  /["']\/(?:health|public|static|favicon|webhook|callback|ws|metrics|status)[/"']/;

// Identifiers that strongly suggest a handler is wrapped in auth middleware
// on the SAME or immediately adjacent lines.
const AUTH_INLINE_PATTERN =
  /\b(?:middleware|auth|jwt|session|authenticate|authorize)\b/i;

function checkHttpHandlerWithoutAuth(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.includes('http.HandleFunc("')) continue;

    // Public paths don't need auth.
    if (PUBLIC_PATH_PATTERN.test(line)) continue;

    // Check whether this specific handler line or the next 3 lines reference
    // an auth middleware (e.g. a chained call or a comment-documented wrapper).
    const lookAheadEnd = Math.min(lines.length - 1, i + 3);
    const localContext = lines.slice(i, lookAheadEnd + 1).join("\n");
    if (AUTH_INLINE_PATTERN.test(localContext)) continue;

    results.push({
      checkId: "go:handler-without-auth",
      title: "HTTP handler registered without authentication middleware",
      severity: "MEDIUM",
      file: filePath,
      line: i + 1,
      description:
        "This HTTP handler is registered without any visible authentication middleware in the surrounding code. The endpoint may be accessible to unauthenticated users.",
      fix: "Add authentication middleware to protect this endpoint.",
      cwe: "CWE-306",
      confidence: "low",
    });
  }

  return results;
}

// --- Check 9: CORS wildcard (CWE-942) ---

function checkCorsWildcard(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // "Access-Control-Allow-Origin" with "*" on the same line, or
    // the wildcard value on a line immediately following the header name.
    if (line.includes("Access-Control-Allow-Origin") && line.includes('"*"')) {
      results.push({
        checkId: "go:cors-wildcard",
        title: "CORS wildcard: Access-Control-Allow-Origin set to *",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          'The Access-Control-Allow-Origin header is set to "*", which allows any origin to make cross-origin requests to this server. This can lead to data leakage.',
        fix: "Restrict CORS to specific origins instead of using wildcard.",
        cwe: "CWE-942",
        confidence: "high",
      });
    } else if (line.includes("Access-Control-Allow-Origin")) {
      // Check the next line as well (multiline header assignment).
      const nextLine = lines[i + 1] ?? "";
      if (nextLine.includes('"*"')) {
        results.push({
          checkId: "go:cors-wildcard",
          title: "CORS wildcard: Access-Control-Allow-Origin set to *",
          severity: "MEDIUM",
          file: filePath,
          line: i + 1,
          description:
            'The Access-Control-Allow-Origin header is set to "*", which allows any origin to make cross-origin requests to this server. This can lead to data leakage.',
          fix: "Restrict CORS to specific origins instead of using wildcard.",
          cwe: "CWE-942",
          confidence: "high",
        });
      }
    }
  }

  return results;
}

// --- Check 10: Path traversal (CWE-22) ---
//
// Only flag when BOTH a file operation AND a user-input source appear on the
// SAME line (or are directly concatenated). A 5-line context window produced
// too many false positives when the input variable was assigned far above.
//
// Additionally, if filepath.Clean or filepath.Abs appears on the same line,
// the path has been sanitized — don't flag it.
//
//   high   — direct string concatenation (`+`) between input and file op
//   medium — variable reference on the same line (no concat visible)

// User-controlled value sources that commonly appear in path traversal.
const PATH_TRAVERSAL_INPUT_PATTERN =
  /\b(?:r\.FormValue|r\.URL\.Query|r\.URL\b|mux\.Vars|chi\.URLParam)\b/;

// Safe path-cleaning functions.
const PATH_SAFE_PATTERN = /filepath\.Clean|filepath\.Abs/;

function checkPathTraversal(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const opensFile =
      line.includes("os.Open(") ||
      line.includes("os.ReadFile(") ||
      line.includes("ioutil.ReadFile(");

    if (!opensFile) continue;

    // Must also have a request-input source on the same line.
    if (!PATH_TRAVERSAL_INPUT_PATTERN.test(line)) continue;

    // If a path-cleaning call is present on the same line, it is sanitized.
    if (PATH_SAFE_PATTERN.test(line)) continue;

    // Determine confidence: direct concat vs. variable reference.
    const confidence: Confidence = line.includes("+") ? "high" : "medium";

    results.push({
      checkId: "go:path-traversal",
      title: "Potential path traversal in file operation",
      severity: "HIGH",
      file: filePath,
      line: i + 1,
      description:
        "A file operation uses a path derived from request input without visible sanitization. An attacker could supply a path like ../../etc/passwd to read arbitrary files.",
      fix: "Validate file paths against a whitelist. Use filepath.Clean() and check the path doesn't escape the intended directory.",
      cwe: "CWE-22",
      confidence,
    });
  }

  return results;
}

// --- Check 11: Unsafe YAML deserialization (CWE-502) ---

// Lines before/after yaml.Unmarshal to search for an interface{} target variable.
const YAML_CONTEXT_WINDOW = 5;

function checkUnsafeYamlDeserialization(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.includes("yaml.Unmarshal(")) continue;

    // Check the line itself AND surrounding lines for interface{} target.
    const windowStart = Math.max(0, i - YAML_CONTEXT_WINDOW);
    const windowEnd = Math.min(lines.length - 1, i + YAML_CONTEXT_WINDOW);
    const contextChunk = lines.slice(windowStart, windowEnd + 1).join("\n");

    if (contextChunk.includes("interface{}")) {
      results.push({
        checkId: "go:unsafe-yaml",
        title: "Unsafe YAML deserialization into interface{}",
        severity: "HIGH",
        file: filePath,
        line: i + 1,
        description:
          "yaml.Unmarshal() is called with an interface{} target. Deserializing into an untyped map can allow unexpected types to be injected and may enable YAML deserialization attacks.",
        fix: "Unmarshal YAML into strictly typed structs instead of interface{} to prevent arbitrary type instantiation.",
        cwe: "CWE-502",
        confidence: "low",
      });
    }
  }

  return results;
}

// --- Check 12: HTTP client without timeout (CWE-400) ---
//
// Single-line regex misses struct literals that span multiple lines.
// We now scan up to 10 lines from the opening brace to detect Timeout.
//
//   low — absence-based: no Timeout field found in the client definition block

// Matches the start of an http.Client struct literal (may be multiline).
const HTTP_CLIENT_START_PATTERN = /&?http\.Client\s*\{/;

function checkHttpClientWithoutTimeout(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (HTTP_CLIENT_START_PATTERN.test(line)) {
      // If the struct closes on the same line, check that line only.
      if (line.includes("}")) {
        if (!line.includes("Timeout")) {
          results.push({
            checkId: "go:http-client-no-timeout",
            title: "HTTP client created without timeout",
            severity: "MEDIUM",
            file: filePath,
            line: i + 1,
            description:
              "An http.Client is created without a Timeout. A client with no timeout can hang indefinitely on slow or unresponsive servers, leading to resource exhaustion.",
            fix: "Always set a Timeout on http.Client: &http.Client{Timeout: 30 * time.Second}",
            cwe: "CWE-400",
            confidence: "low",
          });
        }
        continue;
      }

      // Multi-line struct literal: scan up to 10 lines for closing brace and Timeout.
      const blockEnd = Math.min(lines.length - 1, i + 10);
      let foundTimeout = false;
      let closingLine = blockEnd;

      for (let j = i; j <= blockEnd; j++) {
        if (lines[j].includes("Timeout")) {
          foundTimeout = true;
          break;
        }
        if (j > i && lines[j].includes("}")) {
          closingLine = j;
          break;
        }
      }

      if (!foundTimeout) {
        results.push({
          checkId: "go:http-client-no-timeout",
          title: "HTTP client created without timeout",
          severity: "MEDIUM",
          file: filePath,
          line: i + 1,
          description:
            "An http.Client is created without a Timeout. A client with no timeout can hang indefinitely on slow or unresponsive servers, leading to resource exhaustion.",
          fix: "Always set a Timeout on http.Client: &http.Client{Timeout: 30 * time.Second}",
          cwe: "CWE-400",
          confidence: "low",
        });
      }

      // Skip ahead to the closing brace to avoid re-scanning the block.
      i = closingLine;
      continue;
    }

    // Default http.Get / http.Post use the default client which has no timeout.
    if (line.includes("http.Get(") || line.includes("http.Post(")) {
      results.push({
        checkId: "go:http-default-client",
        title: "http.Get/http.Post uses default client with no timeout",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          "http.Get() and http.Post() use the default http.Client which has no timeout. Requests can hang indefinitely, leading to resource exhaustion or denial of service.",
        fix: "Always set a Timeout on http.Client: &http.Client{Timeout: 30 * time.Second}",
        cwe: "CWE-400",
        confidence: "low",
      });
    }
  }

  return results;
}

// --- Check 13: Insecure randomness (CWE-330) ---

const MATH_RAND_IMPORT = /["']math\/rand["']/;
const RAND_CALL = /rand\.(?:Int|Intn|Int31|Int63|Float32|Float64|Read|New)\s*\(/;
const SECURITY_CONTEXT = /token|secret|key|session|nonce|salt|otp|password|csrf/i;

function checkInsecureRandom(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  if (!MATH_RAND_IMPORT.test(content)) return results;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!RAND_CALL.test(line)) continue;

    const contextStart = Math.max(0, i - 3);
    const contextEnd = Math.min(lines.length, i + 3);
    const context = lines.slice(contextStart, contextEnd).join("\n");

    if (SECURITY_CONTEXT.test(context)) {
      results.push({
        checkId: "go:insecure-random",
        title: "math/rand used for security-sensitive value",
        severity: "HIGH",
        file: filePath,
        line: i + 1,
        description:
          "math/rand is not cryptographically secure. For tokens, secrets, or session IDs, use crypto/rand instead.",
        fix: 'import "crypto/rand"; b := make([]byte, 32); rand.Read(b)',
        cwe: "CWE-330",
        confidence: "medium",
      });
    }
  }

  return results;
}

// --- Check 14: Sensitive data in logs (CWE-532) ---

const SENSITIVE_LOG_PATTERN = /(?:password|token|secret|apiKey|api_key|authorization|creditCard|ssn|privateKey)/i;

function checkSensitiveDataLogged(filePath: string, content: string): GoScanResult[] {
  const results: GoScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const isLogCall =
      /log\.(?:Print|Printf|Println|Fatal|Fatalf)\s*\(/.test(line) ||
      /fmt\.(?:Print|Printf|Println)\s*\(/.test(line);

    if (!isLogCall) continue;

    if (SENSITIVE_LOG_PATTERN.test(line)) {
      results.push({
        checkId: "go:sensitive-data-logged",
        title: "Sensitive data in log output",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          "A log statement references a variable with a sensitive name (password, token, secret, etc.). Logging sensitive data can expose credentials in log files, monitoring systems, or SIEM tools.",
        fix: "Remove sensitive data from log output. Log identifiers instead of credentials.",
        cwe: "CWE-532",
        confidence: "medium",
      });
    }
  }

  return results;
}
