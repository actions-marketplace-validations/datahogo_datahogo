// C# / .NET ecosystem security scanner agent.
// Detects .NET projects (.csproj, .fsproj, .sln) and scans for 13 security
// vulnerabilities spanning hardcoded secrets, injection flaws, insecure
// deserialization, missing authorization, weak cryptography, and more.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

export class CSharpScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const filePath of files.keys()) {
      if (
        filePath.endsWith(".csproj") ||
        filePath.endsWith(".fsproj") ||
        filePath.endsWith(".sln")
      ) {
        return true;
      }
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Collect all file contents for project-level detection.
    const allContent = Array.from(files.values()).join("\n");

    // Detect project-level auth middleware (UseAuthorization / AddAuthorization).
    // When present, missing-[Authorize] findings become low confidence because
    // global or policy-based auth may be in effect.
    const hasGlobalAuth =
      /(?:AddAuthorization|UseAuthorization)\s*\(/.test(allContent) ||
      /AddAuthentication\s*\(/.test(allContent) ||
      /UseAuthentication\s*\(/.test(allContent);

    // Detect project-level rate limiting middleware.
    const hasRateLimiter = /(?:AddRateLimiter|UseRateLimiter)\s*\(/.test(allContent);

    for (const [filePath, content] of files) {
      if (isCSharpFile(filePath)) {
        results.push(...checkMissingAuthorize(filePath, content, hasGlobalAuth));
        results.push(...checkSqlInjection(filePath, content));
        results.push(...checkCorsWildcard(filePath, content));
        results.push(...checkUnsafeDeserialization(filePath, content));
        results.push(...checkXxeVulnerability(filePath, content));
        results.push(...checkPathTraversal(filePath, content));
        results.push(...checkHardcodedConnectionStrings(filePath, content));
        results.push(...checkDeveloperExceptionPage(filePath, content));
        results.push(...checkCommandInjection(filePath, content));
        results.push(...checkWeakHashAlgorithm(filePath, content));
        results.push(...checkMissingAntiForgeryToken(filePath, content));
        results.push(...checkAllowAnonymousOnSensitiveController(filePath, content));
      }

      if (isConfigFile(filePath)) {
        results.push(...checkSecretsInAppSettings(filePath, content));
      }
    }

    // Suppress or downgrade rate-limit-related findings if global rate limiting is
    // detected at the project level (placeholder for future rate-limit check).
    void hasRateLimiter;

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "csharp-agent",
      version: "1.0.0",
      technologies: ["dotnet"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      {
        id: "csharp:secrets-in-appsettings",
        name: "Secret hardcoded in appsettings.json",
        severity: "CRITICAL",
      },
      {
        id: "csharp:missing-authorize",
        name: "Mutating HTTP endpoint missing [Authorize] attribute",
        severity: "MEDIUM",
      },
      {
        id: "csharp:sql-injection",
        name: "SQL injection via string concatenation or interpolation",
        severity: "CRITICAL",
      },
      {
        id: "csharp:cors-wildcard",
        name: "CORS configured to allow any origin",
        severity: "MEDIUM",
      },
      {
        id: "csharp:unsafe-deserialization",
        name: "Unsafe deserialization via BinaryFormatter",
        severity: "CRITICAL",
      },
      {
        id: "csharp:xxe-vulnerability",
        name: "XXE vulnerability: XML parsed without DTD restrictions",
        severity: "HIGH",
      },
      {
        id: "csharp:path-traversal",
        name: "Potential path traversal via user-controlled path",
        severity: "HIGH",
      },
      {
        id: "csharp:hardcoded-connection-string",
        name: "Hardcoded connection string in source code",
        severity: "HIGH",
      },
      {
        id: "csharp:developer-exception-page",
        name: "Developer exception page enabled without environment check",
        severity: "HIGH",
      },
      {
        id: "csharp:command-injection",
        name: "Command injection via Process.Start with dynamic input",
        severity: "CRITICAL",
      },
      {
        id: "csharp:weak-hash-algorithm",
        name: "Weak hash algorithm: MD5 or SHA-1",
        severity: "HIGH",
      },
      {
        id: "csharp:missing-antiforgery-token",
        name: "POST action missing [ValidateAntiForgeryToken]",
        severity: "MEDIUM",
      },
      {
        id: "csharp:allow-anonymous-sensitive",
        name: "[AllowAnonymous] on sensitive controller or action",
        severity: "HIGH",
      },
    ];
  }
}

// --- Helper predicates ---

/** Returns true if the file is a C# source file. */
export function isCSharpFile(path: string): boolean {
  return path.endsWith(".cs");
}

/** Returns true if the file matches the appsettings*.json pattern. */
export function isConfigFile(path: string): boolean {
  const filename = path.split("/").pop() ?? path;
  return /^appsettings.*\.json$/.test(filename);
}

// --- Check 1: Secrets in appsettings*.json (CWE-798) ---

// Values that look like placeholders and should not be flagged.
const PLACEHOLDER_PATTERN = /^(?:your[-_]|change[-_]|todo|example|placeholder|\$\{)/i;

function checkSecretsInAppSettings(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  // Match sensitive JSON key names with non-placeholder string values.
  // The character class excludes the literal dollar sign so that ${VAR} substitution
  // references (which start with $) are excluded at the regex level.
  const pattern =
    /"(?:ConnectionString|Password|Secret|ApiKey|Token|PrivateKey)"\s*:\s*"([^"$]{4,})"/gi;

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Reset lastIndex since we reuse the regex across iterations.
    pattern.lastIndex = 0;
    const match = pattern.exec(line);
    if (!match) continue;

    const value = match[1];
    // Skip empty strings and placeholder patterns.
    if (!value || value.trim().length < 4) continue;
    if (PLACEHOLDER_PATTERN.test(value)) continue;

    results.push({
      checkId: "csharp:secrets-in-appsettings",
      title: "Secret hardcoded in appsettings.json",
      severity: "CRITICAL",
      confidence: "high",
      file: filePath,
      line: i + 1,
      description:
        "A sensitive value (connection string, password, API key, or token) is hardcoded " +
        "directly in appsettings.json. Anyone with read access to the repository or the " +
        "deployed artifact can extract this secret.",
      fix: "Use User Secrets, environment variables, or Azure Key Vault.",
      cwe: "CWE-798",
    });
  }
  return results;
}

// --- Check 2: Missing [Authorize] on mutating HTTP endpoints (CWE-306) ---

function checkMissingAuthorize(
  filePath: string,
  content: string,
  hasGlobalAuth: boolean,
): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  // Skip controllers that are intentionally public.
  const skipControllerNames = /Auth|Login|Public|Health/i;
  if (skipControllerNames.test(filePath)) return results;

  // Check if the class itself carries [Authorize] or if global auth middleware
  // is registered at the project level.
  const classHasAuthorize = /\[Authorize\]/.test(content);
  if (classHasAuthorize) return results;

  // Confidence is low when project-level auth middleware is present because
  // global policy-based auth may protect all routes.
  const confidence = hasGlobalAuth ? "low" : "medium";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!/\[Http(?:Post|Put|Delete)(?:\([^)]*\))?\]/.test(line)) continue;

    // Look at the 5 lines immediately above for [Authorize].
    const windowStart = Math.max(0, i - 5);
    const window = lines.slice(windowStart, i).join("\n");

    if (!/\[Authorize\]/.test(window)) {
      results.push({
        checkId: "csharp:missing-authorize",
        title: "Mutating HTTP endpoint missing [Authorize] attribute",
        severity: "MEDIUM",
        confidence,
        file: filePath,
        line: i + 1,
        description:
          "This controller action uses [HttpPost], [HttpPut], or [HttpDelete] but has no " +
          "[Authorize] attribute and the controller class is also not annotated. The endpoint " +
          "may be accessible to unauthenticated users.",
        fix: "Add [Authorize] attribute to controllers or actions handling sensitive operations.",
        cwe: "CWE-306",
      });
    }
  }
  return results;
}

// --- Check 3: SQL injection via string building (CWE-89) ---

function checkSqlInjection(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // new SqlCommand(... + or $" interpolation
    const hasSqlCommand = /(?:new\s+)?SqlCommand\s*\(/.test(line);
    const hasRawSql = /(?:ExecuteSqlRaw|FromSqlRaw)\s*\(/.test(line);

    if (!hasSqlCommand && !hasRawSql) continue;

    // Skip parameterized queries: @paramName, SqlParameter, or AddWithValue
    // in the same line indicates safe, parameterized usage.
    if (/@\w+|SqlParameter|AddWithValue/.test(line)) continue;

    // Flag if the same line uses string concatenation or interpolation.
    if (/\+/.test(line) || /\$"/.test(line)) {
      results.push({
        checkId: "csharp:sql-injection",
        title: "SQL injection via string concatenation or interpolation",
        severity: "CRITICAL",
        confidence: "high",
        file: filePath,
        line: i + 1,
        description:
          "A SQL command is constructed using string concatenation (+) or interpolation ($\"\"). " +
          "If any part of the string comes from user input, an attacker can inject arbitrary SQL " +
          "to read, modify, or delete data.",
        fix: 'Use parameterized queries: new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn)',
        cwe: "CWE-89",
      });
    }
  }
  return results;
}

// --- Check 4: CORS wildcard (CWE-942) ---

function checkCorsWildcard(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (
      /AllowAnyOrigin\s*\(\s*\)/.test(line) ||
      /WithOrigins\s*\(\s*["']\*["']\s*\)/.test(line) ||
      /SetIsOriginAllowed\s*\(\s*_\s*=>/.test(line)
    ) {
      results.push({
        checkId: "csharp:cors-wildcard",
        title: "CORS configured to allow any origin",
        severity: "MEDIUM",
        confidence: "high",
        file: filePath,
        line: i + 1,
        description:
          "The CORS policy allows requests from any origin. This lets malicious websites make " +
          "authenticated cross-origin requests to your API on behalf of logged-in users.",
        fix: 'Restrict CORS: builder.WithOrigins("https://yourdomain.com")',
        cwe: "CWE-942",
      });
    }
  }
  return results;
}

// --- Check 5: Unsafe deserialization via BinaryFormatter (CWE-502) ---

function checkUnsafeDeserialization(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    if (/BinaryFormatter/.test(lines[i])) {
      results.push({
        checkId: "csharp:unsafe-deserialization",
        title: "Unsafe deserialization via BinaryFormatter",
        severity: "CRITICAL",
        confidence: "high",
        file: filePath,
        line: i + 1,
        description:
          "BinaryFormatter is obsolete and unsafe. Deserializing attacker-controlled data with " +
          "BinaryFormatter can lead to remote code execution because it instantiates arbitrary " +
          "types during deserialization.",
        fix: "Use System.Text.Json or JsonSerializer instead of BinaryFormatter.",
        cwe: "CWE-502",
      });
    }
  }
  return results;
}

// --- Check 6: XXE vulnerability via XmlDocument without DTD prohibition (CWE-611) ---

function checkXxeVulnerability(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];

  // If the file already globally disables DTD processing, skip it.
  if (/DtdProcessing\.Prohibit|ProhibitDtd\s*=\s*true/i.test(content)) {
    return results;
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (/new\s+XmlDocument\s*\(\s*\)|XmlReader\.Create\s*\(/.test(line)) {
      results.push({
        checkId: "csharp:xxe-vulnerability",
        title: "XXE vulnerability: XML parsed without DTD restrictions",
        severity: "HIGH",
        // Medium confidence: some XmlDocument/XmlReader.Create usages process only
        // trusted internal XML and are not actually exploitable. Context matters.
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description:
          "XmlDocument or XmlReader.Create() is used without setting DtdProcessing.Prohibit. " +
          "Attackers can exploit external entity references in crafted XML to read local files, " +
          "perform server-side request forgery, or cause denial-of-service.",
        fix: "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit",
        cwe: "CWE-611",
      });
    }
  }
  return results;
}

// --- Check 7: Path traversal (CWE-22) ---

// User-input terms that when passed as arguments to Path.Combine indicate
// potentially attacker-controlled path components. The regex is case-insensitive
// and does NOT require word boundaries on both sides so it catches compound
// identifiers like `userParam`, `queryString`, `requestBody`, etc.
const PATH_USER_INPUT_TERMS = /(?:request|query|param|body|header|routedata)/i;

function checkPathTraversal(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!/Path\.Combine\s*\(/.test(line)) continue;

    // Extract the argument list from Path.Combine(...).
    // We want user-input terms to appear INSIDE the call's argument list,
    // not just anywhere on the line.
    const combineArgMatch = /Path\.Combine\s*\(([^)]+)\)/.exec(line);
    if (!combineArgMatch) continue;

    const args = combineArgMatch[1];
    if (!PATH_USER_INPUT_TERMS.test(args)) continue;

    // Check if Path.GetFullPath or similar normalization appears within
    // the next 3 lines — if so, the developer likely validates the result.
    const lookAheadEnd = Math.min(lines.length, i + 4);
    const lookAhead = lines.slice(i, lookAheadEnd).join("\n");
    if (/Path\.GetFullPath\s*\(/.test(lookAhead)) continue;

    results.push({
      checkId: "csharp:path-traversal",
      title: "Potential path traversal via user-controlled path",
      severity: "HIGH",
      // Medium: user-input term is in arguments, but we can't verify how
      // it was derived without deeper data-flow analysis.
      confidence: "medium",
      file: filePath,
      line: i + 1,
      description:
        "Path.Combine() is called with what appears to be request-derived input. An attacker " +
        "could supply path segments like '../' to escape the intended directory and access " +
        "arbitrary files on the server.",
      fix: "Validate paths against a whitelist. Use Path.GetFullPath() and verify the result stays within the expected directory.",
      cwe: "CWE-22",
    });
  }
  return results;
}

// --- Check 8: Hardcoded connection strings in .cs source (CWE-798) ---

function checkHardcodedConnectionStrings(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  // Match inline connection string syntax inside string literals.
  const pattern = /"(?:Server|Data Source|Initial Catalog)=/i;
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      results.push({
        checkId: "csharp:hardcoded-connection-string",
        title: "Hardcoded connection string in source code",
        severity: "HIGH",
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description:
          "A database connection string (Server=, Data Source=, or Initial Catalog=) is " +
          "embedded directly in C# source code. This exposes database credentials to anyone " +
          "who can read the repository.",
        fix: "Store connection strings in configuration or environment variables.",
        cwe: "CWE-798",
      });
    }
  }
  return results;
}

// --- Check 9: Developer exception page without environment guard (CWE-215) ---

function checkDeveloperExceptionPage(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];

  // If the file guards the call with IsDevelopment(), it is safe.
  if (/IsDevelopment\s*\(\s*\)/.test(content)) {
    return results;
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (/UseDeveloperExceptionPage\s*\(\s*\)/.test(lines[i])) {
      results.push({
        checkId: "csharp:developer-exception-page",
        title: "Developer exception page enabled without environment check",
        severity: "HIGH",
        confidence: "high",
        file: filePath,
        line: i + 1,
        description:
          "UseDeveloperExceptionPage() is called without a surrounding IsDevelopment() guard. " +
          "In production this reveals full stack traces, source code snippets, and request " +
          "details to users who trigger an unhandled exception.",
        fix: "Only use in development: if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();",
        cwe: "CWE-215",
      });
    }
  }
  return results;
}

// --- Check 10: Command injection via Process.Start with dynamic input (CWE-78) ---

// Terms that indicate user-controlled data flowing into Process.Start arguments.
const COMMAND_USER_INPUT_TERMS = /\b(?:[Rr]equest|[Uu]ser[Ii]nput|[Uu]ser[Nn]ame|[Qq]uery)\b/;

function checkCommandInjection(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!/Process\.Start\s*\(/.test(line)) continue;

    // Only flag when BOTH conditions are met:
    // 1. The line contains string concatenation (+) or interpolation ($").
    // 2. The interpolated/concatenated value involves user-input terms
    //    OR the string concat is plain (+) which can include any variable.
    //
    // Rationale: `var x = Process.Start("notepad.exe")` has `var` on the line
    // but no concat/interpolation, so it is NOT flagged.
    // `Process.Start($"cmd /c {userInput}")` has interpolation → flagged.
    // `Process.Start("bash", "-c " + userInput)` has concat + user term → flagged.
    const hasConcatOrInterpolation = /\+/.test(line) || /\$"/.test(line);
    if (!hasConcatOrInterpolation) continue;

    // For plain concat (+) without an explicit user-input term, require at least
    // one user-input-derived identifier to avoid flagging benign constants.
    const hasInterpolation = /\$"/.test(line);
    const hasUserInputTerm = COMMAND_USER_INPUT_TERMS.test(line);

    // $"..." interpolation with any variable is suspicious (flag it).
    // Plain + concat is only flagged when user-input terms are also present.
    if (!hasInterpolation && !hasUserInputTerm) continue;

    results.push({
      checkId: "csharp:command-injection",
      title: "Command injection via Process.Start with dynamic input",
      severity: "CRITICAL",
      confidence: "high",
      file: filePath,
      line: i + 1,
      description:
        "Process.Start() is called with what appears to be dynamic (potentially user-controlled) " +
        "arguments. If user input is passed unsanitized to a shell command, an attacker can " +
        "execute arbitrary commands on the host.",
      fix: "Validate all input before passing to Process.Start(). Use allowlists.",
      cwe: "CWE-78",
    });
  }
  return results;
}

// --- Check 11: Weak hash algorithm (CWE-328) ---

function checkWeakHashAlgorithm(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const pattern =
    /MD5\.Create\s*\(\s*\)|SHA1\.Create\s*\(\s*\)|new\s+MD5CryptoServiceProvider\s*\(\s*\)|new\s+SHA1CryptoServiceProvider\s*\(\s*\)/;
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      results.push({
        checkId: "csharp:weak-hash-algorithm",
        title: "Weak hash algorithm: MD5 or SHA-1",
        severity: "HIGH",
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description:
          "MD5 and SHA-1 are cryptographically broken. Collisions are computationally feasible " +
          "for both algorithms. Using them for integrity checks or password hashing provides " +
          "insufficient protection.",
        fix: "Use SHA256.Create() or SHA512.Create() for hashing.",
        cwe: "CWE-328",
      });
    }
  }
  return results;
}

// --- Check 12: Missing anti-forgery token on POST actions (CWE-352) ---

function checkMissingAntiForgeryToken(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!/\[HttpPost\]/.test(line)) continue;

    // Look at up to 3 lines immediately above for the anti-forgery attribute.
    const windowStart = Math.max(0, i - 3);
    const window = lines.slice(windowStart, i).join("\n");

    if (!/\[ValidateAntiForgeryToken\]/.test(window)) {
      results.push({
        checkId: "csharp:missing-antiforgery-token",
        title: "POST action missing [ValidateAntiForgeryToken]",
        severity: "MEDIUM",
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description:
          "This [HttpPost] action does not have a [ValidateAntiForgeryToken] attribute within " +
          "the preceding 3 lines. Without CSRF validation, a malicious page can trick a logged-in " +
          "user's browser into submitting unintended requests.",
        fix: "Add [ValidateAntiForgeryToken] to POST actions, or use [AutoValidateAntiforgeryToken] on the controller.",
        cwe: "CWE-352",
      });
    }
  }
  return results;
}

// --- Check 13: [AllowAnonymous] on sensitive controller or action (CWE-306) ---

// Terms that suggest an endpoint handles privileged or personal data.
const SENSITIVE_TERMS = /admin|user|account|settings|manage/i;

// Method names that suggest mutating or privileged operations.
const SENSITIVE_METHOD_NAMES = /Create|Update|Delete|Admin|Settings|Manage|Account/;

// HTTP verbs that mutate state — AllowAnonymous on these is riskier than on GET.
const MUTATING_HTTP_VERBS = /\[Http(?:Post|Put|Delete|Patch)(?:\([^)]*\))?\]/;

function checkAllowAnonymousOnSensitiveController(
  filePath: string,
  content: string,
): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!/\[AllowAnonymous\]/.test(line)) continue;

    // --- Path-based detection ---
    // If the file path itself signals a sensitive controller (e.g. AdminController.cs),
    // flag regardless of HTTP verb because the entire class is presumably privileged.
    if (SENSITIVE_TERMS.test(filePath)) {
      results.push({
        checkId: "csharp:allow-anonymous-sensitive",
        title: "[AllowAnonymous] on sensitive controller or action",
        severity: "HIGH",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          "[AllowAnonymous] is applied in a file whose name suggests it handles admin, user, " +
          "account, settings, or management functionality. This overrides any controller-level " +
          "[Authorize] attribute and makes the endpoint publicly accessible.",
        fix: "Remove [AllowAnonymous] from sensitive endpoints. Use [Authorize] instead.",
        cwe: "CWE-306",
      });
      continue;
    }

    // --- Code-level detection ---
    // For files without a sensitive name, flag when the surrounding context contains
    // a sensitive class or method name (e.g. UserSettingsController, AdminAction,
    // CreateUser). HTTP verb context is used to confirm this is a controller action
    // (not a utility class), but we don't restrict to mutating verbs only — a GET
    // endpoint exposing admin data is also a concern.
    const windowStart = Math.max(0, i - 4);
    const windowEnd = Math.min(lines.length, i + 5);
    const window = lines.slice(windowStart, windowEnd).join("\n");

    // Require at least one HTTP verb attribute nearby to confirm this is a
    // controller action (not just a random class with the attribute).
    const hasHttpVerb = /\[Http(?:Get|Post|Put|Delete|Patch)(?:\([^)]*\))?\]/.test(window);
    const hasSensitiveName = SENSITIVE_TERMS.test(window) || SENSITIVE_METHOD_NAMES.test(window);

    if (hasHttpVerb && hasSensitiveName) {
      results.push({
        checkId: "csharp:allow-anonymous-sensitive",
        title: "[AllowAnonymous] on sensitive controller or action",
        severity: "HIGH",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          "[AllowAnonymous] is applied near code that appears to handle admin, user, account, " +
          "settings, or management functionality. This overrides any controller-level [Authorize] " +
          "attribute and makes the endpoint publicly accessible.",
        fix: "Remove [AllowAnonymous] from sensitive endpoints. Use [Authorize] instead.",
        cwe: "CWE-306",
      });
    }
  }
  return results;
}
