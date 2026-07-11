// Java ecosystem security scanner agent.
// Detects Java/Kotlin projects (Maven, Gradle) and scans for Spring
// misconfigurations, deserialization issues, injection vectors,
// weak cryptography, and common Spring Security pitfalls.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

export class JavaScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const filePath of files.keys()) {
      if (
        filePath === "pom.xml" ||
        filePath === "build.gradle" ||
        filePath === "build.gradle.kts" ||
        filePath.endsWith("/pom.xml") ||
        filePath.endsWith("/build.gradle") ||
        filePath.endsWith("/build.gradle.kts")
      ) {
        return true;
      }
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Detect project-level security infrastructure once and pass to checks
    // that may want to downgrade confidence based on it.
    const projectSecurity = detectProjectLevelSecurity(files);

    results.push(...checkActuatorExposed(files));
    results.push(...checkLog4Shell(files));
    results.push(...checkUnsafeDeserialization(files));
    results.push(...checkSqlInjectionQuery(files));
    results.push(...checkCredentialsInConfig(files));
    results.push(...checkCsrfDisabled(files));
    results.push(...checkXxeVulnerability(files));
    results.push(...checkRequestMappingWithoutMethod(files));
    results.push(...checkPermitAllOnSensitiveRoutes(files));
    results.push(...checkWeakHashAlgorithm(files));
    results.push(...checkCommandInjection(files));
    results.push(...checkCorsWildcard(files));
    results.push(...checkHardcodedJwtSecret(files));
    results.push(...checkStackTraceInResponse(files));
    results.push(...checkSpringSecurityDebug(files));
    results.push(...checkInsecureRandom(files));
    results.push(...checkMassAssignment(files));

    // If project-wide Spring Security is active, downgrade auth-absence
    // findings to "low" confidence (the framework may handle auth globally).
    if (projectSecurity.hasSpringSecurityConfig) {
      for (const result of results) {
        if (
          result.checkId === "java:permit-all-sensitive" ||
          result.checkId === "java:request-mapping-no-method"
        ) {
          result.confidence = "low";
        }
      }
    }

    // If project has rate-limiting libraries, suppress rate-limiting findings
    // (bucket4j / resilience4j / Spring @RateLimiter).
    // (No explicit rate-limit check yet, but leaving the hook for future checks.)

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "java-agent",
      version: "1.0.0",
      technologies: ["java", "spring", "kotlin"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      { id: "java:actuator-exposed",       name: "Spring Actuator endpoints exposed",                    severity: "HIGH"     },
      { id: "java:log4shell",              name: "Log4Shell JNDI injection",                             severity: "CRITICAL" },
      { id: "java:unsafe-deserialization", name: "Unsafe Java deserialization",                          severity: "CRITICAL" },
      { id: "java:sql-injection-query",    name: "SQL injection via @Query",                             severity: "CRITICAL" },
      { id: "java:credentials-in-config",  name: "Hardcoded credentials in config",                      severity: "CRITICAL" },
      { id: "java:csrf-disabled",          name: "CSRF protection disabled",                             severity: "HIGH"     },
      { id: "java:xxe",                    name: "XML External Entity (XXE) vulnerability",              severity: "HIGH"     },
      { id: "java:request-mapping-no-method", name: "@RequestMapping without HTTP method restriction",   severity: "MEDIUM"   },
      { id: "java:permit-all-sensitive",   name: "Sensitive route accessible without authentication",    severity: "HIGH"     },
      { id: "java:weak-hash",              name: "Weak hash algorithm (MD5/SHA-1)",                      severity: "HIGH"     },
      { id: "java:command-injection",      name: "Command injection via Runtime.exec()",                 severity: "CRITICAL" },
      { id: "java:cors-wildcard",          name: "CORS wildcard allows all origins",                     severity: "MEDIUM"   },
      { id: "java:hardcoded-jwt-secret",   name: "Hardcoded JWT secret",                                 severity: "CRITICAL" },
      { id: "java:stack-trace-exposure",   name: "Stack trace exposed via printStackTrace()",            severity: "MEDIUM"   },
      { id: "java:spring-security-debug",  name: "Spring Security debug mode enabled",                   severity: "HIGH"     },
      { id: "java:insecure-random",         name: "java.util.Random used for security-sensitive value",    severity: "HIGH"     },
      { id: "java:mass-assignment",         name: "Mass assignment via unvalidated model binding",         severity: "MEDIUM"   },
    ];
  }
}

// --- Helpers ---

function isJavaFile(filePath: string): boolean {
  return filePath.endsWith(".java");
}

function isConfigFile(filePath: string): boolean {
  return (
    filePath.endsWith(".properties") ||
    filePath.endsWith(".yml") ||
    filePath.endsWith(".yaml")
  );
}

// --- Project-level security detection ---
// Scan all files for global Spring Security annotations or rate-limiting
// libraries. Used to downgrade confidence on absence-based findings.

interface ProjectSecurityInfo {
  /** True when @EnableWebSecurity, @EnableGlobalMethodSecurity, or
   *  @EnableMethodSecurity is found anywhere in the project. */
  hasSpringSecurityConfig: boolean;
  /** True when bucket4j, resilience4j, or @RateLimiter is found. */
  hasRateLimiting: boolean;
}

function detectProjectLevelSecurity(files: Map<string, string>): ProjectSecurityInfo {
  let hasSpringSecurityConfig = false;
  let hasRateLimiting = false;

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    if (
      /@EnableWebSecurity/.test(content) ||
      /@EnableGlobalMethodSecurity/.test(content) ||
      /@EnableMethodSecurity/.test(content)
    ) {
      hasSpringSecurityConfig = true;
    }

    if (
      /@RateLimiter/.test(content) ||
      /bucket4j/.test(content) ||
      /resilience4j/.test(content)
    ) {
      hasRateLimiting = true;
    }

    if (hasSpringSecurityConfig && hasRateLimiting) break;
  }

  return { hasSpringSecurityConfig, hasRateLimiting };
}

// --- Check 1: Spring Actuator exposed ---
// HIGH, CWE-200
// Detects management.endpoints.web.exposure.include with dangerous values.

function checkActuatorExposed(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isConfigFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // --- Properties file format: single line contains full dotted key ---
      if (/management\.endpoints\.web\.exposure\.include/.test(line)) {
        // Handle both properties format (=*) and inline YAML (: * or : "*")
        if (/[=:]\s*["']?\*["']?/.test(line) || /[=:]\s*.*(?:env|configprops|heapdump)/.test(line)) {
          results.push(buildActuatorFinding(filePath, i + 1));
        }
        continue;
      }

      // --- YAML multi-line format: look for `include:` key with dangerous value
      //     when `exposure:` appeared in the preceding few lines ---
      if (/^\s+include\s*:/.test(line)) {
        const value = line.split(":").slice(1).join(":").trim().replace(/["']/g, "");
        const isDangerous =
          value === "*" ||
          /(?:env|configprops|heapdump)/.test(value);

        if (isDangerous) {
          // Confirm we are in an actuator exposure context by scanning back
          const lookBehind = lines.slice(Math.max(0, i - 5), i).join("\n");
          if (/exposure\s*:/.test(lookBehind) && /endpoints\s*:/.test(lookBehind)) {
            results.push(buildActuatorFinding(filePath, i + 1));
          }
        }
      }
    }
  }

  return results;
}

function buildActuatorFinding(filePath: string, line: number): ScanResult {
  return {
    checkId: "java:actuator-exposed",
    title: "Spring Actuator endpoints exposed",
    severity: "HIGH",
    confidence: "high",
    file: filePath,
    line,
    description:
      "Actuator endpoints are configured to expose sensitive information (*, env, configprops, or heapdump). " +
      "These endpoints can leak environment variables, configuration properties, memory heap dumps, and other " +
      "sensitive runtime data to anyone who can reach them.",
    fix: "Restrict actuator endpoints: management.endpoints.web.exposure.include=health,info",
    cwe: "CWE-200",
  };
}

// --- Check 2: Log4j / Log4Shell ---
// CRITICAL, CWE-917
// Detects the literal JNDI lookup string in Java source files.

function checkLog4Shell(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.includes("${jndi:")) {
        results.push({
          checkId: "java:log4shell",
          title: "Log4Shell JNDI lookup string detected",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "A JNDI lookup string '${jndi:' was found in the source code. If this string is logged via Log4j 2.x " +
            "before version 2.17.1, it triggers the Log4Shell vulnerability (CVE-2021-44228), enabling remote code " +
            "execution by an attacker who can control any logged value.",
          fix: "Update Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true.",
          cwe: "CWE-917",
        });
      }
    }
  }

  return results;
}

// --- Check 3: Unsafe deserialization ---
// CRITICAL, CWE-502
// Detects ObjectInputStream instantiation in Java source.

function checkUnsafeDeserialization(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip comments
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      if (/new\s+ObjectInputStream\s*\(/.test(line)) {
        results.push({
          checkId: "java:unsafe-deserialization",
          title: "Unsafe Java deserialization via ObjectInputStream",
          severity: "CRITICAL",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "ObjectInputStream.readObject() can execute arbitrary code when deserializing untrusted data. " +
            "Attackers who control the serialized input can trigger gadget chains leading to remote code execution, " +
            "arbitrary file write, or SSRF.",
          fix: "Use JSON/Protocol Buffers instead. If ObjectInputStream is needed, use a whitelist filter.",
          cwe: "CWE-502",
        });
      }
    }
  }

  return results;
}

// --- Check 4: SQL injection via @Query with string concatenation ---
// CRITICAL, CWE-89
// Detects @Query annotations that build queries via string concatenation
// but DO NOT use positional (?1, ?2) or named (:paramName) parameter markers.

function checkSqlInjectionQuery(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (!/@Query\s*\(/.test(line)) continue;

      // Look at the current line and the next few lines for string concatenation
      const snippet = lines.slice(i, Math.min(i + 5, lines.length)).join("\n");

      // Only flag actual string concatenation (the + operator after a closing quote)
      if (!/"\s*\+/.test(snippet)) continue;

      // Do NOT flag if the snippet contains named (:param) or positional (?1) markers.
      // These indicate the query is parameterized even though there is a + in the
      // annotation string (e.g., multi-line string with a compile-time constant).
      if (/\?[0-9]+/.test(snippet) || /:[a-zA-Z][a-zA-Z0-9]*/.test(snippet)) continue;

      results.push({
        checkId: "java:sql-injection-query",
        title: "SQL injection via @Query with string concatenation",
        severity: "CRITICAL",
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description:
          "The @Query annotation uses string concatenation (+) to build the query. " +
          "Concatenating user-controlled values into JPQL or native SQL queries allows attackers " +
          "to manipulate the query structure and access or modify unauthorized data.",
        fix: 'Use named parameters: @Query("SELECT u FROM User u WHERE u.name = :name")',
        cwe: "CWE-89",
      });
    }
  }

  return results;
}

// --- Check 5: Credentials in config files ---
// CRITICAL, CWE-798
// Detects hardcoded passwords, secrets, keys, or tokens in .properties/.yml files.

function checkCredentialsInConfig(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];
  // Matches: password=secret123, spring.datasource.password: mypassword, etc.
  // Skips: values that are property references like ${DB_PASSWORD}
  const credentialPattern = /(?:password|secret|key|token)\s*[=:]\s*([^\s${}]{4,})/i;

  for (const [filePath, content] of files) {
    if (!isConfigFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip blank lines and comments
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      // Skip lines that are YAML keys with no value (e.g., "password:")
      // Skip lines referencing env vars (${...})
      if (trimmed.includes("${")) continue;

      const match = credentialPattern.exec(line);
      if (match) {
        const value = match[1];
        // Skip obvious placeholders
        if (/^(?:your[_-]|change[_-]me|placeholder|example|here|todo|xxx|n\/a|null|true|false|\d+)$/i.test(value)) {
          continue;
        }

        results.push({
          checkId: "java:credentials-in-config",
          title: "Hardcoded credential in configuration file",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "A password, secret, key, or token appears to be hardcoded directly in a configuration file. " +
            "Committing credentials to source control exposes them to anyone with repository access " +
            "and they persist in git history even after removal.",
          fix: "Use environment variables or a vault: spring.datasource.password=${DB_PASSWORD}",
          cwe: "CWE-798",
        });
      }
    }
  }

  return results;
}

// --- Check 6: CSRF disabled ---
// HIGH, CWE-352
// Detects Spring Security configuration that explicitly disables CSRF protection.

function checkCsrfDisabled(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  // Patterns for different Spring Security versions
  const csrfDisablePatterns = [
    /\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)/,
    /csrf\s*\(\s*csrf\s*->\s*csrf\.disable\s*\(\s*\)/,
    /\.csrf\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)/,
  ];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      if (csrfDisablePatterns.some((pattern) => pattern.test(line))) {
        results.push({
          checkId: "java:csrf-disabled",
          title: "CSRF protection disabled",
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "Spring Security's CSRF protection has been explicitly disabled. " +
            "CSRF allows attackers to trick authenticated users into performing unintended actions " +
            "(state-changing requests) on your application.",
          fix: "Enable CSRF protection for browser-facing endpoints.",
          cwe: "CWE-352",
        });
      }
    }
  }

  return results;
}

// --- Check 7: XXE vulnerability ---
// HIGH, CWE-611
// Detects DocumentBuilderFactory usage without disabling DTD features.
// Uses a 10-line lookahead (extended from 5) to reduce false positives on
// multi-statement builder setup patterns.

function checkXxeVulnerability(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (!/DocumentBuilderFactory\.newInstance\s*\(\s*\)/.test(line)) continue;

      // Look within 10 lines after this call for .setFeature (extended from 5)
      const lookAhead = lines.slice(i, Math.min(i + 11, lines.length)).join("\n");
      if (!lookAhead.includes(".setFeature")) {
        results.push({
          checkId: "java:xxe",
          title: "XML External Entity (XXE) vulnerability",
          severity: "HIGH",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "DocumentBuilderFactory is instantiated without disabling DTD processing. " +
            "An attacker who can control XML input can exploit this to read local files, " +
            "perform SSRF attacks, or cause denial of service via entity expansion.",
          fix: 'Disable DTDs: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
          cwe: "CWE-611",
        });
      }
    }
  }

  return results;
}

// --- Check 8: @RequestMapping without HTTP method restriction ---
// MEDIUM, CWE-749
// Detects @RequestMapping annotations that omit a method= attribute.
// NOT flagged when the file has a class-level @Secured or @PreAuthorize
// combined with @RestController, which indicates the class is already
// protected via method security — making the HTTP method ambiguity lower risk.

function checkRequestMappingWithoutMethod(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    // Check file-wide for class-level security annotations alongside @RestController.
    // If both are present, the developer is using method-security; skip this file.
    const hasRestController = /@RestController/.test(content);
    const hasClassLevelSecurity =
      /@Secured\s*\(/.test(content) || /@PreAuthorize\s*\(/.test(content);

    if (hasRestController && hasClassLevelSecurity) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match @RequestMapping with a path string but no method= attribute
      if (!/@RequestMapping\s*\(/.test(line)) continue;
      if (/method\s*=/.test(line)) continue;

      // Only flag if it has a value/path (not bare @RequestMapping on a class without value)
      if (!/@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']/.test(line)) continue;

      results.push({
        checkId: "java:request-mapping-no-method",
        title: "@RequestMapping without HTTP method restriction",
        severity: "MEDIUM",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          "@RequestMapping without a method= attribute accepts all HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.). " +
          "This widens the attack surface unnecessarily. A CSRF-unprotected endpoint might inadvertently accept POST " +
          "requests, or a read-only endpoint might accept state-changing methods.",
        fix: "Specify HTTP method: @GetMapping, @PostMapping, or @RequestMapping(method = RequestMethod.GET)",
        cwe: "CWE-749",
      });
    }
  }

  return results;
}

// --- Check 9: permitAll on sensitive routes ---
// HIGH, CWE-306
// Heuristic: only flags `permitAll()` when it appears on the SAME LINE as a
// sensitive path pattern. We do NOT attempt to parse the Spring Security DSL
// across multiple lines because the DSL ordering matters (rules are evaluated
// in declaration order) and multi-line regex is too error-prone.
// Confidence is "low" for the same reason: a later `.authenticated()` rule
// could override this for some paths.

function checkPermitAllOnSensitiveRoutes(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];
  // Sensitive path fragments that should require authentication
  const sensitivePaths = ["/admin", "/api/", "/manage", "/config", "/users", "/settings", "/account"];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      // Only examine lines that contain BOTH permitAll() AND a sensitive path.
      // Multi-line DSL chaining is intentionally ignored — too ambiguous.
      if (!line.includes("permitAll")) continue;

      const hasSensitivePath = sensitivePaths.some((path) => line.includes(path));
      if (hasSensitivePath) {
        results.push({
          checkId: "java:permit-all-sensitive",
          title: "Sensitive route accessible without authentication",
          severity: "HIGH",
          confidence: "low",
          file: filePath,
          line: i + 1,
          description:
            "A sensitive path (/admin, /api/, /manage, /config, /users, /settings, or /account) appears on the " +
            "same line as permitAll(), suggesting it may be accessible without authentication. " +
            "Spring Security DSL ordering matters — verify this rule is not overridden by a later authenticated() call.",
          fix: "Require authentication for sensitive endpoints.",
          cwe: "CWE-306",
        });
      }
    }
  }

  return results;
}

// --- Check 10: Weak hash algorithm ---
// HIGH, CWE-328
// Detects MessageDigest.getInstance calls using MD5 or SHA-1.

function checkWeakHashAlgorithm(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];
  const weakAlgorithmPattern = /MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']\s*\)/;

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = weakAlgorithmPattern.exec(line);

      if (match) {
        results.push({
          checkId: "java:weak-hash",
          title: `Weak hash algorithm: ${match[1]}`,
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            `${match[1]} is a cryptographically broken hash algorithm. MD5 and SHA-1 are vulnerable to collision ` +
            "attacks and should not be used for security-sensitive purposes such as password hashing, " +
            "digital signatures, or integrity verification.",
          fix: 'Use SHA-256 or SHA-512: MessageDigest.getInstance("SHA-256")',
          cwe: "CWE-328",
        });
      }
    }
  }

  return results;
}

// --- Check 11: Command injection ---
// CRITICAL, CWE-78
// Only flags Runtime.exec() or ProcessBuilder when the command is built via
// string concatenation (e.g. exec("cmd " + userInput)).
// exec(new String[]{"cmd", arg}) passes separate arguments to the OS and
// does NOT invoke a shell, so it is NOT flagged.

function checkCommandInjection(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      // Runtime.exec() with string concatenation — dangerous because a single
      // concatenated string is passed to a shell and can contain metacharacters.
      // exec(new String[]{...}) is safe; we skip those by checking that the
      // argument is NOT an array literal (no "new String[" on the same line).
      const hasRuntimeExec = /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/.test(line);
      const hasProcessBuilder = /new\s+ProcessBuilder\s*\(/.test(line);

      if (!hasRuntimeExec && !hasProcessBuilder) continue;

      // Skip array-based exec calls — they do not invoke a shell.
      if (/new\s+String\s*\[/.test(line)) continue;

      // Only flag when string concatenation is present in the same statement.
      if (line.includes("+")) {
        results.push({
          checkId: "java:command-injection",
          title: "Command injection via Runtime.exec() with dynamic input",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "Runtime.getRuntime().exec() or ProcessBuilder is called with a dynamically constructed command " +
            "(string concatenation with +). If any part of the command string comes from user input, an attacker " +
            "can inject shell metacharacters to execute arbitrary commands on the server.",
          fix: "Avoid Runtime.exec(). If necessary, use ProcessBuilder with a pre-validated, fixed array of arguments.",
          cwe: "CWE-78",
        });
      }
    }
  }

  return results;
}

// --- Check 12: CORS wildcard ---
// MEDIUM, CWE-942
// Detects Spring @CrossOrigin with wildcard origins or allowedOrigins("*").

function checkCorsWildcard(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  const corsPatterns = [
    // @CrossOrigin(origins = "*")
    /@CrossOrigin\s*\([^)]*origins\s*=\s*["']\*["']/,
    // @CrossOrigin with no arguments (defaults to all origins)
    /@CrossOrigin\s*(?:\(\s*\))?\s*$/,
    // allowedOrigins("*")
    /allowedOrigins\s*\(\s*["']\*["']\s*\)/,
  ];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      if (corsPatterns.some((pattern) => pattern.test(trimmed))) {
        results.push({
          checkId: "java:cors-wildcard",
          title: "CORS wildcard allows all origins",
          severity: "MEDIUM",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "CORS is configured to allow requests from any origin (*). " +
            "This allows any website to make authenticated cross-origin requests to your API, " +
            "potentially leaking user data or enabling cross-site request forgery.",
          fix: 'Restrict CORS: @CrossOrigin(origins = "https://yourdomain.com")',
          cwe: "CWE-942",
        });
      }
    }
  }

  return results;
}

// --- Check 13: Hardcoded JWT secret ---
// CRITICAL, CWE-798
// Detects JWT secret/signing keys hardcoded as string literals.
// Confidence is "high" only when the literal value is present on the same
// line as the jwt/JWT keyword AND is not a Spring @Value injection.

function checkHardcodedJwtSecret(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];
  // Matches: secret = "...", key = "...", signing = "..." in JWT-adjacent context
  const jwtSecretPattern = /(?:secret|key|signing)\s*=\s*["']([^"']{8,})["']/i;

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      // Only flag lines in JWT-relevant context
      if (!/jwt/i.test(line) && !/JWT/i.test(line)) continue;

      // Skip @Value-injected fields — those read from environment/config
      if (/@Value\s*\(/.test(line)) continue;

      const match = jwtSecretPattern.exec(line);
      if (match) {
        const value = match[1];
        // Skip obvious placeholders
        if (/^(?:your[_-]|change[_-]me|placeholder|example|here|xxx)$/i.test(value)) continue;

        results.push({
          checkId: "java:hardcoded-jwt-secret",
          title: "Hardcoded JWT secret in source code",
          severity: "CRITICAL",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "A JWT secret or signing key is hardcoded as a string literal. " +
            "Anyone with access to the source code can forge valid JWT tokens for any user, " +
            "including administrator accounts.",
          fix: "Store JWT secrets in environment variables or a secrets manager.",
          cwe: "CWE-798",
        });
      }
    }
  }

  return results;
}

// --- Check 14: Stack trace in response ---
// MEDIUM, CWE-209
// Detects printStackTrace() only when the surrounding catch block also contains
// a Response-related type or a return/throw statement. A bare printStackTrace()
// in a catch block that only logs is not flagged, because the stack trace never
// reaches the client in that case.

function checkStackTraceInResponse(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    // Skip test files — stack traces in tests are acceptable
    if (
      filePath.includes("/test/") ||
      filePath.includes("Test.java") ||
      filePath.endsWith("Tests.java")
    ) {
      continue;
    }

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      if (!/\.printStackTrace\s*\(\s*\)/.test(line)) continue;

      // Scan a window of ±8 lines to find the enclosing catch block context.
      // If the block contains Response/return/throw, the stack trace could
      // reach the client; flag it.
      const windowStart = Math.max(0, i - 4);
      const windowEnd = Math.min(lines.length, i + 9);
      const catchWindow = lines.slice(windowStart, windowEnd).join("\n");

      const couldLeakToClient =
        /Response/.test(catchWindow) ||
        /\breturn\b/.test(catchWindow) ||
        /\bthrow\b/.test(catchWindow);

      if (!couldLeakToClient) continue;

      results.push({
        checkId: "java:stack-trace-exposure",
        title: "Stack trace exposed via printStackTrace()",
        severity: "MEDIUM",
        confidence: "low",
        file: filePath,
        line: i + 1,
        description:
          "printStackTrace() outputs the full exception stack trace, which may be captured in HTTP " +
          "responses, logs visible to users, or error pages. This leaks internal implementation details " +
          "(class names, method signatures, library versions) that help attackers map the attack surface.",
        fix: "Log errors server-side. Return generic error messages to clients.",
        cwe: "CWE-209",
      });
    }
  }

  return results;
}

// --- Check 15: Spring Security debug mode ---
// HIGH, CWE-215
// Detects @EnableWebSecurity(debug = true).

function checkSpringSecurityDebug(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];
  const debugPattern = /@EnableWebSecurity\s*\([^)]*debug\s*=\s*true[^)]*\)/;

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      if (debugPattern.test(line)) {
        results.push({
          checkId: "java:spring-security-debug",
          title: "Spring Security debug mode enabled",
          severity: "HIGH",
          confidence: "high",
          file: filePath,
          line: i + 1,
          description:
            "@EnableWebSecurity(debug = true) logs every HTTP request including security-relevant information " +
            "such as headers, request parameters, and filter chain decisions. In production this generates " +
            "verbose logs that may expose sensitive data and slow down the application.",
          fix: "Set debug=false in production: @EnableWebSecurity(debug = false)",
          cwe: "CWE-215",
        });
      }
    }
  }

  return results;
}

// --- Check 16: Insecure randomness ---
// HIGH, CWE-330
// Detects java.util.Random used near security-sensitive variable names.

function checkInsecureRandom(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (!/new\s+Random\s*\(|ThreadLocalRandom\.current\(\)/.test(line)) continue;

      const contextStart = Math.max(0, i - 3);
      const contextEnd = Math.min(lines.length, i + 3);
      const context = lines.slice(contextStart, contextEnd).join("\n").toLowerCase();

      if (/token|secret|key|session|nonce|salt|otp|password|csrf/.test(context)) {
        results.push({
          checkId: "java:insecure-random",
          title: "java.util.Random used for security-sensitive value",
          severity: "HIGH",
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description:
            "java.util.Random is not cryptographically secure. For tokens, secrets, or session IDs, use java.security.SecureRandom instead.",
          fix: "SecureRandom random = new SecureRandom(); byte[] bytes = new byte[32]; random.nextBytes(bytes);",
          cwe: "CWE-330",
        });
      }
    }
  }

  return results;
}

// --- Check 17: Mass assignment ---
// MEDIUM, CWE-915
// Detects @RequestBody without @Valid on the same method signature,
// or @ModelAttribute passed directly to repository.save().

function checkMassAssignment(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isJavaFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // @RequestBody without @Valid — spreads entire JSON body into object
      if (/@RequestBody\s+(?!@Valid)/.test(line)) {
        // Look ahead for repository.save() without field filtering
        const ahead = lines.slice(i, Math.min(i + 10, lines.length)).join("\n");
        if (/\.save\s*\(|\.saveAndFlush\s*\(|\.persist\s*\(/.test(ahead)) {
          results.push({
            checkId: "java:mass-assignment",
            title: "Mass assignment — @RequestBody without @Valid to repository.save()",
            severity: "MEDIUM",
            confidence: "low",
            file: filePath,
            line: i + 1,
            description:
              "The request body is bound directly to an entity and saved without validation. An attacker can submit extra fields (role, isAdmin, price) to modify unauthorized properties.",
            fix: "Use a DTO with only the allowed fields, add @Valid for validation, and map explicitly to the entity.",
            cwe: "CWE-915",
          });
        }
      }
    }
  }

  return results;
}
