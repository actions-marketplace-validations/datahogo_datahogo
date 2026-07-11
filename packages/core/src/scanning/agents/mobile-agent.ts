// Mobile ecosystem security scanner agent.
// Detects React Native, Expo, and Flutter projects and scans for
// mobile-specific security vulnerabilities: hardcoded keys, insecure storage,
// excessive permissions, debug code, missing certificate pinning, and more.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

// ---------------------------------------------------------------------------
// File type helpers
// ---------------------------------------------------------------------------

function isJSFile(path: string): boolean {
  return (
    path.endsWith(".js") ||
    path.endsWith(".jsx") ||
    path.endsWith(".ts") ||
    path.endsWith(".tsx")
  );
}

function isDartFile(path: string): boolean {
  return path.endsWith(".dart");
}

// ---------------------------------------------------------------------------
// Agent class
// ---------------------------------------------------------------------------

export class MobileScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const [filePath, content] of files) {
      // Expo / React Native: app.json containing "expo"
      if (filePath === "app.json" && content.includes('"expo"')) {
        return true;
      }

      // Flutter: pubspec.yaml containing "flutter"
      if (filePath === "pubspec.yaml" && content.includes("flutter")) {
        return true;
      }

      // Android: AndroidManifest.xml anywhere in the tree
      if (filePath === "AndroidManifest.xml" || filePath.includes("AndroidManifest.xml")) {
        return true;
      }

      // React Native: package.json with react-native dependency
      if (filePath === "package.json" && content.includes('"react-native"')) {
        return true;
      }
    }

    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    // Project-level checks (run once, not per file)
    results.push(...checkMissingCertificatePinning(files));

    for (const [filePath, content] of files) {
      // Check 1: Hardcoded API keys (JS + Dart files)
      if (isJSFile(filePath) || isDartFile(filePath)) {
        results.push(...checkHardcodedApiKeys(filePath, content));
      }

      // Check 2: AsyncStorage for sensitive data (JS/TS files only)
      if (isJSFile(filePath)) {
        results.push(...checkAsyncStorageSensitiveData(filePath, content));
        results.push(...checkWebViewJavaScript(filePath, content));
        results.push(...checkReactNativeDotenvExposure(filePath, content));
        results.push(...checkExpoConstantsExposure(filePath, content));
        results.push(...checkDebugCodeReactNative(filePath, content));
        results.push(...checkBiometricWithoutServerVerification(filePath, content));
        results.push(...checkInsecureDataStorageJS(filePath, content));
      }

      // Check 3: SharedPreferences for sensitive data (Dart files only)
      if (isDartFile(filePath)) {
        results.push(...checkSharedPreferencesSensitiveData(filePath, content));
        results.push(...checkFlutterDebugEndpoint(filePath, content));
        results.push(...checkDebugCodeFlutter(filePath, content));
      }

      // Check 4: Excessive Android permissions (AndroidManifest.xml)
      if (filePath === "AndroidManifest.xml" || filePath.endsWith("/AndroidManifest.xml")) {
        results.push(...checkExcessiveAndroidPermissions(filePath, content));
        results.push(...checkDeepLinksWithoutVerification(filePath, content));
      }

      // Check 5: Expo config with secrets (app.json, app.config.js, eas.json)
      if (
        filePath === "app.json" ||
        filePath === "app.config.js" ||
        filePath === "app.config.ts" ||
        filePath === "eas.json"
      ) {
        results.push(...checkExpoConfigWithSecrets(filePath, content));
      }
    }

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "mobile-agent",
      version: "1.0.0",
      technologies: ["react-native", "expo", "dart", "flutter"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      {
        id: "mobile:hardcoded-api-keys",
        name: "Hardcoded API keys in mobile code",
        severity: "CRITICAL",
      },
      {
        id: "mobile:async-storage-sensitive-data",
        name: "Sensitive data stored in AsyncStorage",
        severity: "HIGH",
      },
      {
        id: "mobile:shared-preferences-sensitive-data",
        name: "Sensitive data stored in SharedPreferences",
        severity: "HIGH",
      },
      {
        id: "mobile:excessive-android-permissions",
        name: "Excessive Android permissions declared",
        severity: "MEDIUM",
      },
      {
        id: "mobile:expo-config-secrets",
        name: "Secret value in Expo config extra block",
        severity: "CRITICAL",
      },
      {
        id: "mobile:deep-links-without-verification",
        name: "Deep link intent-filter missing autoVerify",
        severity: "HIGH",
      },
      {
        id: "mobile:webview-javascript-enabled",
        name: "WebView with JavaScript enabled and no URL whitelist",
        severity: "HIGH",
      },
      {
        id: "mobile:missing-certificate-pinning",
        name: "No certificate pinning detected",
        severity: "MEDIUM",
      },
      {
        id: "mobile:debug-code-react-native",
        name: "Excessive console.log calls without __DEV__ guard",
        severity: "MEDIUM",
      },
      {
        id: "mobile:debug-code-flutter",
        name: "Excessive print/debugPrint calls without kDebugMode guard",
        severity: "MEDIUM",
      },
      {
        id: "mobile:biometric-without-server-verification",
        name: "Biometric authentication without server-side verification",
        severity: "MEDIUM",
      },
      {
        id: "mobile:react-native-dotenv-exposure",
        name: "Sensitive variable exposed via react-native-dotenv",
        severity: "HIGH",
      },
      {
        id: "mobile:flutter-debug-endpoint",
        name: "Insecure HTTP endpoint in Flutter source",
        severity: "LOW",
      },
      {
        id: "mobile:expo-constants-exposure",
        name: "Sensitive key accessed via Expo Constants.extra",
        severity: "HIGH",
      },
      {
        id: "mobile:insecure-data-storage-js",
        name: "Insecure use of localStorage in React Native",
        severity: "MEDIUM",
      },
    ];
  }
}

// ---------------------------------------------------------------------------
// Check 1: Hardcoded API keys (CWE-798)
// ---------------------------------------------------------------------------

// Known key patterns with tight boundaries to reduce false positives.
const API_KEY_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "AWS Access Key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "Stripe Secret Key", pattern: /\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b/ },
  { name: "Firebase/Google API Key", pattern: /\bAIzaSy[a-zA-Z0-9_-]{33}\b/ },
  // JWT: header.payload — eyJ...eyJ pattern
  { name: "JWT Token", pattern: /eyJ[a-zA-Z0-9_-]{20,}\.eyJ/ },
  // Supabase service_role or anon key (JWT starting with eyJ)
  { name: "Supabase Service/Anon Key", pattern: /supabase[^'"\n]*(?:service_role|anon)[^'"\n]*eyJ[a-zA-Z0-9_-]{20,}/ },
];

// Placeholder / example strings that should not trigger alerts.
const PLACEHOLDER_PATTERNS = [
  /your[_-]?(?:api[_-]?)?key/i,
  /placeholder/i,
  /xxx+/i,
  /\*{4,}/i,
  /\bexample\b/i,
  /replace[_-]?me/i,
  /\btest\b(?!_)/i,
  /\bdummy\b/i,
];

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  // JS/TS single-line comment
  if (trimmed.startsWith("//")) return true;
  // Block comment fragments
  if (trimmed.startsWith("*") || trimmed.startsWith("/*")) return true;
  // Dart/Yaml/Python hash comments
  if (trimmed.startsWith("#")) return true;
  return false;
}

function checkHardcodedApiKeys(filePath: string, content: string): ScanResult[] {
  // Skip .env.example files — they are intentionally placeholder files.
  if (filePath.includes(".env.example") || filePath.includes(".env.sample")) {
    return [];
  }
  // Skip test files.
  if (
    filePath.includes("__tests__") ||
    filePath.includes(".test.") ||
    filePath.includes(".spec.")
  ) {
    return [];
  }

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comment lines.
    if (isCommentLine(line)) continue;

    for (const { name, pattern } of API_KEY_PATTERNS) {
      if (pattern.test(line)) {
        // Extract the matched value and check if it is a placeholder.
        const match = line.match(pattern);
        if (match && isPlaceholder(match[0])) continue;

        results.push({
          checkId: "mobile:hardcoded-api-keys",
          title: `Hardcoded ${name} in source code`,
          severity: "CRITICAL",
          // AWS/Stripe keys have a specific, unambiguous format — high confidence.
          // Firebase/Google key format is also very specific — high confidence.
          confidence: "high",
          file: filePath,
          line: i + 1,
          description: `A ${name} appears to be hardcoded directly in source code. If this repository is ever made public or the code is leaked, attackers gain direct access to your services.`,
          fix: "Use environment variables or a secrets manager. Never commit API keys to source code.",
          cwe: "CWE-798",
        });
        // Report one finding per pattern per line.
        break;
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 2: AsyncStorage for sensitive data (CWE-922)
// ---------------------------------------------------------------------------

const SENSITIVE_KEY_PATTERN = /(?:token|password|secret|key|jwt|session|auth|credential)/i;

function checkAsyncStorageSensitiveData(filePath: string, content: string): ScanResult[] {
  // AsyncStorage is React Native specific — JS/TS files only.
  if (!content.includes("AsyncStorage")) return [];

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    // Look for AsyncStorage.setItem( with a key that sounds sensitive.
    if (/AsyncStorage\.setItem\s*\(/.test(line)) {
      // Extract the first argument (the key).
      const keyMatch = line.match(/AsyncStorage\.setItem\s*\(\s*['"`]([^'"`]+)['"`]/);
      const keyName = keyMatch ? keyMatch[1] : line;

      if (SENSITIVE_KEY_PATTERN.test(keyName)) {
        results.push({
          checkId: "mobile:async-storage-sensitive-data",
          title: "Sensitive data stored in AsyncStorage",
          severity: "HIGH",
          // Key name matches a sensitive pattern — medium confidence.
          // The actual value might be benign, but the key name is a clear signal.
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description: `AsyncStorage is unencrypted and stores data in plaintext on the device filesystem. Storing sensitive values like "${keyName}" here exposes them to any app with file system access or physical device access.`,
          fix: "Use react-native-keychain or expo-secure-store for sensitive data.",
          cwe: "CWE-922",
        });
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 3: SharedPreferences for sensitive data (CWE-922)
// ---------------------------------------------------------------------------

function checkSharedPreferencesSensitiveData(filePath: string, content: string): ScanResult[] {
  if (!content.includes("SharedPreferences")) return [];

  // If the file uses a secure alternative, skip it.
  if (
    content.includes("encrypted_shared_preferences") ||
    content.includes("flutter_secure_storage")
  ) {
    return [];
  }

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    // Look for .setString( or .setInt( etc. with a sensitive key name.
    if (/\bprefs\b.*\.set(?:String|Int|Bool|Double)\s*\(/.test(line) || /SharedPreferences.*set/.test(line)) {
      const keyMatch = line.match(/\.set(?:String|Int|Bool|Double)\s*\(\s*['"`]([^'"`]+)['"`]/);
      const keyName = keyMatch ? keyMatch[1] : "";

      if (SENSITIVE_KEY_PATTERN.test(keyName)) {
        results.push({
          checkId: "mobile:shared-preferences-sensitive-data",
          title: "Sensitive data stored in SharedPreferences",
          severity: "HIGH",
          // Key name matches sensitive pattern — medium confidence.
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description: `SharedPreferences stores data unencrypted on the device. Storing "${keyName}" here exposes it to rooted devices, backups, or apps with READ_EXTERNAL_STORAGE permission.`,
          fix: "Use flutter_secure_storage or encrypted_shared_preferences for sensitive data.",
          cwe: "CWE-922",
        });
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 4: Excessive Android permissions (CWE-250)
// ---------------------------------------------------------------------------

const SENSITIVE_ANDROID_PERMISSIONS = [
  "READ_CONTACTS",
  "READ_SMS",
  "READ_CALL_LOG",
  "READ_PHONE_STATE",
  "CAMERA",
  "RECORD_AUDIO",
  "ACCESS_FINE_LOCATION",
];

// Threshold: flag if 6 or more sensitive permissions exist.
// Common apps legitimately need 4-5; 6+ is a strong signal of over-permissioning.
const PERMISSION_THRESHOLD = 6;

function checkExcessiveAndroidPermissions(filePath: string, content: string): ScanResult[] {
  const foundPermissions: string[] = [];

  for (const perm of SENSITIVE_ANDROID_PERMISSIONS) {
    if (content.includes(perm)) {
      foundPermissions.push(perm);
    }
  }

  if (foundPermissions.length < PERMISSION_THRESHOLD) return [];

  return [
    {
      checkId: "mobile:excessive-android-permissions",
      title: "Excessive Android permissions declared",
      severity: "MEDIUM",
      // Absence-based finding — low confidence.
      confidence: "low",
      file: filePath,
      line: 1,
      description: `AndroidManifest.xml declares ${foundPermissions.length} sensitive permissions: ${foundPermissions.join(", ")}. Requesting more permissions than needed increases attack surface and privacy risk.`,
      fix: "Request only permissions your app actually needs. Remove unused permissions.",
      cwe: "CWE-250",
    },
  ];
}

// ---------------------------------------------------------------------------
// Check 5: Expo config with secrets (CWE-798)
// ---------------------------------------------------------------------------

// Keys that indicate a real secret — must be a whole word or compound that is
// unambiguously secret-like. We exclude endpoint/url/host/path/base keys because
// those hold configuration values, not credentials.
//
// Strategy: match the JSON key name against an exact-word allowlist of secret
// indicators. The regex uses word boundaries to avoid matching "apiEndpoint" as
// containing "api" — only standalone "api" or compound forms like "api_key" match.
const SECRET_KEY_EXACT_WORDS = /^(?:secret|token|password|private_key|api_key|api_secret|apiKey|apiSecret|privateKey|accessToken|refreshToken|clientSecret)$/;

// Keys explicitly known to be safe configuration (not secrets).
const SAFE_EXPO_KEY_NAMES = new Set([
  "apiUrl",
  "apiEndpoint",
  "apiHost",
  "apiBase",
  "apiPath",
  "appId",
  "appName",
  "bundleId",
  "environment",
  "baseUrl",
]);

function isExpoConfigKeySecret(keyName: string): boolean {
  // Explicitly safe keys are never flagged.
  if (SAFE_EXPO_KEY_NAMES.has(keyName)) return false;
  // Match against exact secret key names.
  if (SECRET_KEY_EXACT_WORDS.test(keyName)) return true;
  // Fallback: key contains standalone secret/token/password as a word segment
  // separated by underscores or camelCase boundaries.
  return /(?:^|_)(?:secret|password|token|private_key|api_key)(?:_|$)/i.test(keyName);
}

function checkExpoConfigWithSecrets(filePath: string, content: string): ScanResult[] {
  // Only flag if there is an "extra" block.
  if (!content.includes('"extra"') && !content.includes("extra:")) return [];

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  // Track whether we are inside the "extra" block.
  let insideExtra = false;
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Enter "extra" block.
    if (/['"]extra['"]\s*:/.test(line)) {
      insideExtra = true;
      braceDepth = 0;
    }

    if (insideExtra) {
      // Count braces to know when extra block ends.
      for (const char of line) {
        if (char === "{") braceDepth++;
        if (char === "}") braceDepth--;
      }

      // If braceDepth drops below 0 we have left the extra block.
      if (braceDepth < 0) {
        insideExtra = false;
        continue;
      }

      // Look for key: "value" pairs where key looks sensitive and value is not process.env.
      const kvMatch = line.match(/['"](\w+)['"]\s*:\s*['"]([^'"]{4,})['"]/);
      if (kvMatch) {
        const keyName = kvMatch[1];
        const value = kvMatch[2];

        if (isExpoConfigKeySecret(keyName) && !isPlaceholder(value)) {
          results.push({
            checkId: "mobile:expo-config-secrets",
            title: "Secret value in Expo config extra block",
            severity: "CRITICAL",
            // Specific key name matches a known secret pattern — high confidence.
            confidence: "high",
            file: filePath,
            line: i + 1,
            description: `The "${keyName}" field in the Expo config "extra" block contains a hardcoded value "${value.slice(0, 8)}...". The extra block is bundled into the app binary and can be extracted with basic tooling.`,
            fix: "Use EAS Secrets or environment variables. Never put secrets in app.json/eas.json.",
            cwe: "CWE-798",
          });
        }
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 6: Deep links without verification (CWE-939)
// ---------------------------------------------------------------------------

function checkDeepLinksWithoutVerification(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];

  // Split into intent-filter blocks for targeted analysis.
  // Pattern: <intent-filter ...> ... </intent-filter>
  const intentFilterRegex = /<intent-filter([^>]*)>([\s\S]*?)<\/intent-filter>/g;
  let match: RegExpExecArray | null;

  // We need a line-number reference. Build a line-offset map.
  const lines = content.split("\n");
  const lineOffsets: number[] = [];
  let offset = 0;
  for (const line of lines) {
    lineOffsets.push(offset);
    offset += line.length + 1; // +1 for newline
  }

  function charOffsetToLine(charOffset: number): number {
    for (let i = lineOffsets.length - 1; i >= 0; i--) {
      if (charOffset >= lineOffsets[i]) return i + 1;
    }
    return 1;
  }

  while ((match = intentFilterRegex.exec(content)) !== null) {
    const attrs = match[1];
    const body = match[2];

    // Only flag HTTPS App Links (scheme="https" in data tag).
    if (!body.includes('android:scheme="https"')) continue;

    // Check if autoVerify is already set on this intent-filter.
    if (/android:autoVerify\s*=\s*["']true["']/.test(attrs)) continue;

    const lineNumber = charOffsetToLine(match.index);

    results.push({
      checkId: "mobile:deep-links-without-verification",
      title: "Deep link intent-filter missing autoVerify",
      severity: "HIGH",
      // Direct structural check — high confidence.
      confidence: "high",
      file: filePath,
      line: lineNumber,
      description: "An <intent-filter> handles HTTPS App Links but is missing android:autoVerify=\"true\". Without verification, any app can claim this URI scheme and intercept deep links, enabling link hijacking attacks.",
      fix: 'Add android:autoVerify="true" to intent-filter for App Links verification.',
      cwe: "CWE-939",
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 7: WebView with JavaScript enabled (CWE-749)
// ---------------------------------------------------------------------------

// Returns true if the originWhitelist value is a wildcard (unsafe).
// originWhitelist={['*']} or originWhitelist={["*"]} are wildcards.
// originWhitelist={["https://myapp.com"]} is specific — safe.
function isOriginWhitelistWildcard(content: string): boolean {
  // Match originWhitelist={[...]} to extract the array contents.
  const match = content.match(/originWhitelist\s*=\s*\{?\s*\[([^\]]*)\]/);
  if (!match) return false;
  const arrayContents = match[1].trim();
  // Wildcard: only contains "*" (possibly with quotes/spaces)
  return /^['"\s]*\*['"\s]*$/.test(arrayContents);
}

function checkWebViewJavaScript(filePath: string, content: string): ScanResult[] {
  // Only flag if WebView is used.
  if (!content.includes("WebView") && !content.includes("react-native-webview")) {
    return [];
  }

  // If javaScriptEnabled is not present, there is nothing to flag.
  if (!content.includes("javaScriptEnabled")) return [];

  // If originWhitelist is present with specific domains (not wildcard), the developer
  // is restricting URLs — skip. A wildcard originWhitelist={['*']} is still unsafe.
  if (content.includes("originWhitelist")) {
    if (!isOriginWhitelistWildcard(content)) {
      // Specific domains listed — safe.
      return [];
    }
    // Wildcard present — still flag, fall through.
  }

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (/javaScriptEnabled/.test(line)) {
      results.push({
        checkId: "mobile:webview-javascript-enabled",
        title: "WebView with JavaScript enabled and no URL whitelist",
        severity: "HIGH",
        // Medium confidence — requires javaScriptEnabled without a real whitelist.
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description: "WebView has JavaScript enabled without restricting the URLs it can load via originWhitelist. If a user can navigate to an attacker-controlled page, JavaScript can access native bridge APIs.",
        fix: "Restrict WebView to trusted URLs with originWhitelist. Validate all URLs.",
        cwe: "CWE-749",
      });
      // One finding per file is sufficient.
      break;
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 8: Missing certificate pinning (CWE-295) — project-level check
// ---------------------------------------------------------------------------

// Indicators that the project makes network calls.
const NETWORK_CALL_INDICATORS = [
  "fetch(",
  "axios",
  "http.get",
  "http.post",
  "Dio(",
  "HttpClient",
];

// Indicators that certificate pinning is configured.
const CERT_PINNING_INDICATORS = [
  "ssl-pinning",
  "TrustKit",
  "cert-pinner",
  "rn-ssl-pinning",
  "CertificatePinner",
  "cert_pinner",
];

function checkMissingCertificatePinning(files: Map<string, string>): ScanResult[] {
  let hasNetworkCalls = false;
  let hasPinning = false;

  for (const [, content] of files) {
    if (!hasNetworkCalls) {
      for (const indicator of NETWORK_CALL_INDICATORS) {
        if (content.includes(indicator)) {
          hasNetworkCalls = true;
          break;
        }
      }
    }

    if (!hasPinning) {
      for (const indicator of CERT_PINNING_INDICATORS) {
        if (content.includes(indicator)) {
          hasPinning = true;
          break;
        }
      }
    }

    if (hasNetworkCalls && hasPinning) break;
  }

  if (!hasNetworkCalls || hasPinning) return [];

  return [
    {
      checkId: "mobile:missing-certificate-pinning",
      title: "No certificate pinning detected",
      severity: "MEDIUM",
      // Absence-based finding — low confidence. App may pin via native config.
      confidence: "low",
      file: "project",
      line: 1,
      description: "The app makes network requests but no certificate pinning library is configured. Without pinning, a network attacker with a trusted CA certificate can perform a man-in-the-middle attack and intercept all HTTPS traffic.",
      fix: "Implement certificate pinning to prevent man-in-the-middle attacks.",
      cwe: "CWE-295",
    },
  ];
}

// ---------------------------------------------------------------------------
// Check 9: Debug code in production (CWE-489)
// ---------------------------------------------------------------------------

// Threshold: only flag files with 10+ debug calls.
// Occasional logging (< 10 calls) is normal in production code.
const DEBUG_CALL_THRESHOLD = 10;

function checkDebugCodeReactNative(filePath: string, content: string): ScanResult[] {
  // Skip test files.
  if (
    filePath.includes("__tests__") ||
    filePath.includes(".test.") ||
    filePath.includes(".spec.")
  ) {
    return [];
  }

  // If the file checks __DEV__ or NODE_ENV, the developer is guarding debug code — skip.
  if (content.includes("__DEV__") || content.includes("process.env.NODE_ENV")) return [];

  const lines = content.split("\n");
  const callLines: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    if (/console\.log\s*\(/.test(line)) {
      callLines.push(i + 1);
    }
  }

  if (callLines.length < DEBUG_CALL_THRESHOLD) return [];

  return [
    {
      checkId: "mobile:debug-code-react-native",
      title: "Excessive console.log calls without __DEV__ guard",
      severity: "MEDIUM",
      // Count-based threshold — low confidence due to subjectivity.
      confidence: "low",
      file: filePath,
      line: callLines[0],
      description: `Found ${callLines.length} console.log() calls in production code without a __DEV__ guard. Debug logs in production can leak sensitive runtime data and degrade performance.`,
      fix: "Wrap debug logging with __DEV__ (RN) or kDebugMode (Flutter) checks.",
      cwe: "CWE-489",
    },
  ];
}

function checkDebugCodeFlutter(filePath: string, content: string): ScanResult[] {
  // Skip test files.
  if (filePath.includes("_test.dart") || filePath.includes("/test/")) return [];

  // If the file checks kDebugMode or kReleaseMode, skip.
  if (content.includes("kDebugMode") || content.includes("kReleaseMode")) return [];

  const lines = content.split("\n");
  const callLines: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    if (/\bprint\s*\(/.test(line) || /\bdebugPrint\s*\(/.test(line)) {
      callLines.push(i + 1);
    }
  }

  if (callLines.length < DEBUG_CALL_THRESHOLD) return [];

  return [
    {
      checkId: "mobile:debug-code-flutter",
      title: "Excessive print/debugPrint calls without kDebugMode guard",
      severity: "MEDIUM",
      // Count-based threshold — low confidence due to subjectivity.
      confidence: "low",
      file: filePath,
      line: callLines[0],
      description: `Found ${callLines.length} print()/debugPrint() calls in production Dart code without a kDebugMode guard. Debug logs in production can leak sensitive runtime data.`,
      fix: "Wrap debug logging with __DEV__ (RN) or kDebugMode (Flutter) checks.",
      cwe: "CWE-489",
    },
  ];
}

// ---------------------------------------------------------------------------
// Check 10: Biometric auth without server verification (CWE-287)
// ---------------------------------------------------------------------------

const BIOMETRIC_CALL_PATTERNS = [
  /authenticateAsync\s*\(/,
  /authenticate\s*\(\)/,
  /LocalAuthentication/,
  /react-native-biometrics/,
  /local_auth/,
];

// Look for an API call (fetch, axios, http, or a function name strongly suggesting
// server interaction) within PROXIMITY_LINES lines of the biometric call.
// This avoids false positives from generic uses of "token" elsewhere in the file.
const PROXIMITY_LINES = 20;

const SERVER_CALL_PATTERNS = [
  /\bfetch\s*\(/,
  /\baxios\s*\./,
  /\bhttp\s*\./,
  // Function calls whose name strongly implies server/verify interaction
  /\bverify\w*(?:With|On|At)?Server\b/i,
  /\bserver\w*(?:Verify|Validate|Confirm)\b/i,
  /\bverifyWithServer\b/i,
  /verif(?:y|ication)/i,
  /\bserver\b/i,
];

function hasServerCallNearLine(lines: string[], biometricLineIndex: number): boolean {
  const start = Math.max(0, biometricLineIndex - 2);
  const end = Math.min(lines.length - 1, biometricLineIndex + PROXIMITY_LINES);

  for (let i = start; i <= end; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;
    if (SERVER_CALL_PATTERNS.some((p) => p.test(line))) return true;
  }
  return false;
}

function checkBiometricWithoutServerVerification(filePath: string, content: string): ScanResult[] {
  const hasBiometrics = BIOMETRIC_CALL_PATTERNS.some((p) => p.test(content));
  if (!hasBiometrics) return [];

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (BIOMETRIC_CALL_PATTERNS.some((p) => p.test(line))) {
      // Check within PROXIMITY_LINES for a server/API call.
      if (hasServerCallNearLine(lines, i)) return [];

      return [
        {
          checkId: "mobile:biometric-without-server-verification",
          title: "Biometric authentication without server-side verification",
          severity: "MEDIUM",
          // Hard to verify via static analysis — low confidence.
          confidence: "low",
          file: filePath,
          line: i + 1,
          description: "Biometric authentication is performed but no server-side token verification is detected near the authentication call. Client-side-only biometrics can be bypassed on rooted/jailbroken devices by hooking the authentication result.",
          fix: "Combine biometric auth with server-side token verification. Don't rely on client-side biometrics alone.",
          cwe: "CWE-287",
        },
      ];
    }
  }

  return [];
}

// ---------------------------------------------------------------------------
// Check 11: React Native dotenv exposure (CWE-200)
// ---------------------------------------------------------------------------

const DOTENV_SENSITIVE_NAMES = /(?:secret|key|token|password|api|private)/i;

function checkReactNativeDotenvExposure(filePath: string, content: string): ScanResult[] {
  // Look for import from react-native-dotenv or @env.
  if (!content.includes("react-native-dotenv") && !content.includes("from '@env'") && !content.includes('from "@env"')) {
    return [];
  }

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (
      (line.includes("react-native-dotenv") || line.includes("@env")) &&
      DOTENV_SENSITIVE_NAMES.test(line)
    ) {
      results.push({
        checkId: "mobile:react-native-dotenv-exposure",
        title: "Sensitive variable exposed via react-native-dotenv",
        severity: "HIGH",
        // Medium confidence — import name matches sensitive pattern.
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description: "react-native-dotenv bundles environment variables into the JavaScript bundle. Sensitive values imported via @env are visible to anyone who inspects the app binary.",
        fix: "Only expose non-sensitive config via dotenv. Use a native module for secrets.",
        cwe: "CWE-200",
      });
      break;
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 12: Flutter debug mode endpoint (CWE-489)
// ---------------------------------------------------------------------------

// Localhost and emulator addresses that are acceptable in HTTP context.
const LOCALHOST_PATTERNS = [
  "localhost",
  "127.0.0.1",
  "10.0.2.2", // Android emulator loopback to host machine
];

function isLocalhostUrl(line: string): boolean {
  return LOCALHOST_PATTERNS.some((h) => line.includes(h));
}

function checkFlutterDebugEndpoint(filePath: string, content: string): ScanResult[] {
  // Skip test files.
  if (filePath.includes("_test.dart") || filePath.includes("/test/")) return [];

  // If kReleaseMode or kDebugMode is used, the developer is conditionally setting endpoints.
  if (content.includes("kReleaseMode") || content.includes("kDebugMode")) return [];

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    // Flag http:// URLs (not https://) — likely debug/dev endpoints.
    // Exempt localhost, 127.0.0.1, and Android emulator address (10.0.2.2).
    if (/['"]http:\/\//.test(line) && !isLocalhostUrl(line)) {
      results.push({
        checkId: "mobile:flutter-debug-endpoint",
        title: "Insecure HTTP endpoint in Flutter source",
        severity: "LOW",
        // Low confidence — may be intentional for local/dev builds.
        confidence: "low",
        file: filePath,
        line: i + 1,
        description: "A non-localhost HTTP (not HTTPS) URL is present in production Dart code. This endpoint transmits data in plaintext and is likely a debug or development server URL left in the codebase.",
        fix: "Use kReleaseMode to conditionally set API endpoints.",
        cwe: "CWE-489",
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 13: Expo Constants exposure (CWE-200)
// ---------------------------------------------------------------------------

const EXPO_CONSTANTS_SENSITIVE = /(?:secret|key|token|password|api)/i;

function checkExpoConstantsExposure(filePath: string, content: string): ScanResult[] {
  if (
    !content.includes("Constants.expoConfig") &&
    !content.includes("Constants.manifest")
  ) {
    return [];
  }

  if (!content.includes(".extra")) return [];

  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    if (
      (line.includes("Constants.expoConfig") || line.includes("Constants.manifest")) &&
      line.includes(".extra") &&
      EXPO_CONSTANTS_SENSITIVE.test(line)
    ) {
      results.push({
        checkId: "mobile:expo-constants-exposure",
        title: "Sensitive key accessed via Expo Constants.extra",
        severity: "HIGH",
        // Medium confidence — property name matches sensitive pattern.
        confidence: "medium",
        file: filePath,
        line: i + 1,
        description: "Secrets accessed via Constants.expoConfig.extra or Constants.manifest.extra are embedded in the app bundle and can be extracted by decompiling the JavaScript bundle.",
        fix: "Don't store secrets in Expo config extra. Use expo-secure-store.",
        cwe: "CWE-200",
      });
      break;
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 14: Insecure data storage (CWE-922)
// ---------------------------------------------------------------------------

function checkInsecureDataStorageJS(filePath: string, content: string): ScanResult[] {
  const results: ScanResult[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isCommentLine(line)) continue;

    // localStorage.setItem in React Native context — should use SecureStore.
    if (/localStorage\.setItem\s*\(/.test(line)) {
      const keyMatch = line.match(/localStorage\.setItem\s*\(\s*['"`]([^'"`]+)['"`]/);
      const keyName = keyMatch ? keyMatch[1] : "";

      if (SENSITIVE_KEY_PATTERN.test(keyName) || keyName === "") {
        results.push({
          checkId: "mobile:insecure-data-storage-js",
          title: "Insecure use of localStorage in React Native",
          severity: "MEDIUM",
          // Medium confidence — key name matches sensitive pattern.
          confidence: "medium",
          file: filePath,
          line: i + 1,
          description: "localStorage is a web API that is not securely isolated on mobile platforms. In React Native, it maps to AsyncStorage (unencrypted). Sensitive data should use platform-specific secure storage.",
          fix: "Use platform-specific secure storage APIs.",
          cwe: "CWE-922",
        });
      }
    }
  }

  return results;
}
