// Supabase security scanner agent.
// Detects projects that use Supabase and scans for misconfigured RLS policies,
// exposed service role keys, SECURITY DEFINER functions without auth checks,
// public storage buckets, unfiltered selects, and Edge Functions without JWT verification.

import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "../types.js";

export class SupabaseScanAgent implements ScanAgent {
  async detect(files: Map<string, string>): Promise<boolean> {
    for (const [filePath, content] of files) {
      if (filePath === "supabase/config.toml") return true;
      if (filePath === "package.json" && content.includes("@supabase/supabase-js")) return true;
    }
    return false;
  }

  async scan(files: Map<string, string>): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    results.push(...checkAdminApiInClientCode(files));
    results.push(...checkDisableRLS(files));
    results.push(...checkCreateTableWithoutRLS(files));
    results.push(...checkOverlyPermissiveRLSPolicy(files));
    results.push(...checkSecurityDefinerWithoutAuthCheck(files));
    results.push(...checkSignupWithoutEmailConfirmation(files));
    results.push(...checkServiceRoleKeyInClient(files));
    results.push(...checkPublicStorageBucket(files));
    results.push(...checkUnfilteredSelect(files));
    results.push(...checkEdgeFunctionWithoutJwtVerification(files));

    return results;
  }

  getMetadata(): AgentMetadata {
    return {
      name: "supabase-agent",
      version: "1.0.0",
      technologies: ["supabase"],
    };
  }

  getChecks(): CheckDefinition[] {
    return [
      {
        id: "supabase:admin-api-in-client",
        name: "Admin API in client-side code",
        severity: "CRITICAL",
      },
      {
        id: "supabase:disable-rls",
        name: "DISABLE ROW LEVEL SECURITY",
        severity: "CRITICAL",
      },
      {
        id: "supabase:create-table-without-rls",
        name: "CREATE TABLE without RLS",
        severity: "CRITICAL",
      },
      {
        id: "supabase:permissive-rls-policy",
        name: "Overly permissive RLS policy",
        severity: "CRITICAL",
      },
      {
        id: "supabase:security-definer-no-auth",
        name: "SECURITY DEFINER without auth check",
        severity: "HIGH",
      },
      {
        id: "supabase:signup-no-email-confirmation",
        name: "Signup without email confirmation",
        severity: "HIGH",
      },
      {
        id: "supabase:service-role-key-in-client",
        name: "Service role key in client",
        severity: "CRITICAL",
      },
      {
        id: "supabase:public-storage-bucket",
        name: "Public storage bucket",
        severity: "HIGH",
      },
      {
        id: "supabase:unfiltered-select",
        name: "Unfiltered SELECT query",
        severity: "MEDIUM",
      },
      {
        id: "supabase:edge-function-no-jwt",
        name: "Edge Function without JWT verification",
        severity: "HIGH",
      },
    ];
  }
}

// --- Helper predicates ---

/** Returns true if the file path ends with .sql */
function isSQLFile(filePath: string): boolean {
  return filePath.endsWith(".sql");
}

/** Returns true if the file is likely rendered in a browser / client bundle. */
function isClientFile(filePath: string, content: string): boolean {
  // Explicit "use client" directive is the definitive signal
  if (content.includes('"use client"') || content.includes("'use client'")) return true;

  // Next.js Route Handlers and server utilities are never client code
  // even if they live under app/ — match paths like app/api/, app/.../route.ts
  if (/app\/api\//.test(filePath)) return false;
  if (filePath.endsWith("/route.ts") || filePath.endsWith("/route.js")) return false;

  // Files in these directories are typically client-rendered by convention
  if (filePath.includes("components/") || filePath.includes("pages/")) return true;

  // .tsx/.jsx files directly inside app/ (not in api/) are often client-rendered
  if (filePath.includes("app/") && (filePath.endsWith(".tsx") || filePath.endsWith(".jsx"))) {
    return true;
  }

  return filePath.endsWith(".tsx") || filePath.endsWith(".jsx");
}

/** Returns true if the file lives inside supabase/functions/. */
function isEdgeFunction(filePath: string): boolean {
  return filePath.startsWith("supabase/functions/") || filePath.includes("/supabase/functions/");
}

// --- Check 1: Admin API in client code (CRITICAL, CWE-306) ---

function checkAdminApiInClientCode(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isClientFile(filePath, content)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes("supabase.auth.admin") || line.includes("auth.admin.")) {
        results.push({
          checkId: "supabase:admin-api-in-client",
          title: "Supabase admin API used in client-side code",
          severity: "CRITICAL",
          file: filePath,
          line: i + 1,
          description:
            "The Supabase auth.admin API is being called in client-side code. " +
            "Admin methods bypass Row Level Security and require the service role key, " +
            "which must never be exposed to the browser.",
          fix: "Move admin API calls to server-side code. Never use auth.admin in client components.",
          cwe: "CWE-306",
        });
      }
    }
  }

  return results;
}

// --- Check 2: DISABLE ROW LEVEL SECURITY (CRITICAL, CWE-284) ---

const DISABLE_RLS_REGEX = /ALTER\s+TABLE\s+\S+\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY/i;

function checkDisableRLS(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isSQLFile(filePath)) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      // Join with next line to catch multi-line statements
      const chunk = lines.slice(i, i + 3).join(" ");
      if (DISABLE_RLS_REGEX.test(chunk) && DISABLE_RLS_REGEX.test(lines[i] + (lines[i + 1] ?? "") + (lines[i + 2] ?? ""))) {
        // Confirm the match starts on this line
        if (/ALTER\s+TABLE/i.test(lines[i]) || (i > 0 && /ALTER\s+TABLE/i.test(lines[i - 1]))) {
          results.push({
            checkId: "supabase:disable-rls",
            title: "Row Level Security disabled on table",
            severity: "CRITICAL",
            file: filePath,
            line: i + 1,
            description:
              "DISABLE ROW LEVEL SECURITY removes all data access restrictions from the table. " +
              "Any authenticated or anonymous user can read or modify all rows, bypassing all policies.",
            fix: "Never disable RLS in production. If needed for migration, re-enable immediately after.",
            cwe: "CWE-284",
          });
        }
      }
    }
  }

  return results;
}

// --- Check 3: CREATE TABLE without RLS (CRITICAL, CWE-284) ---

function checkCreateTableWithoutRLS(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isSQLFile(filePath)) continue;

    if (!content.toUpperCase().includes("CREATE TABLE")) continue;
    if (content.toUpperCase().includes("ENABLE ROW LEVEL SECURITY")) continue;

    // Find the first CREATE TABLE line to report
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (/CREATE\s+TABLE/i.test(lines[i])) {
        results.push({
          checkId: "supabase:create-table-without-rls",
          title: "Table created without enabling Row Level Security",
          severity: "CRITICAL",
          file: filePath,
          line: i + 1,
          description:
            "This migration creates a table but does not enable Row Level Security. " +
            "Without RLS, any user with database access can read or modify all rows.",
          fix: "Add RLS to every table: ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;",
          cwe: "CWE-284",
        });
        // One finding per file is sufficient — the missing ENABLE RLS is a file-level issue
        break;
      }
    }
  }

  return results;
}

// --- Check 4: Overly permissive RLS policy (CRITICAL, CWE-284) ---

// Matches USING (true) or USING(true) with optional whitespace
const PERMISSIVE_USING_REGEX = /USING\s*\(\s*true\s*\)/i;
// Matches public table names in the CREATE POLICY statement
const PUBLIC_TABLE_REGEX = /(?:public_|_public\b|["'\s]public["'\s])/i;

function checkOverlyPermissiveRLSPolicy(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isSQLFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!/CREATE\s+POLICY/i.test(line)) continue;

      // Gather the full policy statement (up to the semicolon or next 10 lines)
      const policyLines: string[] = [];
      for (let j = i; j < Math.min(i + 10, lines.length); j++) {
        policyLines.push(lines[j]);
        if (lines[j].includes(";")) break;
      }
      const policyBlock = policyLines.join(" ");

      if (!PERMISSIVE_USING_REGEX.test(policyBlock)) continue;

      // Skip policies explicitly for public-read tables
      if (PUBLIC_TABLE_REGEX.test(policyBlock) || /\bpublic\b/i.test(line)) continue;

      results.push({
        checkId: "supabase:permissive-rls-policy",
        title: "Overly permissive RLS policy uses USING(true)",
        severity: "CRITICAL",
        file: filePath,
        line: i + 1,
        description:
          "USING (true) in an RLS policy allows every user — including anonymous users — " +
          "to access every row in the table. This effectively disables row-level access control.",
        fix: "Use auth.uid() in policies: CREATE POLICY ... USING (auth.uid() = user_id)",
        cwe: "CWE-284",
      });
    }
  }

  return results;
}

// --- Check 5: SECURITY DEFINER without auth check (HIGH, CWE-306) ---

function checkSecurityDefinerWithoutAuthCheck(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isSQLFile(filePath)) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      if (!/SECURITY\s+DEFINER/i.test(lines[i])) continue;

      // Check surrounding 20 lines for auth.uid / auth.jwt
      const start = Math.max(0, i - 10);
      const end = Math.min(lines.length, i + 10);
      const surroundingBlock = lines.slice(start, end).join("\n");

      if (!/auth\.uid|auth\.jwt/i.test(surroundingBlock)) {
        results.push({
          checkId: "supabase:security-definer-no-auth",
          title: "SECURITY DEFINER function without authentication check",
          severity: "HIGH",
          file: filePath,
          line: i + 1,
          description:
            "A SECURITY DEFINER function runs with the privileges of the function owner, " +
            "bypassing RLS and normal permission checks. Without an auth.uid() or auth.jwt() " +
            "guard, any caller — including anonymous users — can invoke it with elevated privileges.",
          fix: "Add auth checks in SECURITY DEFINER functions: IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Not authenticated'; END IF;",
          cwe: "CWE-306",
        });
      }
    }
  }

  return results;
}

// --- Check 6: Signup without email confirmation (HIGH, CWE-287) ---

function checkSignupWithoutEmailConfirmation(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (filePath !== "supabase/config.toml") continue;

    if (!content.includes("enable_signup = true")) continue;

    // Require explicit enable_confirmations = true; absence or false both fail
    if (!content.includes("enable_confirmations = true")) {
      const lines = content.split("\n");
      const lineIndex = lines.findIndex((l) => l.includes("enable_signup = true"));

      results.push({
        checkId: "supabase:signup-no-email-confirmation",
        title: "Supabase signup enabled without email confirmation",
        severity: "HIGH",
        file: filePath,
        line: lineIndex + 1,
        description:
          "Signups are enabled but email confirmation is not required. " +
          "Anyone can register with any email address — including addresses they do not own — " +
          "without verifying ownership. This enables account hijacking and spam.",
        fix: "Enable email confirmations: [auth] enable_confirmations = true",
        cwe: "CWE-287",
      });
    }
  }

  return results;
}

// --- Check 7: Service role key in client (CRITICAL, CWE-798) ---

// Matches env var names that expose service role keys to the client
const SERVICE_ROLE_ENV_REGEX = /NEXT_PUBLIC_SUPABASE_SERVICE_ROLE|NEXT_PUBLIC[_A-Z]*service_role|VITE_SUPABASE_SERVICE_ROLE/i;

function checkServiceRoleKeyInClient(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Pattern A: env variable with NEXT_PUBLIC or VITE_ prefix exposes service role
      if (SERVICE_ROLE_ENV_REGEX.test(line)) {
        results.push({
          checkId: "supabase:service-role-key-in-client",
          title: "Service role key exposed via public environment variable",
          severity: "CRITICAL",
          file: filePath,
          line: i + 1,
          description:
            "The Supabase service role key is referenced through a public environment variable " +
            "(NEXT_PUBLIC_ or VITE_ prefixed). These variables are bundled into the client-side " +
            "JavaScript and visible to any user who inspects the page source. " +
            "The service role key bypasses all RLS policies.",
          fix: "Never expose the service role key to the client. Use it only in server-side code.",
          cwe: "CWE-798",
        });
        continue;
      }

      // Pattern B: service_role or serviceRoleKey referenced inside client files
      if (
        isClientFile(filePath, content) &&
        (line.includes("service_role") || line.includes("serviceRoleKey"))
      ) {
        results.push({
          checkId: "supabase:service-role-key-in-client",
          title: "Service role key referenced in client-side code",
          severity: "CRITICAL",
          file: filePath,
          line: i + 1,
          description:
            "The Supabase service role key is referenced in client-side code. " +
            "It bypasses all Row Level Security policies and grants full database access. " +
            "Exposing it in the browser allows attackers to read, modify, or delete all data.",
          fix: "Never expose the service role key to the client. Use it only in server-side code.",
          cwe: "CWE-798",
        });
      }
    }
  }

  return results;
}

// --- Check 8: Public storage bucket (HIGH, CWE-284) ---

// Matches storage.objects SELECT policies with USING (true) — publicly readable
const STORAGE_SELECT_USING_TRUE_REGEX =
  /storage\.objects[\s\S]{0,200}?FOR\s+SELECT[\s\S]{0,100}?USING\s*\(\s*true\s*\)/i;

function checkPublicStorageBucket(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isSQLFile(filePath)) continue;

    if (!content.toLowerCase().includes("storage.objects")) continue;

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      // Look for a policy block that references storage.objects
      if (!/storage\.objects/i.test(lines[i])) continue;

      // Collect the surrounding policy block (up to 20 lines forward)
      const block = lines.slice(i, Math.min(i + 20, lines.length)).join("\n");

      if (/FOR\s+SELECT/i.test(block) && /USING\s*\(\s*true\s*\)/i.test(block)) {
        results.push({
          checkId: "supabase:public-storage-bucket",
          title: "Public storage bucket allows unrestricted SELECT",
          severity: "HIGH",
          file: filePath,
          line: i + 1,
          description:
            "A storage.objects policy uses USING (true) for SELECT, making all files in the " +
            "bucket publicly readable without authentication. Sensitive files could be accessed " +
            "by anyone who discovers the storage URL.",
          fix: "Add proper RLS policies to storage buckets based on user authentication.",
          cwe: "CWE-284",
        });
        break; // One finding per storage.objects block
      }
    }
  }

  return results;
}

// --- Check 9: Unfiltered select in server code (MEDIUM, CWE-200) ---

function checkUnfilteredSelect(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    // Only check TypeScript/JavaScript files
    if (
      !filePath.endsWith(".ts") &&
      !filePath.endsWith(".tsx") &&
      !filePath.endsWith(".js") &&
      !filePath.endsWith(".jsx")
    ) {
      continue;
    }

    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Must have .from( to be a Supabase query
      if (!line.includes(".from(")) continue;

      // Must have .select( with wildcard or empty argument
      const fromIndex = line.indexOf(".from(");
      const selectMatch = line.match(/\.select\s*\(\s*['"`]\*['"`]\s*\)/) ||
                          line.match(/\.select\s*\(\s*\)/);
      if (!selectMatch) {
        // Check the next 2 lines for a .select() call
        const nextLines = lines.slice(i + 1, Math.min(i + 3, lines.length)).join(" ");
        if (
          !/\.select\s*\(\s*['"`]\*['"`]\s*\)/.test(nextLines) &&
          !/\.select\s*\(\s*\)/.test(nextLines)
        ) {
          continue;
        }
      }

      // Check if a filter is present within 3 lines
      const block = lines.slice(i, Math.min(i + 4, lines.length)).join("\n");
      if (/\.eq\s*\(|\.match\s*\(|\.filter\s*\(/.test(block)) continue;

      // Skip if the file is client-side (client files are already partially
      // restricted by RLS, the bigger concern is server-side unfiltered access)
      // We actually flag both but avoid flagging test/mock files.
      if (filePath.includes(".test.") || filePath.includes(".spec.")) continue;

      results.push({
        checkId: "supabase:unfiltered-select",
        title: "Unfiltered Supabase SELECT query without row filter",
        severity: "MEDIUM",
        file: filePath,
        line: i + 1,
        description:
          "A Supabase query selects all rows with no filter condition (.eq(), .match(), .filter()). " +
          "Even with RLS enabled, this pattern may return more data than intended if policies are " +
          "accidentally permissive. Always scope queries to the current user.",
        fix: "Always filter queries by user: supabase.from('table').select('*').eq('user_id', userId)",
        cwe: "CWE-200",
      });
    }
  }

  return results;
}

// --- Check 10: Edge Function without JWT verification (HIGH, CWE-306) ---

function checkEdgeFunctionWithoutJwtVerification(files: Map<string, string>): ScanResult[] {
  const results: ScanResult[] = [];

  for (const [filePath, content] of files) {
    if (!isEdgeFunction(filePath)) continue;
    if (!filePath.endsWith(".ts") && !filePath.endsWith(".js")) continue;

    const hasAuthCheck =
      content.includes("req.headers.get('authorization')") ||
      content.includes('req.headers.get("authorization")') ||
      content.includes("req.headers.get('Authorization')") ||
      content.includes('req.headers.get("Authorization")') ||
      content.includes("Authorization") ||
      content.includes("supabase.auth.getUser") ||
      content.includes("supabase.auth.getSession");

    if (!hasAuthCheck) {
      // Find the first non-blank line to pin the finding
      const lines = content.split("\n");
      const firstLine = lines.findIndex((l) => l.trim() !== "") + 1;

      results.push({
        checkId: "supabase:edge-function-no-jwt",
        title: "Edge Function does not verify JWT authorization",
        severity: "HIGH",
        file: filePath,
        line: firstLine > 0 ? firstLine : 1,
        description:
          "This Supabase Edge Function does not appear to check the Authorization header " +
          "or verify the caller's JWT. Any unauthenticated request can invoke it, " +
          "potentially exposing sensitive operations to the public.",
        fix: "Verify JWT in Edge Functions: const authHeader = req.headers.get('Authorization')",
        cwe: "CWE-306",
      });
    }
  }

  return results;
}
