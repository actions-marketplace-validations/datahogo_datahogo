// Database rules parser engine - analyzes Supabase RLS and Firebase security rules
// Parses user-provided rule text to detect misconfigurations

import type { FindingData } from "./types.js";

export function analyzeDbRules(
  rulesInput: string,
  rulesType: "supabase" | "firebase" | "auto"
): FindingData[] {
  const detectedType = rulesType === "auto" ? detectRulesType(rulesInput) : rulesType;

  if (detectedType === "supabase") {
    return analyzeSupabaseRules(rulesInput);
  }
  if (detectedType === "firebase") {
    return analyzeFirebaseRules(rulesInput);
  }

  return [];
}

function detectRulesType(input: string): "supabase" | "firebase" | "unknown" {
  if (input.includes("CREATE POLICY") || input.includes("ENABLE ROW LEVEL SECURITY") || input.includes("CREATE TABLE")) {
    return "supabase";
  }
  if (input.includes("allow read") || input.includes("allow write") || input.includes("match /") || input.includes(".read") || input.includes(".write")) {
    return "firebase";
  }
  return "unknown";
}

// === Supabase RLS Analysis ===

function analyzeSupabaseRules(sql: string): FindingData[] {
  const findings: FindingData[] = [];

  // Find all CREATE TABLE statements
  const tableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi;
  let tableMatch;
  const tables: string[] = [];

  while ((tableMatch = tableRegex.exec(sql)) !== null) {
    tables.push(tableMatch[1]);
  }

  // Check if each table has RLS enabled
  for (const table of tables) {
    const rlsPattern = new RegExp(
      `ALTER\\s+TABLE\\s+${table}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
      "i"
    );
    if (!rlsPattern.test(sql)) {
      findings.push({
        vulnerability_id: 31,
        severity: "critical",
        category: "supabase",
        title: `RLS Not Enabled on Table: ${table}`,
        description_technical: `Table ${table} does not have Row Level Security enabled. All data is accessible without restrictions.`,
        code_snippet: `CREATE TABLE ${table} (...)\n-- Missing: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`,
        fix_code: `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`,
        status: "open",
      });
    }
  }

  // Check for USING(true) policies (allow everything)
  const policyUsingTrue = /CREATE\s+POLICY\s+["']?(\w+)["']?\s+ON\s+(\w+)[\s\S]*?USING\s*\(\s*true\s*\)/gi;
  let policyMatch;
  while ((policyMatch = policyUsingTrue.exec(sql)) !== null) {
    findings.push({
      vulnerability_id: 32,
      severity: "critical",
      category: "supabase",
      title: `RLS Policy Allows Everything: ${policyMatch[1]}`,
      description_technical: `Policy "${policyMatch[1]}" on table "${policyMatch[2]}" uses USING(true), which allows all rows to be accessed by any user.`,
      code_snippet: policyMatch[0],
      status: "open",
    });
  }

  // Check for tables with RLS enabled but no policies
  for (const table of tables) {
    const rlsEnabled = new RegExp(
      `ALTER\\s+TABLE\\s+${table}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
      "i"
    ).test(sql);

    const hasPolicies = new RegExp(
      `CREATE\\s+POLICY[\\s\\S]*?ON\\s+${table}\\b`,
      "i"
    ).test(sql);

    if (rlsEnabled && !hasPolicies) {
      findings.push({
        vulnerability_id: 33,
        severity: "high",
        category: "supabase",
        title: `RLS Enabled But No Policies on: ${table}`,
        description_technical: `Table "${table}" has RLS enabled but no policies defined. This blocks ALL access, which may be intentional for service-role-only tables, but verify this is expected.`,
        code_snippet: `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\n-- No CREATE POLICY found for this table`,
        status: "open",
      });
    }
  }

  // Check for RPC functions without auth.uid()
  const functionRegex = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(\w+)[\s\S]*?(?:LANGUAGE\s+plpgsql|LANGUAGE\s+sql)/gi;
  let funcMatch;
  while ((funcMatch = functionRegex.exec(sql)) !== null) {
    const funcBody = funcMatch[0];
    const funcName = funcMatch[1];

    // Skip trigger functions (they use SECURITY DEFINER for a reason)
    if (/RETURNS\s+TRIGGER/i.test(funcBody)) continue;

    if (!funcBody.includes("auth.uid()") && !funcBody.includes("SECURITY DEFINER")) {
      // Only flag functions that could be called via RPC
      if (!funcName.startsWith("handle_") && !funcName.startsWith("update_")) {
        findings.push({
          vulnerability_id: 36,
          severity: "high",
          category: "supabase",
          title: `RPC Function Without Auth Check: ${funcName}`,
          description_technical: `Function "${funcName}" doesn't check auth.uid(). If exposed via RPC, any user can call it.`,
          code_snippet: funcBody.substring(0, 200),
          status: "open",
        });
      }
    }
  }

  return findings;
}

// === Firebase Rules Analysis ===

function analyzeFirebaseRules(rules: string): FindingData[] {
  const findings: FindingData[] = [];

  // Check for "allow read, write: if true" (Firestore)
  const firestoreOpenRegex = /allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true/gi;
  let firestoreMatch;
  while ((firestoreMatch = firestoreOpenRegex.exec(rules)) !== null) {
    findings.push({
      vulnerability_id: 39,
      severity: "critical",
      category: "firebase",
      title: "Firestore Rules Allow All Access",
      description_technical: "Rule 'allow read, write: if true' makes your database completely open to anyone.",
      code_snippet: getContextAroundMatch(rules, firestoreMatch.index),
      status: "open",
    });
  }

  // Check for ".read": true or ".write": true (Realtime DB)
  const realtimeOpenRegex = /["']\.(?:read|write)["']\s*:\s*(?:true|"true")/gi;
  let realtimeMatch;
  while ((realtimeMatch = realtimeOpenRegex.exec(rules)) !== null) {
    findings.push({
      vulnerability_id: 40,
      severity: "critical",
      category: "firebase",
      title: "Realtime Database Rules Allow All Access",
      description_technical: "Open .read or .write rules make your database accessible to anyone.",
      code_snippet: getContextAroundMatch(rules, realtimeMatch.index),
      status: "open",
    });
  }

  // Check for permissive storage rules
  const storageOpenRegex = /allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true[\s\S]*?match\s+\/b\/\{bucket\}\/o\/\{allPaths=\*\*\}/gi;
  if (storageOpenRegex.test(rules)) {
    findings.push({
      vulnerability_id: 41,
      severity: "high",
      category: "firebase",
      title: "Storage Rules Are Permissive",
      description_technical: "Storage rules allow unrestricted access to all files.",
      status: "open",
    });
  }

  // Check for missing request.auth in rules
  if (rules.includes("match /") && !rules.includes("request.auth")) {
    findings.push({
      vulnerability_id: 39,
      severity: "high",
      category: "firebase",
      title: "Firestore Rules Missing Authentication Check",
      description_technical: "Rules don't check request.auth, meaning unauthenticated users may have access.",
      code_snippet: rules.substring(0, 300),
      status: "open",
    });
  }

  return findings;
}

function getContextAroundMatch(text: string, index: number): string {
  const start = Math.max(0, text.lastIndexOf("\n", index - 1));
  const end = text.indexOf("\n", index + 50);
  return text.substring(start, end === -1 ? text.length : end).trim();
}
