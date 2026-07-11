// Gitleaks engine - runs the Gitleaks binary for comprehensive secret detection.
// Falls back gracefully if gitleaks is not installed (regex secrets engine covers basics).

import { execWithTimeout } from "../utils/exec.js";
import { readFile, rm } from "../utils/fs.js";
import path from "node:path";
import os from "node:os";
import type { FindingData, Severity } from "./types.js";

// Gitleaks JSON report entry
interface GitleaksLeak {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  SymlinkFile: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}

// Map Gitleaks RuleIDs to our vulnerability catalog
const RULE_ID_MAP: Record<string, { id: number; severity: Severity; category: string }> = {
  "generic-api-key": { id: 53, severity: "critical", category: "vibecoding" },
  "private-key": { id: 53, severity: "critical", category: "vibecoding" },
  "aws-access-key-id": { id: 53, severity: "critical", category: "vibecoding" },
  "aws-secret-access-key": { id: 53, severity: "critical", category: "vibecoding" },
  "github-pat": { id: 53, severity: "critical", category: "vibecoding" },
  "github-fine-grained-pat": { id: 53, severity: "critical", category: "vibecoding" },
  "github-oauth": { id: 53, severity: "critical", category: "vibecoding" },
  "github-app-token": { id: 53, severity: "critical", category: "vibecoding" },
  "gcp-api-key": { id: 53, severity: "critical", category: "vibecoding" },
  "stripe-access-token": { id: 53, severity: "critical", category: "vibecoding" },
  "slack-bot-token": { id: 53, severity: "critical", category: "vibecoding" },
  "slack-webhook-url": { id: 53, severity: "high", category: "vibecoding" },
  "twilio-api-key": { id: 53, severity: "critical", category: "vibecoding" },
  "sendgrid-api-key": { id: 53, severity: "critical", category: "vibecoding" },
  "mailchimp-api-key": { id: 53, severity: "high", category: "vibecoding" },
  "npm-access-token": { id: 53, severity: "critical", category: "supply-chain" },
  "pypi-upload-token": { id: 53, severity: "critical", category: "supply-chain" },
  "telegram-bot-api-token": { id: 53, severity: "high", category: "vibecoding" },
  "discord-api-token": { id: 53, severity: "high", category: "vibecoding" },
  "discord-client-secret": { id: 53, severity: "high", category: "vibecoding" },
  "heroku-api-key": { id: 53, severity: "critical", category: "vibecoding" },
  "linkedin-client-secret": { id: 53, severity: "high", category: "vibecoding" },
  "vault-service-token": { id: 53, severity: "critical", category: "vibecoding" },
  "jwt": { id: 53, severity: "high", category: "vibecoding" },
  "password-in-url": { id: 55, severity: "critical", category: "vibecoding" },
  "postgresql-connection-string": { id: 101, severity: "critical", category: "database" },
  "mysql-connection-string": { id: 101, severity: "critical", category: "database" },
  "mongodb-connection-string": { id: 101, severity: "critical", category: "database" },
};

const DEFAULT_MAPPING = { id: 53, severity: "critical" as Severity, category: "vibecoding" };

export async function runGitleaks(repoDir: string): Promise<FindingData[]> {
  const reportPath = path.join(os.tmpdir(), `gitleaks-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);

  try {
    // Gitleaks exits with code 1 when leaks are found — this is expected behavior
    await execWithTimeout("gitleaks", [
      "dir",
      repoDir,
      "-v",
      "--report-format", "json",
      "--report-path", reportPath,
      "--no-git", // Scan current files, not git history (faster, history not available)
    ], { timeoutMs: 30_000 });
  } catch (error) {
    // Only re-throw if it's a timeout or missing binary
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("timed out") || message.includes("ENOENT")) {
      throw error;
    }
    // exit code 1 = leaks found, report file should exist
  }

  let reportContent: string;
  try {
    reportContent = await readFile(reportPath, "utf-8");
  } catch {
    // No report file = no leaks found (exit code 0, empty report)
    return [];
  } finally {
    await rm(reportPath, { force: true }).catch(() => {});
  }

  if (!reportContent.trim()) return [];

  let results: GitleaksLeak[];
  try {
    results = JSON.parse(reportContent);
  } catch {
    return [];
  }

  if (!Array.isArray(results)) return [];

  return results.map((leak) => mapLeakToFinding(leak, repoDir));
}

function mapLeakToFinding(leak: GitleaksLeak, repoDir: string): FindingData {
  const mapping = RULE_ID_MAP[leak.RuleID] ?? DEFAULT_MAPPING;

  // Make file path relative to repo root
  const filePath = leak.File.startsWith(repoDir)
    ? leak.File.slice(repoDir.length + 1)
    : leak.File;

  // Mask the actual secret value
  const maskedSecret = leak.Secret.length > 6
    ? leak.Secret.substring(0, 6) + "...REDACTED"
    : "***REDACTED***";

  return {
    vulnerability_id: mapping.id,
    severity: mapping.severity,
    category: mapping.category,
    title: `${leak.Description}`,
    description_technical: `Gitleaks detected ${leak.RuleID}: ${leak.Description}`,
    file_path: filePath,
    line_number: leak.StartLine,
    code_snippet: leak.Match.replace(leak.Secret, maskedSecret),
    owasp_ref: "A07:2021",
    status: "open",
  };
}
