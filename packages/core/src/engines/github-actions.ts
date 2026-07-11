// GitHub Actions security engine - scans workflow files for common CI/CD vulnerabilities.
// Operates on the files Map (no filesystem access needed).

import type { FindingData } from "./types.js";

export function analyzeGitHubActions(files: Map<string, string>): FindingData[] {
  const findings: FindingData[] = [];

  for (const [filePath, content] of files) {
    if (!filePath.match(/\.github\/workflows\/.*\.ya?ml$/)) continue;

    findings.push(...checkUnpinnedActions(content, filePath));
    findings.push(...checkScriptInjection(content, filePath));
    findings.push(...checkSecretsExposure(content, filePath));
    findings.push(...checkExcessivePermissions(content, filePath));
    findings.push(...checkSelfHostedRunners(content, filePath));
    findings.push(...checkPullRequestTarget(content, filePath));
  }

  return findings;
}

function checkUnpinnedActions(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(/uses:\s*["']?([^"'\s]+)@([^"'\s]+)/);
    if (!match) continue;

    const [, action, ref] = match;

    // Skip Docker and local actions
    if (action.startsWith("docker://") || action.startsWith("./")) continue;

    // Flag if using branch ref instead of SHA or version tag
    if (ref === "main" || ref === "master" || ref === "latest" || ref === "dev") {
      findings.push({
        vulnerability_id: 140,
        severity: "medium",
        category: "supply-chain",
        title: `Unpinned Action: ${action}@${ref}`,
        description_technical: `Action ${action} is pinned to branch '${ref}' instead of a SHA or version tag. This is vulnerable to supply chain attacks if the action is compromised.`,
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        fix_description: `Pin to a specific version tag (e.g., @v4) or full SHA (e.g., @abc123...)`,
        status: "open",
      });
    }
  }

  return findings;
}

function checkScriptInjection(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  // Dangerous GitHub context expressions in run: blocks
  const dangerousContexts = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
    "github.event.pages.page_name",
  ];

  let inRunBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.match(/^\s*run:\s*[|>]?\s*$/)) {
      inRunBlock = true;
      continue;
    }
    if (line.match(/^\s*run:\s*\S/)) {
      // Single-line run
      inRunBlock = false;
      checkLineForInjection(line, i, filePath, dangerousContexts, findings);
      continue;
    }
    if (inRunBlock && line.match(/^\s*\w+:/)) {
      inRunBlock = false;
      continue;
    }

    if (inRunBlock || line.match(/^\s*run:/)) {
      checkLineForInjection(line, i, filePath, dangerousContexts, findings);
    }
  }

  return findings;
}

function checkLineForInjection(
  line: string,
  lineIndex: number,
  filePath: string,
  dangerousContexts: string[],
  findings: FindingData[]
): void {
  for (const context of dangerousContexts) {
    if (line.includes(`\${{ ${context}`) || line.includes(`\${{${context}`)) {
      findings.push({
        vulnerability_id: 76,
        severity: "high",
        category: "injection",
        title: `Script Injection via ${context}`,
        description_technical: `Untrusted input from '${context}' is used in a run: block. An attacker can inject arbitrary commands by crafting a malicious title/body.`,
        file_path: filePath,
        line_number: lineIndex + 1,
        code_snippet: line.trim(),
        fix_description: "Use an environment variable instead: env: TITLE: ${{ github.event.issue.title }} and reference $TITLE in the script",
        owasp_ref: "A03:2021",
        status: "open",
      });
      break; // One finding per line
    }
  }
}

function checkSecretsExposure(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for hardcoded secret-like values in env or with blocks
    if (line.match(/(?:env|with):\s*$/)) continue; // Block header, skip
    if (line.match(/^\s+\w+:\s*["'][A-Za-z0-9_\-./+=]{20,}["']/)) {
      // Skip if it references secrets context
      if (line.includes("${{ secrets.") || line.includes("${{ github.")) continue;

      findings.push({
        vulnerability_id: 53,
        severity: "critical",
        category: "vibecoding",
        title: "Hardcoded Secret in Workflow",
        description_technical: "A long string value in the workflow file may be a hardcoded secret. Use GitHub Secrets instead.",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim().replace(/["'][A-Za-z0-9_\-./+=]{20,}["']/, '"***REDACTED***"'),
        fix_description: "Store the value as a GitHub Secret and reference it via ${{ secrets.SECRET_NAME }}",
        owasp_ref: "A07:2021",
        status: "open",
      });
    }
  }

  return findings;
}

function checkExcessivePermissions(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for write-all permissions
    if (line.match(/^\s*permissions:\s*write-all/)) {
      findings.push({
        vulnerability_id: 133,
        severity: "medium",
        category: "serverless",
        title: "Workflow Has write-all Permissions",
        description_technical: "The workflow grants write permissions to all scopes. Follow the principle of least privilege.",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        fix_description: "Specify only the permissions needed, e.g., permissions: { contents: read, pull-requests: write }",
        status: "open",
      });
    }

    // Check for no permissions block at top level
    if (i === 0 && !content.includes("permissions:")) {
      findings.push({
        vulnerability_id: 133,
        severity: "low",
        category: "serverless",
        title: "Workflow Missing Permissions Block",
        description_technical: "No permissions block defined. The workflow inherits default permissions which may be broader than needed.",
        file_path: filePath,
        line_number: 1,
        code_snippet: lines.slice(0, 3).join("\n"),
        fix_description: "Add a top-level permissions block to restrict token scope",
        status: "open",
      });
    }
  }

  return findings;
}

function checkSelfHostedRunners(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.match(/runs-on:\s*["']?self-hosted/)) {
      findings.push({
        vulnerability_id: 136,
        severity: "info",
        category: "serverless",
        title: "Self-Hosted Runner Used",
        description_technical: "Self-hosted runners can persist state between jobs. Ensure runners are ephemeral or properly hardened.",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
      });
    }
  }

  return findings;
}

function checkPullRequestTarget(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];

  if (content.includes("pull_request_target") && content.includes("actions/checkout")) {
    // This is a dangerous pattern: pull_request_target + checkout = code execution from fork
    const lineNum = content.split("\n").findIndex((l) => l.includes("pull_request_target")) + 1;
    findings.push({
      vulnerability_id: 76,
      severity: "critical",
      category: "injection",
      title: "Dangerous pull_request_target + Checkout Pattern",
      description_technical: "Using pull_request_target with actions/checkout can execute untrusted code from forks with write permissions and secrets access.",
      file_path: filePath,
      line_number: lineNum,
      code_snippet: "on: pull_request_target\n...\nuses: actions/checkout@...",
      fix_description: "Use pull_request instead, or avoid checking out PR code in pull_request_target workflows",
      owasp_ref: "A03:2021",
      status: "open",
    });
  }

  return findings;
}
