// `datahogo doctor` — reports which optional external tools are available.
// The scanner works without them; they add depth (AST rules, secret rules).

import { execFile } from "node:child_process";

export interface ToolStatus {
  name: string;
  found: boolean;
  version?: string;
  installHint: string;
}

function checkBinary(command: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: 10_000 }, (error, stdout) => {
      if (error) resolve(null);
      else resolve(stdout.trim().split("\n")[0]);
    });
  });
}

export async function checkTools(): Promise<ToolStatus[]> {
  const [semgrep, gitleaks, npmVersion] = await Promise.all([
    checkBinary("semgrep", ["--version"]),
    checkBinary("gitleaks", ["version"]),
    checkBinary("npm", ["--version"]),
  ]);

  return [
    {
      name: "semgrep",
      found: semgrep !== null,
      version: semgrep ?? undefined,
      installHint: "brew install semgrep  (or: pipx install semgrep)",
    },
    {
      name: "gitleaks",
      found: gitleaks !== null,
      version: gitleaks ?? undefined,
      installHint: "brew install gitleaks",
    },
    {
      name: "npm",
      found: npmVersion !== null,
      version: npmVersion ?? undefined,
      installHint: "included with Node.js — https://nodejs.org",
    },
  ];
}

export function renderDoctor(tools: ToolStatus[]): string {
  const lines: string[] = ["", "  datahogo doctor", ""];
  lines.push(`  node ${process.version} ✓`);
  for (const tool of tools) {
    if (tool.found) {
      lines.push(`  ${tool.name} ${tool.version ?? ""} ✓`);
    } else {
      lines.push(`  ${tool.name} — not found (optional)`);
      lines.push(`      install: ${tool.installHint}`);
    }
  }
  lines.push("");
  lines.push("  semgrep adds ~250 AST-based checks; gitleaks adds full secret-rule coverage.");
  lines.push("  npm enables dependency auditing (npm audit) when a lockfile is present.");
  lines.push("");
  return lines.join("\n");
}
