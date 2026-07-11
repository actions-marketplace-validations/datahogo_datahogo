#!/usr/bin/env node
// datahogo — open-source security scanner that runs on your machine.
// Your code never leaves your laptop.

import { parseArgs } from "node:util";
import { promises as fs } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { runScan, detectTechnologies } from "@datahogo/core";
import type { Severity } from "@datahogo/core";
import { walkDirectory } from "./walk.js";
import { renderResults, renderBinaryHints } from "./render.js";
import { toSarif } from "./sarif.js";
import { checkTools, renderDoctor } from "./doctor.js";

const require = createRequire(import.meta.url);
const VERSION: string = require("../package.json").version;

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const HELP = `
datahogo ${VERSION} — open-source security scanner. Your code never leaves your machine.

Usage:
  datahogo [scan] [path]        Scan a directory (default: current directory)
  datahogo doctor               Check optional external tools (semgrep, gitleaks)

Options:
  --json                        Output results as JSON
  --sarif                       Output results as SARIF 2.1.0 (GitHub Code Scanning)
  --fail-on <severity>          Exit with code 1 if findings at or above this
                                severity exist (critical|high|medium|low)
  --url <url>                   Also scan a deployed URL (headers, SSL, CORS)
  --all                         Include informational and non-production findings
  --help, -h                    Show this help
  --version, -v                 Show version

Examples:
  npx datahogo
  datahogo scan ./my-app --fail-on high
  datahogo scan --sarif > results.sarif
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      json: { type: "boolean", default: false },
      sarif: { type: "boolean", default: false },
      "fail-on": { type: "string" },
      url: { type: "string" },
      all: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
    allowPositionals: true,
  });

  if (values.version) {
    console.log(VERSION);
    return 0;
  }
  if (values.help) {
    console.log(HELP);
    return 0;
  }

  const command = positionals[0] === "doctor" ? "doctor" : "scan";

  if (command === "doctor") {
    console.log(renderDoctor(await checkTools()));
    return 0;
  }

  const failOn = values["fail-on"] as Severity | undefined;
  if (failOn && !(failOn in SEVERITY_RANK)) {
    console.error(`Unknown severity for --fail-on: "${failOn}". Use critical|high|medium|low.`);
    return 2;
  }

  // "datahogo scan ./x" and "datahogo ./x" both work.
  const pathArg = positionals[0] === "scan" ? positionals[1] : positionals[0];
  const rootDir = path.resolve(pathArg ?? ".");

  try {
    const stat = await fs.stat(rootDir);
    if (!stat.isDirectory()) {
      console.error(`Not a directory: ${rootDir}`);
      return 2;
    }
  } catch {
    console.error(`Directory not found: ${rootDir}`);
    return 2;
  }

  const machineOutput = values.json || values.sarif;
  if (!machineOutput) {
    console.log(`\n  Scanning ${rootDir} …`);
  }

  const { files } = await walkDirectory(rootDir);
  if (files.size === 0) {
    console.error("No scannable files found.");
    return 2;
  }

  const techs = detectTechnologies(files).technologies;
  const result = await runScan({
    files,
    repoDir: rootDir,
    appUrl: values.url,
  });

  if (values.sarif) {
    console.log(JSON.stringify(toSarif(result.findings, VERSION), null, 2));
  } else if (values.json) {
    console.log(JSON.stringify({ ...result, techsDetected: techs }, null, 2));
  } else {
    console.log(renderResults(result, { techs, fileCount: files.size, showAll: values.all ?? false }));
    const tools = await checkTools();
    const missing = tools.filter((t) => !t.found && t.name !== "npm").map((t) => t.name);
    process.stdout.write(renderBinaryHints(missing));
  }

  if (failOn) {
    const threshold = SEVERITY_RANK[failOn];
    const hit = result.findings.some(
      (f) =>
        (f.context ?? "production") === "production" &&
        f.classification !== "informational" &&
        SEVERITY_RANK[f.severity] >= threshold,
    );
    if (hit) return 1;
  }

  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(2);
  });
