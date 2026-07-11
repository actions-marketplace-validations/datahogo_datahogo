// Walks a local directory and builds the Map<path, content> the scan
// engine expects, honoring .gitignore and the core file relevance filter.

import { promises as fs } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import type { Ignore, Options } from "ignore";
import { isRelevantFile } from "@datahogo/core";

// The ignore package is CommonJS; under NodeNext ESM its default-export
// typing is not callable, so we load it via require with explicit types.
const require = createRequire(import.meta.url);
const ignore = require("ignore") as (options?: Options) => Ignore;

// Mirrors the engine-side cap: very large files are skipped.
const MAX_FILE_SIZE = 500_000;

export interface WalkResult {
  files: Map<string, string>;
  skippedLarge: string[];
}

async function loadGitignore(rootDir: string): Promise<Ignore> {
  const ig = ignore();
  // .git contents are never scannable, whether or not a .gitignore exists.
  ig.add(".git");
  try {
    const content = await fs.readFile(path.join(rootDir, ".gitignore"), "utf-8");
    ig.add(content);
  } catch {
    // No .gitignore — scan everything the relevance filter allows.
  }
  return ig;
}

export async function walkDirectory(rootDir: string): Promise<WalkResult> {
  const ig = await loadGitignore(rootDir);
  const files = new Map<string, string>();
  const skippedLarge: string[] = [];

  async function walk(currentDir: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);
      // The ignore package expects POSIX-style relative paths.
      const posixPath = relativePath.split(path.sep).join("/");

      if (ig.ignores(entry.isDirectory() ? `${posixPath}/` : posixPath)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (!isRelevantFile(posixPath)) continue;

        try {
          const stat = await fs.stat(fullPath);
          if (stat.size > MAX_FILE_SIZE) {
            skippedLarge.push(posixPath);
            continue;
          }
          const content = await fs.readFile(fullPath, "utf-8");
          files.set(posixPath, content);
        } catch {
          // Unreadable file (binary, permissions) — skip it.
        }
      }
    }
  }

  await walk(rootDir);
  return { files, skippedLarge };
}
