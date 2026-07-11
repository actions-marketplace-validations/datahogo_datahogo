import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { walkDirectory } from "./walk.js";

let tempDir: string;

beforeAll(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "datahogo-walk-"));

  await fs.mkdir(path.join(tempDir, "src"), { recursive: true });
  await fs.mkdir(path.join(tempDir, "node_modules", "leftpad"), { recursive: true });
  await fs.mkdir(path.join(tempDir, "secrets"), { recursive: true });

  await fs.writeFile(path.join(tempDir, ".gitignore"), "secrets/\n*.log\n");
  await fs.writeFile(path.join(tempDir, "src", "app.ts"), "console.log('hi');");
  await fs.writeFile(path.join(tempDir, "src", "main.py"), "print('hi')");
  await fs.writeFile(path.join(tempDir, "requirements.txt"), "flask==2.0.0");
  await fs.writeFile(path.join(tempDir, "node_modules", "leftpad", "index.js"), "x");
  await fs.writeFile(path.join(tempDir, "secrets", "creds.json"), "{}");
  await fs.writeFile(path.join(tempDir, "debug.log"), "log line");
  await fs.writeFile(path.join(tempDir, "photo.png"), "binary-ish");
  await fs.writeFile(path.join(tempDir, "big.ts"), "x".repeat(600_000));
});

afterAll(async () => {
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("walkDirectory", () => {
  it("includes scannable source files, including multi-tech languages", async () => {
    const { files } = await walkDirectory(tempDir);
    expect(files.has("src/app.ts")).toBe(true);
    expect(files.has("src/main.py")).toBe(true);
    expect(files.has("requirements.txt")).toBe(true);
  });

  it("respects .gitignore entries", async () => {
    const { files } = await walkDirectory(tempDir);
    expect(files.has("secrets/creds.json")).toBe(false);
    expect(files.has("debug.log")).toBe(false);
  });

  it("skips node_modules and irrelevant file types", async () => {
    const { files } = await walkDirectory(tempDir);
    expect(files.has("node_modules/leftpad/index.js")).toBe(false);
    expect(files.has("photo.png")).toBe(false);
  });

  it("skips files above the size cap and reports them", async () => {
    const { files, skippedLarge } = await walkDirectory(tempDir);
    expect(files.has("big.ts")).toBe(false);
    expect(skippedLarge).toContain("big.ts");
  });
});
