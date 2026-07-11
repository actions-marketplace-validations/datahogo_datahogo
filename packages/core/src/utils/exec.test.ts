// Tests for the exec utility.
// We mock ./child-process.js (which re-exports node:child_process)
// and verify the Promise contract: resolves with stdout/stderr/exitCode, does NOT reject
// on non-zero exit codes, and does reject on timeout or signal kill.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---- module mocks (registered before any import) ----------------------

// Capture the execFile callback and child mock so tests can drive them.
let capturedCallback: (
  error: NodeJS.ErrnoException | null,
  stdout: string,
  stderr: string
) => void;

let mockKill = vi.fn();
let mockChildKilled = false;

vi.mock("./child-process.js", () => ({
  execFile: (
    _cmd: string,
    _args: string[],
    _options: unknown,
    cb: (error: NodeJS.ErrnoException | null, stdout: string, stderr: string) => void
  ) => {
    capturedCallback = cb;
    return {
      killed: mockChildKilled,
      kill: mockKill,
      unref: vi.fn(),
    };
  },
}));

// Suppress logger warn() output in tests
vi.mock("./logger.js", () => ({
  warn: vi.fn(),
}));

// -----------------------------------------------------------------------

import { execWithTimeout } from "./exec.js";

// -----------------------------------------------------------------------

beforeEach(() => {
  mockKill = vi.fn();
  mockChildKilled = false;
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("execWithTimeout", () => {
  describe("when the command succeeds", () => {
    it("resolves with stdout, stderr, and exitCode 0", async () => {
      const promise = execWithTimeout("echo", ["hello"], { timeoutMs: 5000 });

      capturedCallback(null, "hello\n", "");

      const result = await promise;

      expect(result.stdout).toBe("hello\n");
      expect(result.stderr).toBe("");
      expect(result.exitCode).toBe(0);
    });

    it("resolves with populated stderr alongside stdout", async () => {
      const promise = execWithTimeout("cmd", [], { timeoutMs: 5000 });

      capturedCallback(null, "out", "some warning");

      const result = await promise;

      expect(result.stdout).toBe("out");
      expect(result.stderr).toBe("some warning");
    });
  });

  describe("when the command exits with a non-zero code", () => {
    it("still resolves (does NOT throw) with the non-zero exit code", async () => {
      const promise = execWithTimeout("gitleaks", ["dir", "."], { timeoutMs: 5000 });

      // Simulate gitleaks exiting with code 1 (leaks found — expected behavior)
      const err = Object.assign(new Error("Command failed"), {
        code: 1,
      }) as NodeJS.ErrnoException;
      capturedCallback(err, "[]", "");

      const result = await promise;

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toBe("[]");
    });

    it("uses exit code 1 when error.code is a non-numeric string", async () => {
      const promise = execWithTimeout("npm", ["audit", "--json"], { timeoutMs: 5000 });

      const err = Object.assign(new Error("Command failed"), {
        code: "EACCES",
      }) as NodeJS.ErrnoException;
      capturedCallback(err, "", "permission denied");

      const result = await promise;

      expect(result.exitCode).toBe(1);
    });

    it("resolves with exitCode 0 when error is null (clean exit)", async () => {
      const promise = execWithTimeout("semgrep", ["scan", "--json"], { timeoutMs: 5000 });

      capturedCallback(null, "{}", "");

      const result = await promise;

      expect(result.exitCode).toBe(0);
    });
  });

  describe("when the process is killed by a signal", () => {
    it("rejects with a descriptive error when error.killed is true", async () => {
      const promise = execWithTimeout("gitleaks", [], { timeoutMs: 5000 });

      const err = Object.assign(new Error("Process killed"), {
        killed: true,
        code: "SIGTERM",
      }) as NodeJS.ErrnoException;
      capturedCallback(err, "", "");

      await expect(promise).rejects.toThrow("was killed by signal");
    });
  });

  describe("timeout behavior", () => {
    it("rejects with a timeout error when the timer fires", async () => {
      const promise = execWithTimeout("slow-tool", [], { timeoutMs: 1000 });

      vi.advanceTimersByTime(1001);

      await expect(promise).rejects.toThrow("timed out after 1000ms");
    });

    it("includes the command name in the timeout error message", async () => {
      const promise = execWithTimeout("my-scanner", [], { timeoutMs: 500 });

      vi.advanceTimersByTime(501);

      await expect(promise).rejects.toThrow("my-scanner timed out after 500ms");
    });

    it("does NOT reject when the callback fires before the timeout", async () => {
      const promise = execWithTimeout("fast-tool", [], { timeoutMs: 5000 });

      capturedCallback(null, "done", "");

      // Advance timers — the cleared timer should have no effect
      vi.advanceTimersByTime(10000);

      const result = await promise;
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("done");
    });
  });

  describe("options", () => {
    it("accepts an optional cwd option without throwing", async () => {
      const promise = execWithTimeout("node", ["--version"], {
        timeoutMs: 5000,
        cwd: "/tmp",
      });

      capturedCallback(null, "v20.0.0", "");

      const result = await promise;
      expect(result.stdout).toBe("v20.0.0");
    });

    it("accepts an optional env option without throwing", async () => {
      const promise = execWithTimeout("node", ["-e", "console.log(process.env.FOO)"], {
        timeoutMs: 5000,
        env: { FOO: "bar" },
      });

      capturedCallback(null, "bar", "");

      const result = await promise;
      expect(result.stdout).toBe("bar");
    });

    it("accepts an optional maxBuffer option without throwing", async () => {
      const promise = execWithTimeout("cat", ["bigfile"], {
        timeoutMs: 5000,
        maxBuffer: 50 * 1024 * 1024,
      });

      capturedCallback(null, "data", "");

      const result = await promise;
      expect(result.stdout).toBe("data");
    });
  });
});
