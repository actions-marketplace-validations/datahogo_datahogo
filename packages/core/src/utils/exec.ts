// Shared utility for running external tool binaries with timeout support.
// Uses execFile (not exec) to avoid shell injection — critical for a security product.

import { execFile } from "./child-process.js";
import { warn } from "./logger.js";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecOptions {
  timeoutMs: number;
  cwd?: string;
  env?: Record<string, string>;
  maxBuffer?: number;
}

const DEFAULT_MAX_BUFFER = 10 * 1024 * 1024; // 10MB

/**
 * Execute a command with timeout. Returns stdout/stderr/exitCode.
 * Throws on timeout or signal kill. Does NOT throw on non-zero exit code
 * (many tools like gitleaks/npm audit exit non-zero when they find issues).
 */
export function execWithTimeout(
  command: string,
  args: string[],
  options: ExecOptions
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      {
        cwd: options.cwd,
        env: options.env ? { ...process.env, ...options.env } : undefined,
        maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
        timeout: 0, // We handle timeout ourselves for graceful kill
      },
      (error, stdout, stderr) => {
        clearTimeout(timer);

        if (timedOut) {
          return; // Already rejected by timeout handler
        }

        if (error && error.killed) {
          reject(new Error(`${command} was killed by signal`));
          return;
        }

        // Non-zero exit code is NOT an error — tools like gitleaks exit 1 on findings
        const exitCode = error?.code !== undefined
          ? (typeof error.code === "number" ? error.code : 1)
          : 0;

        resolve({ stdout, stderr, exitCode });
      }
    );

    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      warn(`${command} timed out after ${options.timeoutMs}ms, sending SIGTERM`);
      child.kill("SIGTERM");

      // Force kill after 5s if still alive
      const forceKillTimer = setTimeout(() => {
        if (!child.killed) {
          warn(`${command} did not exit after SIGTERM, sending SIGKILL`);
          child.kill("SIGKILL");
        }
      }, 5000);
      forceKillTimer.unref();

      reject(new Error(`${command} timed out after ${options.timeoutMs}ms`));
    }, options.timeoutMs);

    timer.unref();
  });
}
