// Re-export child_process functions for testability.
// Vitest cannot reliably mock node:child_process builtins.

export { execFile } from "node:child_process";
