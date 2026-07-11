// Re-export fs/promises functions for testability.
// Vitest cannot reliably mock node:fs/promises builtins,
// so engines import from this module instead.

export { readFile, rm, access } from "node:fs/promises";
