// @datahogo/core — public API.
// The scan engine takes a map of file paths to contents (plus an optional
// directory on disk to enable the external-binary engines) and returns
// findings, a security score, and per-engine results.

export { runScan } from "./orchestrator.js";
export type { ScanParams, ScanResult } from "./orchestrator.js";

export type {
  Severity,
  FindingContext,
  FindingConfidence,
  FindingData,
  EngineResult,
} from "./engines/types.js";

export { isRelevantFile, filterFiles } from "./utils/file-filter.js";
export { detectTechnologies } from "./scanning/tech-detector.js";
export type { TechDetectionResult } from "./scanning/tech-detector.js";
export type { Technology, ScanLog } from "./scanning/types.js";
