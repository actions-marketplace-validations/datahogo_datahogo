// Shared types for worker engines

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingContext =
  | "production"
  | "test"
  | "example"
  | "config"
  | "rule"
  | "vendored";

export type FindingConfidence = "high" | "medium" | "low";

export interface FindingData {
  vulnerability_id: number;
  severity: Severity;
  category: string;
  title: string;
  description_simple?: string;
  description_technical?: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  fix_description?: string;
  fix_code?: string;
  owasp_ref?: string;
  status: "open";
  context?: FindingContext;
  confidence?: FindingConfidence;
  // Post-processor fields
  is_framework_requirement?: boolean;
  framework_note?: string;
  classification?: "actionable" | "informational";
}

export interface EngineResult {
  engine: string;
  findings: FindingData[];
  error?: string;
  durationMs: number;
}
