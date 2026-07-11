// Converts scan results to SARIF 2.1.0 so findings can be uploaded to
// GitHub Code Scanning (or any SARIF-compatible viewer).

import type { FindingData, Severity } from "@datahogo/core";

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        version: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          helpUri?: string;
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number };
        };
      }>;
    }>;
  }>;
}

export function toSarif(findings: FindingData[], toolVersion: string): SarifLog {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  const results: SarifLog["runs"][0]["results"] = [];

  for (const finding of findings) {
    const ruleId = `datahogo-${finding.vulnerability_id}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: finding.title.replace(/[^a-zA-Z0-9]+/g, ""),
        shortDescription: { text: finding.title },
      });
    }

    const messageParts = [finding.title];
    if (finding.description_technical || finding.description_simple) {
      messageParts.push(finding.description_technical ?? finding.description_simple ?? "");
    }
    if (finding.fix_description) {
      messageParts.push(`Fix: ${finding.fix_description}`);
    }

    results.push({
      ruleId,
      level: SARIF_LEVEL[finding.severity],
      message: { text: messageParts.join("\n\n") },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.file_path ?? "unknown" },
            region: { startLine: finding.line_number && finding.line_number > 0 ? finding.line_number : 1 },
          },
        },
      ],
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "datahogo",
            informationUri: "https://github.com/datahogo/datahogo",
            version: toolVersion,
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
