import { describe, it, expect, beforeEach } from "vitest";
import {
  runMultiTechScan,
  registerAgent,
  clearAgentRegistry,
  getRegisteredAgents,
} from "./orchestrator";
import type { ScanAgent, ScanResult, AgentMetadata, CheckDefinition } from "./types";

/** Helper to create a mock agent. */
function createMockAgent(
  meta: AgentMetadata,
  detectResult: boolean,
  scanResults: ScanResult[],
): ScanAgent {
  return {
    detect: async () => detectResult,
    scan: async () => scanResults,
    getMetadata: () => meta,
  };
}

/** Helper to create a mock agent with getChecks(). */
function createMockAgentWithChecks(
  meta: AgentMetadata,
  detectResult: boolean,
  scanResults: ScanResult[],
  checks: CheckDefinition[],
): ScanAgent {
  return {
    detect: async () => detectResult,
    scan: async () => scanResults,
    getMetadata: () => meta,
    getChecks: () => checks,
  };
}

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

beforeEach(() => {
  clearAgentRegistry();
});

describe("agent registry", () => {
  it("starts empty", () => {
    expect(getRegisteredAgents()).toHaveLength(0);
  });

  it("registerAgent adds an agent", () => {
    const agent = createMockAgent(
      { name: "test", version: "1.0", technologies: ["nodejs"] },
      true,
      [],
    );
    registerAgent(agent);
    expect(getRegisteredAgents()).toHaveLength(1);
  });

  it("clearAgentRegistry removes all agents", () => {
    registerAgent(
      createMockAgent({ name: "a", version: "1.0", technologies: ["nodejs"] }, true, []),
    );
    registerAgent(
      createMockAgent({ name: "b", version: "1.0", technologies: ["python"] }, true, []),
    );
    expect(getRegisteredAgents()).toHaveLength(2);
    clearAgentRegistry();
    expect(getRegisteredAgents()).toHaveLength(0);
  });
});

describe("runMultiTechScan", () => {
  it("returns empty report when no agents registered", async () => {
    const files = makeFiles({ "package.json": '{ "dependencies": {} }' });
    const report = await runMultiTechScan(files);
    expect(report.score).toBe(100);
    expect(report.results).toHaveLength(0);
    expect(report.techsDetected).toContain("nodejs");
    expect(report.timestamp).toBeTruthy();
  });

  it("runs agents that match detected technologies", async () => {
    const findings: ScanResult[] = [
      {
        title: "SQL Injection",
        severity: "CRITICAL",
        file: "src/db.ts",
        line: 10,
        description: "Unsanitized query",
        fix: "Use parameterized queries",
        cwe: "CWE-89",
      },
    ];
    const agent = createMockAgent(
      { name: "nodejs-agent", version: "1.0", technologies: ["nodejs"] },
      true,
      findings,
    );
    registerAgent(agent);

    const files = makeFiles({ "package.json": '{ "dependencies": {} }' });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(1);
    expect(report.results[0].title).toBe("SQL Injection");
    expect(report.score).toBe(85); // 100 - 15 (CRITICAL)
  });

  it("skips agents whose technology is not detected", async () => {
    const agent = createMockAgent(
      { name: "python-agent", version: "1.0", technologies: ["python"] },
      true,
      [{ title: "Issue", severity: "HIGH", file: "app.py", line: 1, description: "d", fix: "f" }],
    );
    registerAgent(agent);

    const files = makeFiles({ "package.json": '{ "dependencies": {} }' });
    const report = await runMultiTechScan(files);

    // Python agent should not run — no python files detected
    expect(report.results).toHaveLength(0);
    expect(report.score).toBe(100);
  });

  it("skips agents whose detect() returns false", async () => {
    const agent = createMockAgent(
      { name: "strict-agent", version: "1.0", technologies: ["nodejs"] },
      false, // detect returns false even though nodejs is detected
      [{ title: "Issue", severity: "HIGH", file: "x.ts", line: 1, description: "d", fix: "f" }],
    );
    registerAgent(agent);

    const files = makeFiles({ "package.json": '{}' });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(0);
  });

  it("runs multiple agents in parallel", async () => {
    const nodeAgent = createMockAgent(
      { name: "node-agent", version: "1.0", technologies: ["nodejs"] },
      true,
      [{ title: "Eval usage", severity: "HIGH", file: "src/a.ts", line: 5, description: "d", fix: "f" }],
    );
    const reactAgent = createMockAgent(
      { name: "react-agent", version: "1.0", technologies: ["react"] },
      true,
      [{ title: "XSS", severity: "MEDIUM", file: "src/b.tsx", line: 10, description: "d", fix: "f" }],
    );
    registerAgent(nodeAgent);
    registerAgent(reactAgent);

    const files = makeFiles({
      "package.json": JSON.stringify({ dependencies: { react: "18.0" } }),
    });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(2);
    expect(report.score).toBe(85); // 100 - 10 (HIGH) - 5 (MEDIUM)
    expect(report.agentResults).toHaveLength(2);
  });

  it("handles agent errors gracefully", async () => {
    const crashingAgent: ScanAgent = {
      detect: async () => true,
      scan: async () => { throw new Error("Boom"); },
      getMetadata: () => ({ name: "crash-agent", version: "1.0", technologies: ["nodejs"] }),
    };
    registerAgent(crashingAgent);

    const files = makeFiles({ "package.json": '{}' });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(0);
    expect(report.score).toBe(100);
    expect(report.agentResults[0].error).toContain("Boom");
  });

  it("deduplicates findings from multiple agents", async () => {
    const finding: ScanResult = {
      title: "Same Issue",
      severity: "HIGH",
      file: "src/a.ts",
      line: 10,
      description: "d",
      fix: "f",
    };
    const agent1 = createMockAgent(
      { name: "agent-1", version: "1.0", technologies: ["nodejs"] },
      true,
      [finding],
    );
    const agent2 = createMockAgent(
      { name: "agent-2", version: "1.0", technologies: ["nodejs"] },
      true,
      [{ ...finding, line: 11 }], // Same file, ±2 lines = duplicate
    );
    registerAgent(agent1);
    registerAgent(agent2);

    const files = makeFiles({ "package.json": '{}' });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(1); // Deduplicated
    expect(report.score).toBe(90); // Only penalized once
  });

  it("does not deduplicate different findings", async () => {
    const agent = createMockAgent(
      { name: "multi-agent", version: "1.0", technologies: ["nodejs"] },
      true,
      [
        { title: "Issue A", severity: "HIGH", file: "a.ts", line: 1, description: "d", fix: "f" },
        { title: "Issue B", severity: "MEDIUM", file: "b.ts", line: 1, description: "d", fix: "f" },
      ],
    );
    registerAgent(agent);

    const files = makeFiles({ "package.json": '{}' });
    const report = await runMultiTechScan(files);

    expect(report.results).toHaveLength(2);
  });

  describe("score calculation", () => {
    it("returns 100 for no findings", async () => {
      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);
      expect(report.score).toBe(100);
    });

    it("calculates correct penalties", async () => {
      const agent = createMockAgent(
        { name: "test", version: "1.0", technologies: ["nodejs"] },
        true,
        [
          { title: "C", severity: "CRITICAL", file: "a.ts", line: 1, description: "d", fix: "f" },
          { title: "H", severity: "HIGH", file: "b.ts", line: 1, description: "d", fix: "f" },
          { title: "M", severity: "MEDIUM", file: "c.ts", line: 1, description: "d", fix: "f" },
          { title: "L", severity: "LOW", file: "d.ts", line: 1, description: "d", fix: "f" },
          { title: "I", severity: "INFO", file: "e.ts", line: 1, description: "d", fix: "f" },
        ],
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      // 100 - 15 - 10 - 5 - 2 - 0 = 68
      expect(report.score).toBe(68);
    });

    it("floors at 0", async () => {
      const findings: ScanResult[] = Array.from({ length: 10 }, (_, i) => ({
        title: `Critical ${i}`,
        severity: "CRITICAL" as const,
        file: `file${i}.ts`,
        line: 1,
        description: "d",
        fix: "f",
      }));
      const agent = createMockAgent(
        { name: "test", version: "1.0", technologies: ["nodejs"] },
        true,
        findings,
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      // 100 - (10 * 15) = -50 → 0
      expect(report.score).toBe(0);
    });
  });

  describe("techsDetected", () => {
    it("includes all detected technologies even without agents", async () => {
      const files = makeFiles({
        "package.json": JSON.stringify({
          dependencies: { next: "14.0", "@supabase/supabase-js": "2.0", stripe: "13.0" },
        }),
        "Dockerfile": "FROM node:20",
      });
      const report = await runMultiTechScan(files);
      expect(report.techsDetected).toContain("nodejs");
      expect(report.techsDetected).toContain("nextjs");
      expect(report.techsDetected).toContain("supabase");
      expect(report.techsDetected).toContain("stripe");
      expect(report.techsDetected).toContain("docker");
    });
  });

  describe("scanLog", () => {
    it("includes scanLog in report", async () => {
      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);
      expect(report.scanLog).toBeDefined();
      expect(report.scanLog.technologiesDetected).toEqual(report.techsDetected);
      expect(report.scanLog.totalDurationMs).toBeGreaterThanOrEqual(0);
    });

    it("tracks matched and confirmed agents", async () => {
      const agent = createMockAgentWithChecks(
        { name: "test-agent", version: "2.0", technologies: ["nodejs"] },
        true, [], [],
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      expect(report.scanLog.agentsMatched).toContain("test-agent");
      expect(report.scanLog.agentsConfirmed).toContain("test-agent");
    });

    it("separates matched from confirmed when detect() returns false", async () => {
      const agent = createMockAgentWithChecks(
        { name: "strict-agent", version: "1.0", technologies: ["nodejs"] },
        false, [], [{ id: "s:a", name: "A", severity: "HIGH" }],
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      expect(report.scanLog.agentsMatched).toContain("strict-agent");
      expect(report.scanLog.agentsConfirmed).not.toContain("strict-agent");
      expect(report.scanLog.agentLogs).toHaveLength(0);
    });

    it("builds checkResults by diffing getChecks vs findings", async () => {
      const checks: CheckDefinition[] = [
        { id: "test:check-a", name: "Check A", severity: "HIGH" },
        { id: "test:check-b", name: "Check B", severity: "MEDIUM" },
      ];
      const findings: ScanResult[] = [
        { title: "Found A", severity: "HIGH", file: "a.ts", line: 1, description: "d", fix: "f", checkId: "test:check-a" },
      ];
      const agent = createMockAgentWithChecks(
        { name: "check-agent", version: "1.0", technologies: ["nodejs"] },
        true, findings, checks,
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      const agentLog = report.scanLog.agentLogs[0];
      expect(agentLog.checkResults).toHaveLength(2);

      const checkA = agentLog.checkResults.find(c => c.checkId === "test:check-a");
      expect(checkA?.status).toBe("fail");
      expect(checkA?.findingCount).toBe(1);

      const checkB = agentLog.checkResults.find(c => c.checkId === "test:check-b");
      expect(checkB?.status).toBe("pass");
      expect(checkB?.findingCount).toBe(0);
    });

    it("counts multiple findings per check correctly", async () => {
      const checks: CheckDefinition[] = [
        { id: "test:multi", name: "Multi-hit check", severity: "HIGH" },
      ];
      const findings: ScanResult[] = [
        { title: "Hit 1", severity: "HIGH", file: "a.ts", line: 1, description: "d", fix: "f", checkId: "test:multi" },
        { title: "Hit 2", severity: "HIGH", file: "b.ts", line: 5, description: "d", fix: "f", checkId: "test:multi" },
        { title: "Hit 3", severity: "HIGH", file: "c.ts", line: 10, description: "d", fix: "f", checkId: "test:multi" },
      ];
      const agent = createMockAgentWithChecks(
        { name: "multi-agent", version: "1.0", technologies: ["nodejs"] },
        true, findings, checks,
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      const agentLog = report.scanLog.agentLogs[0];
      expect(agentLog.checkResults[0].findingCount).toBe(3);
      expect(agentLog.checkResults[0].status).toBe("fail");
    });

    it("summary totals are correct across multiple agents", async () => {
      const agent1 = createMockAgentWithChecks(
        { name: "agent-1", version: "1.0", technologies: ["nodejs"] },
        true,
        [{ title: "Issue", severity: "HIGH", file: "a.ts", line: 1, description: "d", fix: "f", checkId: "a:check" }],
        [{ id: "a:check", name: "Check A", severity: "HIGH" }],
      );
      const agent2 = createMockAgentWithChecks(
        { name: "agent-2", version: "1.0", technologies: ["nodejs"] },
        true,
        [],
        [
          { id: "b:check1", name: "B1", severity: "MEDIUM" },
          { id: "b:check2", name: "B2", severity: "LOW" },
        ],
      );
      registerAgent(agent1);
      registerAgent(agent2);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      expect(report.scanLog.agentLogs).toHaveLength(2);
      expect(report.scanLog.summary.totalChecks).toBe(3);
      expect(report.scanLog.summary.passed).toBe(2);
      expect(report.scanLog.summary.failed).toBe(1);
    });

    it("marks errored agent correctly in log", async () => {
      const crashingAgent: ScanAgent = {
        detect: async () => true,
        scan: async () => { throw new Error("Boom"); },
        getMetadata: () => ({ name: "crash-agent", version: "1.0", technologies: ["nodejs"] }),
        getChecks: () => [{ id: "crash:a", name: "A", severity: "HIGH" }],
      };
      registerAgent(crashingAgent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      const agentLog = report.scanLog.agentLogs[0];
      expect(agentLog.status).toBe("error");
      expect(agentLog.error).toContain("Boom");
      expect(agentLog.agentName).toBe("crash-agent");
    });

    it("agent without getChecks has empty checkResults", async () => {
      const agent = createMockAgent(
        { name: "old-agent", version: "1.0", technologies: ["nodejs"] },
        true,
        [{ title: "Issue", severity: "HIGH", file: "a.ts", line: 1, description: "d", fix: "f" }],
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      const agentLog = report.scanLog.agentLogs[0];
      expect(agentLog.checkResults).toHaveLength(0);
      expect(agentLog.totalChecks).toBe(0);
      expect(agentLog.passed).toBe(0);
      expect(agentLog.failed).toBe(0);
    });

    it("records agent version and technologies in log", async () => {
      const agent = createMockAgentWithChecks(
        { name: "versioned", version: "3.5", technologies: ["nodejs", "react"] },
        true, [], [],
      );
      registerAgent(agent);

      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { react: "18.0" } }),
      });
      const report = await runMultiTechScan(files);

      const agentLog = report.scanLog.agentLogs[0];
      expect(agentLog.agentVersion).toBe("3.5");
      expect(agentLog.technologies).toEqual(["nodejs", "react"]);
    });

    it("completed agent has correct status", async () => {
      const agent = createMockAgentWithChecks(
        { name: "good-agent", version: "1.0", technologies: ["nodejs"] },
        true, [], [{ id: "g:a", name: "A", severity: "LOW" }],
      );
      registerAgent(agent);

      const files = makeFiles({ "package.json": '{}' });
      const report = await runMultiTechScan(files);

      expect(report.scanLog.agentLogs[0].status).toBe("completed");
      expect(report.scanLog.agentLogs[0].durationMs).toBeGreaterThanOrEqual(0);
    });
  });
});
