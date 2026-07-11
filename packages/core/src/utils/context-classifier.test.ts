import { describe, it, expect } from "vitest";
import { classifyContext, classifyFindings } from "./context-classifier";

describe("classifyContext", () => {
  describe("test files", () => {
    it.each([
      "src/engines/config.test.ts",
      "src/engines/patterns.test.js",
      "src/utils/helpers.spec.tsx",
      "src/__tests__/api/scans.test.ts",
      "src/__mocks__/supabase.ts",
      "test/helpers.ts",
      "tests/integration/scan.ts",
      "fixtures/sample-repo/index.ts",
      "e2e/auth.spec.ts",
      "cypress/integration/login.ts",
      "playwright/tests/dashboard.ts",
      "src/components/Button.stories.tsx",
      "vitest.config.ts",
      "jest.config.js",
      "playwright.config.ts",
      "scripts/setup-e2e-user.ts",
      "scripts/setup-test-db.js",
      "supabase/seed.sql",
      "prisma/seed.ts",
      "db/seeds/users.ts",
    ])("classifies %s as test", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("test");
    });
  });

  describe("rule definitions and scanner engine code", () => {
    it.each([
      "worker/src/rules/xss-detection.yaml",
      "rules/owasp.yml",
      "config/.semgrep.yaml",
      ".gitleaks.toml",
      "worker/src/engines/patterns.ts",
      "worker/src/engines/secrets.ts",
      "worker/src/scanning/agents/python-agent.ts",
      "worker/src/scanning/agents/supabase-agent.ts",
    ])("classifies %s as rule", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("rule");
    });
  });

  describe("examples and documentation", () => {
    it.each([
      "content/blog/en/sql-injection.mdx",
      "content/learn/categories.json",
      "docs/ARCHITECTURE.md",
      "examples/vulnerable-app/index.ts",
      "demo/src/app.ts",
      "tutorials/getting-started.ts",
      "samples/webhook-handler.ts",
      "config.example.ts",
      "src/messages/en.json",
      "src/messages/es.json",
    ])("classifies %s as example", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("example");
    });
  });

  describe("config and scripts", () => {
    it.each([
      "scripts/generate-x-posts.js",
      "scripts/deploy.sh",
      ".github/workflows/ci.yml",
      ".circleci/config.yml",
      "infra/main.tf",
      "terraform/modules/vpc.tf",
      "pulumi/index.ts",
      "supabase/migrations/20260307_initial_schema.sql",
      "migrations/001_create_users.sql",
      "prisma/migrations/20260101_init/migration.sql",
    ])("classifies %s as config", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("config");
    });
  });

  describe("vendored / generated", () => {
    it.each([
      "vendor/github.com/lib/pq/conn.go",
      "generated/prisma/client.ts",
      "src/types/database.gen.ts",
      "src/api/client.generated.ts",
      "dist/index.js",
      "node_modules/lodash/index.js",
    ])("classifies %s as vendored", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("vendored");
    });
  });

  describe("production code", () => {
    it.each([
      "src/app/api/scans/route.ts",
      "src/lib/supabase/server.ts",
      "src/components/ui/score-circle.tsx",
      "worker/src/orchestrator.ts",
      "src/middleware.ts",
      "next.config.ts",
      "Dockerfile",
      "docker-compose.yml",
      "package.json",
      "tsconfig.json",
      "vercel.json",
      "src/app/[locale]/(dashboard)/scans/[id]/page.tsx",
    ])("classifies %s as production", (filePath) => {
      expect(classifyContext({ file_path: filePath })).toBe("production");
    });
  });

  describe("edge cases", () => {
    it("classifies findings without file_path as production", () => {
      expect(classifyContext({})).toBe("production");
      expect(classifyContext({ file_path: "" })).toBe("production");
    });

    it("classifies URL scanner findings (no file_path) as production", () => {
      expect(classifyContext({ file_path: undefined })).toBe("production");
    });
  });
});

describe("classifyFindings", () => {
  it("adds context to each finding", () => {
    const findings = [
      { file_path: "src/app/api/route.ts", vulnerability_id: 1 },
      { file_path: "src/engines/config.test.ts", vulnerability_id: 2 },
      { file_path: "content/blog/en/post.mdx", vulnerability_id: 3 },
    ];

    const result = classifyFindings(findings);
    expect(result[0].context).toBe("production");
    expect(result[1].context).toBe("test");
    expect(result[2].context).toBe("example");
  });

  it("preserves all original fields", () => {
    const finding = {
      file_path: "src/index.ts",
      vulnerability_id: 42,
      severity: "high" as const,
      title: "Test",
      status: "open" as const,
      category: "web-owasp",
    };

    const [result] = classifyFindings([finding]);
    expect(result.vulnerability_id).toBe(42);
    expect(result.severity).toBe("high");
    expect(result.title).toBe("Test");
    expect(result.context).toBe("production");
  });
});
