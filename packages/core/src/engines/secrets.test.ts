import { describe, it, expect } from "vitest";
import { detectSecrets } from "./secrets";

describe("detectSecrets", () => {
  it("detects OpenAI API keys", () => {
    const code = 'const key = "sk-proj-abc123def456ghi789jkl012mno";';
    const findings = detectSecrets(code, "src/config.ts");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("detects AWS access keys", () => {
    const code = "const key = 'AKIAIOSFODNN7REALKEY1';";
    const findings = detectSecrets(code, "src/aws.ts");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects GitHub tokens", () => {
    const code = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";';
    const findings = detectSecrets(code, "src/github.ts");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects Stripe secret keys", () => {
    // Built via concatenation so no contiguous Stripe-key-shaped literal
    // appears in source (avoids tripping GitHub push protection on our own
    // fake fixture — it's testing the sk_live_ prefix, not a real key).
    const fakeKey = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab";
    const code = `const key = "${fakeKey}";`;
    const findings = detectSecrets(code, "src/stripe.ts");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects database connection strings", () => {
    const code = 'const url = "postgres://user:password@host:5432/db";';
    const findings = detectSecrets(code, "src/db.ts");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].vulnerability_id).toBe(101);
  });

  it("ignores .env.example files", () => {
    const code = "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno";
    const findings = detectSecrets(code, ".env.example");
    expect(findings).toHaveLength(0);
  });

  it("ignores placeholder values", () => {
    const code = 'const key = "your_key_here";';
    const findings = detectSecrets(code, "src/config.ts");
    expect(findings).toHaveLength(0);
  });

  it("ignores process.env references", () => {
    const code = "const key = process.env.OPENAI_API_KEY;";
    const findings = detectSecrets(code, "src/config.ts");
    expect(findings).toHaveLength(0);
  });

  it("ignores markdown files", () => {
    const code = 'Use your key: sk-proj-abc123def456ghi789jkl012mno';
    const findings = detectSecrets(code, "README.md");
    expect(findings).toHaveLength(0);
  });

  it("ignores comments", () => {
    const code = '// const key = "sk-proj-abc123def456ghi789jkl012mno";';
    const findings = detectSecrets(code, "src/config.ts");
    expect(findings).toHaveLength(0);
  });
});
