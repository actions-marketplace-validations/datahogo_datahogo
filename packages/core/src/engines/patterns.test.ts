import { describe, it, expect } from "vitest";
import { analyzePatterns } from "./patterns";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

describe("analyzePatterns", () => {
  describe("API Route Without Auth Check", () => {
    it("detects API route missing auth check", () => {
      const code = `
export async function GET(req: Request) {
  const data = await fetchData();
  return Response.json({ data });
}`;
      const files = makeFiles({ "src/app/api/users/route.ts": code });
      const findings = analyzePatterns(files);
      const authFindings = findings.filter((f) => f.vulnerability_id === 1);
      expect(authFindings.length).toBeGreaterThan(0);
      expect(authFindings[0].severity).toBe("high");
      expect(authFindings[0].category).toBe("web-owasp");
    });

    it("does not flag API route with getUser auth check", () => {
      const code = `
export async function GET(req: Request) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
  return Response.json({ data });
}`;
      const files = makeFiles({ "src/app/api/users/route.ts": code });
      const findings = analyzePatterns(files);
      const authFindings = findings.filter((f) => f.vulnerability_id === 1);
      expect(authFindings).toHaveLength(0);
    });

    it("does not flag webhook routes", () => {
      const code = `
export async function POST(req: Request) {
  const body = await req.json();
  return Response.json({ ok: true });
}`;
      const files = makeFiles({ "src/app/api/webhooks/github/route.ts": code });
      const findings = analyzePatterns(files);
      const authFindings = findings.filter((f) => f.vulnerability_id === 1);
      expect(authFindings).toHaveLength(0);
    });
  });

  describe("eval() with Dynamic Input", () => {
    it("detects eval with dynamic variable", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/utils/run.ts": code });
      const findings = analyzePatterns(files);
      const evalFindings = findings.filter((f) => f.vulnerability_id === 61);
      expect(evalFindings.length).toBeGreaterThan(0);
      expect(evalFindings[0].severity).toBe("critical");
      expect(evalFindings[0].category).toBe("vibecoding");
    });

    it("detects eval with template literal containing interpolation", () => {
      const code = "const result = eval(`console.log(${data})`);";
      const files = makeFiles({ "src/exec.ts": code });
      const findings = analyzePatterns(files);
      const evalFindings = findings.filter((f) => f.vulnerability_id === 61);
      expect(evalFindings.length).toBeGreaterThan(0);
    });

    it("detects Function constructor with dynamic input", () => {
      const code = "const fn = Function(userCode);";
      const files = makeFiles({ "src/exec.ts": code });
      const findings = analyzePatterns(files);
      const evalFindings = findings.filter((f) => f.vulnerability_id === 61);
      expect(evalFindings.length).toBeGreaterThan(0);
    });
  });

  describe("Potential SQL Injection", () => {
    it("detects raw query with template literal interpolation", () => {
      const code = "const result = await prisma.$queryRaw(`SELECT * FROM users WHERE id = ${userId}`);";
      const files = makeFiles({ "src/db/queries.ts": code });
      const findings = analyzePatterns(files);
      const sqlFindings = findings.filter((f) => f.vulnerability_id === 5);
      expect(sqlFindings.length).toBeGreaterThan(0);
      expect(sqlFindings[0].severity).toBe("critical");
      expect(sqlFindings[0].owasp_ref).toBe("A03:2021");
    });

    it("detects sequelize.query with interpolation", () => {
      const code = "const result = await sequelize.query(`DELETE FROM users WHERE id = ${id}`);";
      const files = makeFiles({ "src/db/raw.ts": code });
      const findings = analyzePatterns(files);
      const sqlFindings = findings.filter((f) => f.vulnerability_id === 5);
      expect(sqlFindings.length).toBeGreaterThan(0);
    });
  });

  describe("Weak Hash Algorithm (MD5/SHA1)", () => {
    it("detects MD5 hashing", () => {
      const code = `const hash = crypto.createHash("md5").update(data).digest("hex");`;
      const files = makeFiles({ "src/utils/hash.ts": code });
      const findings = analyzePatterns(files);
      const hashFindings = findings.filter((f) => f.vulnerability_id === 2);
      expect(hashFindings.length).toBeGreaterThan(0);
      expect(hashFindings[0].severity).toBe("high");
      expect(hashFindings[0].owasp_ref).toBe("A02:2021");
    });

    it("detects SHA1 hashing", () => {
      const code = `const hash = crypto.createHash('sha1').update(password).digest('hex');`;
      const files = makeFiles({ "src/utils/hash.ts": code });
      const findings = analyzePatterns(files);
      const hashFindings = findings.filter((f) => f.vulnerability_id === 2);
      expect(hashFindings.length).toBeGreaterThan(0);
    });

    it("does not flag SHA256", () => {
      const code = `const hash = crypto.createHash("sha256").update(data).digest("hex");`;
      const files = makeFiles({ "src/utils/hash.ts": code });
      const findings = analyzePatterns(files);
      const hashFindings = findings.filter((f) => f.vulnerability_id === 2);
      expect(hashFindings).toHaveLength(0);
    });
  });

  describe("dangerouslySetInnerHTML Without Sanitization", () => {
    it("detects dangerouslySetInnerHTML without sanitizer", () => {
      const code = `<div dangerouslySetInnerHTML={{ __html: userContent }} />`;
      const files = makeFiles({ "src/components/preview.tsx": code });
      const findings = analyzePatterns(files);
      const xssFindings = findings.filter((f) => f.vulnerability_id === 46);
      expect(xssFindings.length).toBeGreaterThan(0);
      expect(xssFindings[0].severity).toBe("high");
    });

    it("does not flag dangerouslySetInnerHTML with DOMPurify", () => {
      const code = `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />`;
      const files = makeFiles({ "src/components/preview.tsx": code });
      const findings = analyzePatterns(files);
      const xssFindings = findings.filter((f) => f.vulnerability_id === 46);
      expect(xssFindings).toHaveLength(0);
    });

    it("only checks tsx/jsx files", () => {
      const code = `dangerouslySetInnerHTML={{ __html: userContent }}`;
      const files = makeFiles({ "src/utils/config.ts": code });
      const findings = analyzePatterns(files);
      const xssFindings = findings.filter((f) => f.vulnerability_id === 46);
      expect(xssFindings).toHaveLength(0);
    });
  });

  describe("Open CORS Policy", () => {
    it("detects hardcoded CORS wildcard", () => {
      const code = `res.setHeader("Access-Control-Allow-Origin", "*");`;
      const files = makeFiles({ "src/app/api/data/route.ts": code });
      const findings = analyzePatterns(files);
      const corsFindings = findings.filter(
        (f) => f.vulnerability_id === 4 || f.vulnerability_id === 50
      );
      expect(corsFindings.length).toBeGreaterThan(0);
    });

    it("detects CORS * in header string", () => {
      const code = `headers.set("Access-Control-Allow-Origin", "*")`;
      const files = makeFiles({ "src/app/api/data/route.ts": code });
      const findings = analyzePatterns(files);
      const corsFindings = findings.filter(
        (f) => f.vulnerability_id === 4 || f.vulnerability_id === 50
      );
      expect(corsFindings.length).toBeGreaterThan(0);
    });
  });

  describe("Supabase Service Role Key in Client Code", () => {
    it("detects NEXT_PUBLIC env var referencing service role", () => {
      const code = `const key = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY;`;
      const files = makeFiles({ "src/lib/supabase/client.ts": code });
      const findings = analyzePatterns(files);
      const supabaseFindings = findings.filter((f) => f.vulnerability_id === 34);
      expect(supabaseFindings.length).toBeGreaterThan(0);
      expect(supabaseFindings[0].severity).toBe("critical");
    });
  });

  describe("Math.random for Security Purpose", () => {
    it("detects Math.random used for token generation", () => {
      const code = `const token = Math.random().toString(36);`;
      const files = makeFiles({ "src/utils/auth.ts": code });
      const findings = analyzePatterns(files);
      const mathFindings = findings.filter((f) => f.vulnerability_id === 125);
      expect(mathFindings.length).toBeGreaterThan(0);
      expect(mathFindings[0].severity).toBe("high");
    });
  });

  describe("JWT Algorithm None Allowed", () => {
    it("detects algorithms array including none", () => {
      const code = `const options = { algorithms: ["none", "HS256"] };`;
      const files = makeFiles({ "src/auth/jwt.ts": code });
      const findings = analyzePatterns(files);
      const jwtFindings = findings.filter((f) => f.vulnerability_id === 126);
      expect(jwtFindings.length).toBeGreaterThan(0);
      expect(jwtFindings[0].severity).toBe("critical");
    });
  });

  describe("Tokens Stored in localStorage", () => {
    it("detects storing JWT in localStorage", () => {
      const code = `localStorage.setItem("token", jwtToken);`;
      const files = makeFiles({ "src/lib/auth.ts": code });
      const findings = analyzePatterns(files);
      const storageFindings = findings.filter((f) => f.vulnerability_id === 47);
      expect(storageFindings.length).toBeGreaterThan(0);
      expect(storageFindings[0].severity).toBe("high");
    });
  });

  describe("TLS Certificate Validation Disabled", () => {
    it("detects NODE_TLS_REJECT_UNAUTHORIZED = 0", () => {
      const code = `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`;
      const files = makeFiles({ "src/api/client.ts": code });
      const findings = analyzePatterns(files);
      const tlsFindings = findings.filter((f) => f.vulnerability_id === 124);
      expect(tlsFindings.length).toBeGreaterThan(0);
      expect(tlsFindings[0].severity).toBe("critical");
    });
  });

  describe("Environment Variables Logged", () => {
    it("detects console.log of process.env", () => {
      const code = `console.log(process.env.SECRET_KEY);`;
      const files = makeFiles({ "src/debug.ts": code });
      const findings = analyzePatterns(files);
      const logFindings = findings.filter((f) => f.vulnerability_id === 134);
      expect(logFindings.length).toBeGreaterThan(0);
      expect(logFindings[0].severity).toBe("high");
    });
  });

  describe("RLS Policy with USING(true) in SQL", () => {
    it("detects USING(true) in SQL files", () => {
      const code = `CREATE POLICY "allow_all" ON users USING (true);`;
      const files = makeFiles({ "supabase/migrations/001.sql": code });
      const findings = analyzePatterns(files);
      const rlsFindings = findings.filter((f) => f.vulnerability_id === 32);
      expect(rlsFindings.length).toBeGreaterThan(0);
      expect(rlsFindings[0].severity).toBe("critical");
    });
  });

  describe("returns empty for clean code", () => {
    it("returns no findings for well-written secure code", () => {
      const code = `
import { createClient } from "@/lib/supabase/server";
import { rateLimiter } from "@/lib/rate-limit";

export async function GET(req: Request) {
  const supabase = createClient();
  await rateLimiter.check(req);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const { data } = await supabase.from("scans").select("id, score, created_at").eq("user_id", user.id);
  return Response.json({ data });
}`;
      const files = makeFiles({ "src/lib/data/scans.ts": code });
      const findings = analyzePatterns(files);
      expect(findings).toHaveLength(0);
    });
  });

  describe("returns correct severity levels", () => {
    it("critical for SQL injection", () => {
      const code = "await prisma.$queryRaw(`SELECT * FROM users WHERE id = ${id}`);";
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const sqlFindings = findings.filter((f) => f.vulnerability_id === 5);
      expect(sqlFindings[0].severity).toBe("critical");
    });

    it("high for weak hash", () => {
      const code = `crypto.createHash("md5").update(x).digest("hex");`;
      const files = makeFiles({ "src/hash.ts": code });
      const findings = analyzePatterns(files);
      const hashFindings = findings.filter((f) => f.vulnerability_id === 2);
      expect(hashFindings[0].severity).toBe("high");
    });

    it("medium for open CORS", () => {
      const code = `Access-Control-Allow-Origin: "*"`;
      const files = makeFiles({ "src/config.ts": code });
      const findings = analyzePatterns(files);
      const corsFindings = findings.filter((f) => f.vulnerability_id === 4);
      expect(corsFindings[0].severity).toBe("medium");
    });
  });

  describe("file filtering", () => {
    it("skips non-source files", () => {
      const code = `eval(userInput);`;
      const files = makeFiles({ "README.md": code });
      const findings = analyzePatterns(files);
      expect(findings).toHaveLength(0);
    });

    it("processes .ts files", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/run.ts": code });
      const findings = analyzePatterns(files);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("processes .sql files", () => {
      const code = `CREATE POLICY "bad" ON users USING (true);`;
      const files = makeFiles({ "supabase/migrations/001.sql": code });
      const findings = analyzePatterns(files);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe("finding structure", () => {
    it("includes all required fields", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/exec.ts": code });
      const findings = analyzePatterns(files);
      expect(findings.length).toBeGreaterThan(0);

      const finding = findings[0];
      expect(finding).toHaveProperty("vulnerability_id");
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("category");
      expect(finding).toHaveProperty("title");
      expect(finding).toHaveProperty("file_path");
      expect(finding).toHaveProperty("line_number");
      expect(finding).toHaveProperty("code_snippet");
      expect(finding).toHaveProperty("status");
      expect(finding.status).toBe("open");
    });

    it("reports correct file path", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/dangerous/exec.ts": code });
      const findings = analyzePatterns(files);
      expect(findings[0].file_path).toBe("src/dangerous/exec.ts");
    });

    it("reports correct line number", () => {
      const code = `const x = 1;\nconst y = 2;\nconst result = eval(userInput);\nconst z = 3;`;
      const files = makeFiles({ "src/exec.ts": code });
      const findings = analyzePatterns(files);
      const evalFindings = findings.filter((f) => f.vulnerability_id === 61);
      expect(evalFindings[0].line_number).toBe(3);
    });
  });

  describe("multiple files", () => {
    it("scans all files in the map", () => {
      const files = makeFiles({
        "src/a.ts": `const result = eval(userInput);`,
        "src/b.ts": `crypto.createHash("md5").update(x).digest("hex");`,
      });
      const findings = analyzePatterns(files);
      expect(findings.length).toBeGreaterThanOrEqual(2);
      const filePathsWithFindings = [...new Set(findings.map((f) => f.file_path))];
      expect(filePathsWithFindings).toContain("src/a.ts");
      expect(filePathsWithFindings).toContain("src/b.ts");
    });
  });

  // =========================================================================
  // AI / LLM Security (IDs 200, 203, 208)
  // =========================================================================

  describe("Prompt Injection — User Input in LLM Prompt (ID 200)", () => {
    it("detects user request body interpolated into prompt template", () => {
      const code = [
        `import Anthropic from "@anthropic-ai/sdk";`,
        "const prompt = `You are helpful. User said: ${req.body.message}`;",
        `await client.messages.create({ model: "claude-3", messages: [{ role: "user", content: prompt }] });`,
      ].join("\n");
      const files = makeFiles({ "src/ai/chat.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("ai-llm");
    });

    it("detects query parameter interpolated into a prompt sent to an LLM", () => {
      const code = [
        "const prompt = `Summarize: ${query.userInput}`;",
        `await anthropic.messages.create({ messages: [{ role: "user", content: prompt }] });`,
      ].join("\n");
      const files = makeFiles({ "src/ai/summarize.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects user input pushed into messages array", () => {
      const code = [
        `messages.push({ role: "user", content: req.body.text });`,
        `await client.messages.create({ messages });`,
      ].join("\n");
      const files = makeFiles({ "src/ai/messages.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag a static system prompt with no user input", () => {
      const code = [
        `import OpenAI from "openai";`,
        "const prompt = `You are a helpful assistant. Always respond concisely.`;",
      ].join("\n");
      const files = makeFiles({ "src/ai/chat.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match).toHaveLength(0);
    });

    // Regression: the exact false positive found while dogfooding — user input
    // interpolated into an EMAIL html template (variable named `content`) with
    // no LLM anywhere in the file must NOT be flagged as prompt injection.
    it("does not flag user input in an email/HTML content template (no LLM)", () => {
      const code = [
        "const content = `<p>${params.toolLabel} results</p>${sanitize(params.resultsSummary)}`;",
        "return sendRawEmail({ to, subject, html: content });",
      ].join("\n");
      const files = makeFiles({ "src/lib/email/client.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match).toHaveLength(0);
    });

    // Regression: user input in a prompt-shaped template, but the file never
    // talks to an LLM (e.g. a greeting builder). The requiresNearby guard must
    // suppress it.
    it("does not flag a prompt-shaped template in a file with no LLM usage", () => {
      const code = "const prompt = `Dear ${req.body.name}, welcome to the team`;";
      const files = makeFiles({ "src/email/greeting.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match).toHaveLength(0);
    });
  });

  describe("AI API Key Exposed in Frontend (ID 203)", () => {
    it("detects NEXT_PUBLIC_ANTHROPIC_API_KEY usage", () => {
      const code = `const key = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY;`;
      const files = makeFiles({ "src/lib/ai.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("ai-llm");
      expect(match[0].owasp_ref).toBe("A07:2021");
    });

    it("detects NEXT_PUBLIC_OPENAI_API_KEY usage", () => {
      const code = `const apiKey = process.env.NEXT_PUBLIC_OPENAI_API_KEY;`;
      const files = makeFiles({ "src/hooks/use-ai.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects NEXT_PUBLIC_AI_API_KEY usage", () => {
      const code = `const key = process.env.NEXT_PUBLIC_AI_API_KEY;`;
      const files = makeFiles({ "src/components/chat.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects window.ANTHROPIC_API_KEY usage", () => {
      const code = `const key = window.ANTHROPIC_API_KEY;`;
      const files = makeFiles({ "src/utils/ai.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag server-side ANTHROPIC_API_KEY without NEXT_PUBLIC prefix", () => {
      const code = `const key = process.env.ANTHROPIC_API_KEY;`;
      const files = makeFiles({ "src/lib/server/ai.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match).toHaveLength(0);
    });

    it("does not flag OPENAI_API_KEY used server-side", () => {
      const code = `const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });`;
      const files = makeFiles({ "src/lib/server/openai.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match).toHaveLength(0);
    });
  });

  describe("AI-Generated Code Executed Dynamically (ID 208)", () => {
    it("detects eval on AI completion response", () => {
      const code = `eval(completion.choices[0].text)`;
      const files = makeFiles({ "src/ai/execute.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 61);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
    });

    it("detects Function constructor called with AI response", () => {
      const code = `const fn = Function(aiOutput);`;
      const files = makeFiles({ "src/ai/runner.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 61);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects vm.run on LLM-generated code", () => {
      const code = `vm.run(llmResult.code)`;
      const files = makeFiles({ "src/sandbox/runner.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 61);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects eval on generated code variable", () => {
      const code = `const result = eval(generated);`;
      const files = makeFiles({ "src/execute.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 61);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag eval on plain user input as AI-generated code execution", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/execute.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.title === "AI-Generated Code Executed Dynamically");
      expect(match).toHaveLength(0);
    });
  });

  // =========================================================================
  // Database Connection Security (IDs 209, 211, 212, 213, 214, 219)
  // =========================================================================

  describe("Database Connection Without SSL (ID 209)", () => {
    it("detects createPool without ssl option", () => {
      const code = `const pool = createPool({ host: "db.prod.example.com", user: "admin", database: "app" })`;
      const files = makeFiles({ "src/database/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects createConnection without ssl option", () => {
      const code = `const conn = createConnection({ host: "db.prod.example.com", user: "root" })`;
      const files = makeFiles({ "src/database/connection.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects new Pool without ssl option", () => {
      const code = `const pool = new Pool({ connectionString: "postgresql://user@db.prod.example.com/db" })`;
      const files = makeFiles({ "src/db/pool.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag createPool with ssl enabled", () => {
      const code = `const pool = createPool({ host: "db.prod.example.com", ssl: true })`;
      const files = makeFiles({ "src/database/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });

    it("does not flag createConnection with sslmode specified", () => {
      const code = `const conn = createConnection({ host: "db.example.com", sslmode: "require" })`;
      const files = makeFiles({ "src/database/connection.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });
  });

  describe("Default Database Credentials (ID 211)", () => {
    it("detects postgres:postgres in connection URL", () => {
      const code = `const url = "postgres:postgres@db.prod.example.com:5432/myapp";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects root:root in connection URL", () => {
      const code = `const dbUrl = "mysql://root:root@db.prod.example.com/app";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects admin:admin credentials", () => {
      const code = `const conn = "admin:admin@db.prod.example.com";`;
      const files = makeFiles({ "src/config.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects user:password default credentials", () => {
      const code = `const dsn = "user:password@db.prod.example.com/mydb";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag strong custom credentials", () => {
      const code = `const url = "pguser:s3cur3RandomP@ssw0rd!@db.prod.example.com/app";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });
  });

  describe("Database Connection String with Inline Password (ID 212)", () => {
    it("detects postgresql connection string with inline password on remote host", () => {
      const code = `const url = "postgresql://admin:mypassword@db.prod.example.com:5432/app";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects mysql connection string with inline password", () => {
      const code = `const dsn = "mysql://dbuser:secretpass@db.example.com:3306/shop";`;
      const files = makeFiles({ "src/database/mysql.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects mongodb connection string with inline password on remote host", () => {
      const code = `const uri = "mongodb://mongouser:s3cret@db.prod.example.com:27017/mydb";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag localhost connection strings (development)", () => {
      const code = `const url = "postgresql://admin:devpass@localhost:5432/app";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });

    it("does not flag 127.0.0.1 connection strings (development)", () => {
      const code = `const url = "mysql://root:devpass@127.0.0.1:3306/app";`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });
  });

  describe("MongoDB Connection Without Authentication (ID 213)", () => {
    it("detects mongodb connection to remote host without authSource", () => {
      const code = `const client = new MongoClient("mongodb://db.prod.example.com:27017/app");`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects mongodb:// connection string without credentials", () => {
      const code = `mongoose.connect("mongodb://mongo.prod.example.com:27017/mydb");`;
      const files = makeFiles({ "src/db/mongo.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag localhost MongoDB connection (development)", () => {
      const code = `const client = new MongoClient("mongodb://localhost:27017/app");`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });

    it("does not flag 127.0.0.1 MongoDB connection (development)", () => {
      const code = `mongoose.connect("mongodb://127.0.0.1:27017/app");`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });
  });

  describe("Redis Without Authentication (ID 214)", () => {
    it("detects redis:// URL without password on remote host", () => {
      const code = `const url = "redis://cache.prod.example.com:6379";`;
      const files = makeFiles({ "src/cache.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects new Redis({}) without password option", () => {
      const code = `const redis = new Redis({ host: "cache.prod.example.com", port: 6379 });`;
      const files = makeFiles({ "src/cache.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag redis:// URL with password", () => {
      const code = `const url = "redis://:myStrongPassword@cache.prod.example.com:6379";`;
      const files = makeFiles({ "src/cache.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });

    it("does not flag new Redis with password option", () => {
      const code = `const redis = new Redis({ host: "cache.prod.example.com", port: 6379, password: process.env.REDIS_PASSWORD });`;
      const files = makeFiles({ "src/cache.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 101);
      expect(match).toHaveLength(0);
    });
  });

  describe("Database SSL Certificate Validation Disabled (ID 219)", () => {
    it("detects rejectUnauthorized: false inside ssl block", () => {
      const code = `
const pool = createPool({
  host: "db.prod.example.com",
  ssl: {
    rejectUnauthorized: false
  }
});`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 2);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("database-connection");
    });

    it("detects tls block with rejectUnauthorized: false", () => {
      const code = `
const options = {
  tls: {
    rejectUnauthorized: false
  }
};`;
      const files = makeFiles({ "src/database/config.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 2);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag rejectUnauthorized: true", () => {
      const code = `
const pool = createPool({
  ssl: {
    rejectUnauthorized: true
  }
});`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 2);
      expect(match).toHaveLength(0);
    });

    it("does not flag ssl: true shorthand (safe)", () => {
      const code = `const pool = createPool({ host: "db.prod.example.com", ssl: true });`;
      const files = makeFiles({ "src/db.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 2);
      expect(match).toHaveLength(0);
    });
  });

  // =========================================================================
  // Cloud Provider Security (IDs 221, 222, 223)
  // =========================================================================

  describe("S3 Bucket Public Access (ID 221)", () => {
    it("detects BlockPublicAccess: false", () => {
      const code = `const bucket = { BlockPublicAccess: false, BucketName: "my-bucket" };`;
      const files = makeFiles({ "src/storage.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 4);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("cloud");
      expect(match[0].owasp_ref).toBe("A05:2021");
    });

    it("detects ACL: 'public-read'", () => {
      const code = `const params = { Bucket: "my-assets", ACL: "public-read" };`;
      const files = makeFiles({ "src/s3.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 4);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects s3:PutBucketPolicy with wildcard principal", () => {
      const code = `const policy = { Action: "s3:PutBucketPolicy", Principal: "*" };`;
      const files = makeFiles({ "src/iam.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 4);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag private bucket configuration", () => {
      const code = `const params = { Bucket: "my-bucket", ACL: "private" };`;
      const files = makeFiles({ "src/s3.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 4);
      expect(match).toHaveLength(0);
    });
  });

  describe("Cloud Metadata SSRF Vector (ID 222)", () => {
    it("detects AWS IMDS URL 169.254.169.254", () => {
      const code = `const metadataUrl = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";`;
      const files = makeFiles({ "src/utils.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 10);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("cloud");
      expect(match[0].owasp_ref).toBe("A10:2021");
    });

    it("detects GCP metadata endpoint metadata.google.internal", () => {
      const code = `const url = "http://metadata.google.internal/computeMetadata/v1/instance/";`;
      const files = makeFiles({ "src/gcp.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 10);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects ECS metadata endpoint 169.254.170.2", () => {
      const code = `const credUrl = "http://169.254.170.2" + process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI;`;
      const files = makeFiles({ "src/aws.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 10);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag unrelated IP addresses", () => {
      const code = `const apiUrl = "https://192.168.1.100/api/data";`;
      const files = makeFiles({ "src/api.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 10);
      expect(match).toHaveLength(0);
    });
  });

  describe("AWS Credentials Hardcoded (ID 223)", () => {
    it("detects hardcoded aws_access_key_id", () => {
      const code = `const aws_access_key_id = "AKIAIOSFODNN7EXAMPLE1234";`;
      const files = makeFiles({ "src/aws.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("cloud");
    });

    it("detects hardcoded aws_secret_access_key", () => {
      const code = `const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";`;
      const files = makeFiles({ "src/config.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects AWS_ACCESS_KEY_ID assigned a literal value", () => {
      const code = `AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLEKEY12345"`;
      const files = makeFiles({ "src/deploy.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag reading AWS credentials from environment variables", () => {
      const code = `const accessKeyId = process.env.AWS_ACCESS_KEY_ID;`;
      const files = makeFiles({ "src/aws.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match).toHaveLength(0);
    });

    it("does not flag an empty AWS key reference", () => {
      const code = `const config = { region: "us-east-1" };`;
      const files = makeFiles({ "src/aws.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 53);
      expect(match).toHaveLength(0);
    });
  });

  // =========================================================================
  // CI/CD Pipeline Security (IDs 241, 242)
  // Note: .yml/.yaml are not supported by isSourceFile. Tests use .ts files
  // with .github/workflows/ in the path to satisfy the fileFilter.
  // =========================================================================

  describe("Unpinned GitHub Action (ID 241)", () => {
    it("detects action pinned to @main branch", () => {
      const code = `uses: actions/checkout@main\n`;
      const files = makeFiles({ ".github/workflows/ci.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 140);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("cicd");
    });

    it("detects action pinned to @master branch", () => {
      const code = `uses: actions/setup-node@master\n`;
      const files = makeFiles({ ".github/workflows/build.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 140);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects action pinned to @latest tag", () => {
      const code = `uses: docker/build-push-action@latest\n`;
      const files = makeFiles({ ".github/workflows/release.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 140);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects action pinned to mutable version tag like @v3", () => {
      const code = `uses: actions/checkout@v3\n`;
      const files = makeFiles({ ".github/workflows/ci.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 140);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag action pinned to a full SHA hash", () => {
      const code = `uses: actions/checkout@abc1234567890abcdef1234567890abcdef123456\n`;
      const files = makeFiles({ ".github/workflows/ci.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 140);
      expect(match).toHaveLength(0);
    });
  });

  describe("GitHub Actions Script Injection (ID 242)", () => {
    it("detects github.event.issue.title injected into run step", () => {
      // Using string concatenation to avoid template literal parsing issues with ${{ }}
      const code = "run: echo ${{ github.event.issue.title }}\n";
      const files = makeFiles({ ".github/workflows/ci.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("critical");
      expect(match[0].category).toBe("cicd");
      expect(match[0].owasp_ref).toBe("A03:2021");
    });

    it("detects github.event.pull_request.body injected into run step", () => {
      const code = "run: echo ${{ github.event.pull_request.body }}\n";
      const files = makeFiles({ ".github/workflows/pr.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects github.event.comment.body injected into run step", () => {
      const code = "run: echo ${{ github.event.comment.body }}\n";
      const files = makeFiles({ ".github/workflows/comment.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects github.event.pull_request.head.ref in run step", () => {
      const code = "run: git checkout ${{ github.event.pull_request.head.ref }}\n";
      const files = makeFiles({ ".github/workflows/deploy.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag safe run steps without github event interpolation", () => {
      const code = "run: echo 'Hello World'\n";
      const files = makeFiles({ ".github/workflows/ci.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 75);
      expect(match).toHaveLength(0);
    });
  });

  // =========================================================================
  // WebSocket & Real-time (IDs 249, 250)
  // =========================================================================

  describe("WebSocket Missing Origin Validation (ID 249)", () => {
    it("detects wss.on connection handler without origin validation", () => {
      const code = `
wss.on('connection', (socket) => {
  socket.on('message', (data) => { process(data); });
});`;
      const files = makeFiles({ "src/server.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 1);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("high");
      expect(match[0].category).toBe("websocket");
    });

    it("detects ws.on connection handler without origin validation", () => {
      const code = `
ws.on('connection', (socket, req) => {
  socket.send('welcome');
});`;
      const files = makeFiles({ "src/realtime.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 1);
      expect(match.length).toBeGreaterThan(0);
    });

    it("detects io.on connection handler (Socket.io) without origin check", () => {
      const code = `
io.on('connection', (socket) => {
  socket.on('join', (room) => socket.join(room));
});`;
      const files = makeFiles({ "src/socket.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 1);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag WebSocket server that uses verifyClient option", () => {
      const code = `
const wss = new WebSocket.Server({
  port: 8080,
  verifyClient: function(info, callback) {
    const origin = info.origin;
    callback(allowedOrigins.includes(origin), 403, "Forbidden");
  }
});`;
      const files = makeFiles({ "src/server.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 1);
      expect(match).toHaveLength(0);
    });
  });

  describe("WebSocket Without Message Rate Limiting (ID 250)", () => {
    it("detects ws.on message handler without rate limiting", () => {
      const code = `
ws.on('message', (data) => {
  db.query('INSERT INTO messages VALUES (?)', [data]);
});`;
      const files = makeFiles({ "src/server.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 197);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].severity).toBe("medium");
      expect(match[0].category).toBe("websocket");
    });

    it("detects socket.on message handler without rate limiting", () => {
      const code = `
socket.on('message', (data) => {
  broadcastToAll(data);
});`;
      const files = makeFiles({ "src/chat.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 197);
      expect(match.length).toBeGreaterThan(0);
    });

    it("does not flag non-WebSocket message handlers", () => {
      const code = `
process.on('message', (msg) => {
  handleWorkerMessage(msg);
});`;
      const files = makeFiles({ "src/worker.ts": code });
      const findings = analyzePatterns(files);
      const match = findings.filter((f) => f.vulnerability_id === 197);
      expect(match).toHaveLength(0);
    });
  });

  // =============================================
  // Project-level middleware suppression
  // =============================================
  describe("project-level middleware suppression", () => {
    it("suppresses rate limiting findings when middleware.ts has rate limiting", () => {
      const apiCode = `
export async function GET(req: Request) {
  const data = await db.query("SELECT * FROM users");
  return Response.json({ data });
}`;
      const middlewareCode = `
import { rateLimit } from "./lib/rate-limiter";
export function middleware(req) {
  return rateLimit(req, { limit: 60, window: "1m" });
}`;
      const files = makeFiles({
        "src/app/api/users/route.ts": apiCode,
        "src/middleware.ts": middlewareCode,
      });
      const findings = analyzePatterns(files);
      const rateLimitFindings = findings.filter((f) => f.vulnerability_id === 96);
      expect(rateLimitFindings).toHaveLength(0);
    });

    it("reports rate limiting findings when no middleware exists", () => {
      const apiCode = `
export async function GET(req: Request) {
  const data = await db.query("SELECT * FROM users");
  return Response.json({ data });
}`;
      const files = makeFiles({ "src/app/api/users/route.ts": apiCode });
      const findings = analyzePatterns(files);
      const rateLimitFindings = findings.filter((f) => f.vulnerability_id === 96);
      expect(rateLimitFindings.length).toBeGreaterThan(0);
    });

    it("suppresses auth rate limiting findings when middleware has rate limiting", () => {
      const authCode = `
// /login route
export async function POST(req: Request) {
  const { email, password } = await req.json();
  return Response.json({ token: "abc" });
}`;
      const middlewareCode = `
export function middleware(req) { return rateLimiter(req); }`;
      const files = makeFiles({
        "src/app/api/auth/login/route.ts": authCode,
        "src/middleware.ts": middlewareCode,
      });
      const findings = analyzePatterns(files);
      const authRateFindings = findings.filter((f) => f.vulnerability_id === 78);
      expect(authRateFindings).toHaveLength(0);
    });
  });

  // =============================================
  // Improved pattern accuracy
  // =============================================
  describe("improved dangerouslySetInnerHTML (safe sources)", () => {
    it("does not flag dangerouslySetInnerHTML with JSON.stringify (JSON-LD)", () => {
      const code = `
<script type="application/ld+json"
  dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
/>`;
      const files = makeFiles({ "src/components/seo.tsx": code });
      const findings = analyzePatterns(files);
      const xss = findings.filter((f) => f.vulnerability_id === 46);
      expect(xss).toHaveLength(0);
    });

    it("does not flag dangerouslySetInnerHTML with codeToHtml (Shiki)", () => {
      const code = `
<div dangerouslySetInnerHTML={{ __html: await codeToHtml(code, { lang }) }} />`;
      const files = makeFiles({ "src/components/code-block.tsx": code });
      const findings = analyzePatterns(files);
      const xss = findings.filter((f) => f.vulnerability_id === 46);
      expect(xss).toHaveLength(0);
    });

    it("still flags dangerouslySetInnerHTML with raw user input", () => {
      const code = `
<div dangerouslySetInnerHTML={{ __html: userContent }} />`;
      const files = makeFiles({ "src/components/preview.tsx": code });
      const findings = analyzePatterns(files);
      const xss = findings.filter((f) => f.vulnerability_id === 46);
      expect(xss.length).toBeGreaterThan(0);
    });
  });

  describe("improved verbose error response", () => {
    it("flags sending err.message in 500 response", () => {
      const code = `
} catch (err) {
  return Response.json({ error: err.message }, { status: 500 });
}`;
      const files = makeFiles({ "src/app/api/test/route.ts": code });
      const findings = analyzePatterns(files);
      const verbose = findings.filter((f) => f.vulnerability_id === 59);
      expect(verbose.length).toBeGreaterThan(0);
    });

    it("does not flag generic error message in 500 response", () => {
      const code = `
} catch (error) {
  console.error("Failed:", error.message);
  return Response.json({ error: "Internal server error" }, { status: 500 });
}`;
      const files = makeFiles({ "src/app/api/test/route.ts": code });
      const findings = analyzePatterns(files);
      const verbose = findings.filter((f) => f.vulnerability_id === 59);
      expect(verbose).toHaveLength(0);
    });
  });

  describe("improved PII detection", () => {
    it("does not flag internal API calls or email services sending email field", () => {
      const code = `
const res = await fetch("/api/tools/capture-email", {
  method: "POST",
  body: JSON.stringify({ email, toolName }),
});`;
      const files = makeFiles({ "src/components/tools.tsx": code });
      const findings = analyzePatterns(files);
      const pii = findings.filter((f) => f.title === "PII Sent to External AI API");
      expect(pii).toHaveLength(0);
    });

    it("flags actual API call sending PII", () => {
      const code = `
const result = await anthropic.messages.create({
  messages: [{ role: "user", content: user.email }]
});`;
      const files = makeFiles({ "src/lib/ai.ts": code });
      const findings = analyzePatterns(files);
      const pii = findings.filter((f) => f.title === "PII Sent to External AI API");
      expect(pii.length).toBeGreaterThan(0);
    });
  });

  describe("confidence field", () => {
    it("includes confidence in findings", () => {
      const code = `const result = eval(userInput);`;
      const files = makeFiles({ "src/utils/run.ts": code });
      const findings = analyzePatterns(files);
      expect(findings[0].confidence).toBeDefined();
    });
  });

  describe("file-level dangerouslySetInnerHTML (Shiki import on different line)", () => {
    it("does not flag when file imports codeToHtml from shiki", () => {
      const code = `
import { codeToHtml } from "shiki";
async function CodeBlock({ code }) {
  const html = await codeToHtml(code, { lang: "js", theme: "one-dark-pro" });
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}`;
      const files = makeFiles({ "src/components/code-block.tsx": code });
      const findings = analyzePatterns(files);
      const xss = findings.filter((f) => f.vulnerability_id === 46);
      expect(xss).toHaveLength(0);
    });

    it("does not flag when file uses MDX compiled content", () => {
      const code = `
import { getPostBySlug } from "@/lib/content";
export default async function BlogPost({ params }) {
  const post = await getPostBySlug(params.slug, "en");
  return <div dangerouslySetInnerHTML={{ __html: post.content }} />;
}`;
      const files = makeFiles({ "src/app/blog/[slug]/page.tsx": code });
      const findings = analyzePatterns(files);
      const xss = findings.filter((f) => f.vulnerability_id === 46);
      expect(xss).toHaveLength(0);
    });
  });

  describe("API Route Without Auth — bearer token", () => {
    it("does not flag cron route with Bearer token auth", () => {
      const code = `
export async function GET(request) {
  const authHeader = request.headers.get("authorization");
  if (authHeader !== \`Bearer \${process.env.CRON_SECRET}\`) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return Response.json({ ok: true });
}`;
      const files = makeFiles({ "src/app/api/cron/cleanup/route.ts": code });
      const findings = analyzePatterns(files);
      const authFindings = findings.filter((f) => f.vulnerability_id === 1 && f.title === "API Route Without Auth Check");
      expect(authFindings).toHaveLength(0);
    });
  });

  describe("ORM Injection — file filter", () => {
    it("does not flag ORM-like patterns in marketing pages", () => {
      const code = `
const example = \`prisma.$queryRaw\\\`SELECT * FROM users WHERE id = \\\${userId}\\\`\`;
return <CodeBlock code={example} />;`;
      const files = makeFiles({ "src/app/marketing/page.tsx": code });
      const findings = analyzePatterns(files);
      const orm = findings.filter((f) => f.vulnerability_id === 103);
      expect(orm).toHaveLength(0);
    });

    it("still flags ORM injection in API routes", () => {
      const code = `
const result = await knex.raw(query + userId);`;
      const files = makeFiles({ "src/app/api/users/route.ts": code });
      const findings = analyzePatterns(files);
      const orm = findings.filter((f) => f.vulnerability_id === 103);
      expect(orm.length).toBeGreaterThan(0);
    });
  });
});
