import { describe, it, expect } from "vitest";
import { SupabaseScanAgent } from "./supabase-agent.js";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

const agent = new SupabaseScanAgent();

// ---------------------------------------------------------------------------
// getMetadata
// ---------------------------------------------------------------------------

describe("SupabaseScanAgent", () => {
  describe("getMetadata()", () => {
    it("returns correct name, version, and technologies", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("supabase-agent");
      expect(meta.version).toBe("1.0.0");
      expect(meta.technologies).toEqual(["supabase"]);
    });
  });

  // ---------------------------------------------------------------------------
  // detect()
  // ---------------------------------------------------------------------------

  describe("detect()", () => {
    it("returns true when supabase/config.toml is present", async () => {
      const files = makeFiles({ "supabase/config.toml": "[auth]\nsite_url = \"http://localhost:3000\"" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns true when package.json contains @supabase/supabase-js", async () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2.0.0" } }),
      });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns false when no supabase indicators exist", async () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { "express": "^4.0.0" } }),
        "src/index.ts": "console.log('hello')",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for an empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Check 1: Admin API in client code
  // ---------------------------------------------------------------------------

  describe("scan() — Check 1: admin API in client code", () => {
    it("detects supabase.auth.admin call in a 'use client' file", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "components/AdminPanel.tsx": `
"use client";
import { supabase } from "@/lib/supabase";

export function AdminPanel() {
  const users = supabase.auth.admin.listUsers();
  return <div />;
}
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase admin API used in client-side code");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-306");
    });

    it("detects auth.admin. call in a .tsx file inside components/", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "components/user-list.tsx": `
import { supabase } from "@/lib/supabase";

const list = await supabase.auth.admin.deleteUser(id);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase admin API used in client-side code");
      expect(finding).toBeDefined();
    });

    it("does not flag admin API in a server-side route file", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "app/api/admin/route.ts": `
import { supabase } from "@/lib/supabase-server";

export async function DELETE(req: Request) {
  const users = await supabase.auth.admin.listUsers();
  return Response.json(users);
}
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase admin API used in client-side code");
      expect(finding).toBeUndefined();
    });

    it("does not flag admin API in a lib/ server utility", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/admin.ts": `
import { supabase } from "./supabase-server";

export async function deleteUser(id: string) {
  return supabase.auth.admin.deleteUser(id);
}
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase admin API used in client-side code");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 2: DISABLE ROW LEVEL SECURITY
  // ---------------------------------------------------------------------------

  describe("scan() — Check 2: DISABLE ROW LEVEL SECURITY", () => {
    it("detects ALTER TABLE ... DISABLE ROW LEVEL SECURITY in a .sql file", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/001_setup.sql": `
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Row Level Security disabled on table");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-284");
    });

    it("detects case-insensitive DISABLE RLS statement", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/002_disable.sql": `
alter table profiles disable row level security;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Row Level Security disabled on table");
      expect(finding).toBeDefined();
    });

    it("does not flag ENABLE ROW LEVEL SECURITY statements", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/003_enable.sql": `
CREATE TABLE orders (id uuid PRIMARY KEY);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Row Level Security disabled on table");
      expect(finding).toBeUndefined();
    });

    it("does not flag non-SQL files", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "README.md": "ALTER TABLE users DISABLE ROW LEVEL SECURITY;",
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Row Level Security disabled on table");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 3: CREATE TABLE without RLS
  // ---------------------------------------------------------------------------

  describe("scan() — Check 3: CREATE TABLE without RLS", () => {
    it("flags a .sql file that has CREATE TABLE but lacks ENABLE ROW LEVEL SECURITY", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/001_create.sql": `
CREATE TABLE products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Table created without enabling Row Level Security");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-284");
    });

    it("does not flag a migration that enables RLS for the created table", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/002_safe.sql": `
CREATE TABLE products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL
);
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Table created without enabling Row Level Security");
      expect(finding).toBeUndefined();
    });

    it("does not flag .sql files without CREATE TABLE", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/003_index.sql": `
CREATE INDEX idx_users_email ON users (email);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Table created without enabling Row Level Security");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 4: Overly permissive RLS policy
  // ---------------------------------------------------------------------------

  describe("scan() — Check 4: overly permissive RLS policy", () => {
    it("detects CREATE POLICY with USING (true)", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/001_policy.sql": `
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow all" ON messages FOR SELECT USING (true);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Overly permissive RLS policy uses USING(true)");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-284");
    });

    it("detects USING(true) without spaces", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/002_policy.sql": `
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open" ON messages USING(true);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Overly permissive RLS policy uses USING(true)");
      expect(finding).toBeDefined();
    });

    it("does not flag policies that use auth.uid()", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/003_policy.sql": `
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
CREATE POLICY "user_only" ON messages FOR SELECT USING (auth.uid() = user_id);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Overly permissive RLS policy uses USING(true)");
      expect(finding).toBeUndefined();
    });

    it("does not flag policies that mention 'public' in the policy name", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/004_policy.sql": `
ALTER TABLE avatars ENABLE ROW LEVEL SECURITY;
CREATE POLICY "public read" ON avatars FOR SELECT USING (true);
`,
      });
      const results = await agent.scan(files);
      // Policy name contains "public" — should not be flagged
      const finding = results.find((r) => r.title === "Overly permissive RLS policy uses USING(true)");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 5: SECURITY DEFINER without auth check
  // ---------------------------------------------------------------------------

  describe("scan() — Check 5: SECURITY DEFINER without auth check", () => {
    it("detects a SECURITY DEFINER function without auth.uid()", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/001_fn.sql": `
CREATE OR REPLACE FUNCTION delete_all_data()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM orders;
END;
$$;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "SECURITY DEFINER function without authentication check");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-306");
    });

    it("detects SECURITY DEFINER without auth.jwt()", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/002_fn.sql": `
CREATE FUNCTION admin_action() RETURNS void
LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "SECURITY DEFINER function without authentication check");
      expect(finding).toBeDefined();
    });

    it("does not flag SECURITY DEFINER functions that check auth.uid()", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/003_fn.sql": `
CREATE OR REPLACE FUNCTION safe_delete()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  DELETE FROM orders WHERE user_id = auth.uid();
END;
$$;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "SECURITY DEFINER function without authentication check");
      expect(finding).toBeUndefined();
    });

    it("does not flag SECURITY DEFINER functions that use auth.jwt()", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/004_fn.sql": `
CREATE FUNCTION jwt_check() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE claims json;
BEGIN
  claims := auth.jwt();
  IF claims IS NULL THEN RAISE EXCEPTION 'No JWT'; END IF;
END;
$$;
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "SECURITY DEFINER function without authentication check");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 6: Signup without email confirmation
  // ---------------------------------------------------------------------------

  describe("scan() — Check 6: signup without email confirmation", () => {
    it("flags config.toml with enable_signup=true and no enable_confirmations", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
site_url = "http://localhost:3000"
enable_signup = true
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase signup enabled without email confirmation");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-287");
    });

    it("flags config.toml with enable_confirmations = false explicitly", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
enable_signup = true
enable_confirmations = false
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase signup enabled without email confirmation");
      expect(finding).toBeDefined();
    });

    it("does not flag when enable_confirmations = true is set", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
enable_signup = true
enable_confirmations = true
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase signup enabled without email confirmation");
      expect(finding).toBeUndefined();
    });

    it("does not flag when enable_signup is not present", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
site_url = "http://localhost:3000"
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Supabase signup enabled without email confirmation");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 7: Service role key in client
  // ---------------------------------------------------------------------------

  describe("scan() — Check 7: service role key in client", () => {
    it("detects NEXT_PUBLIC_SUPABASE_SERVICE_ROLE env variable reference", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        ".env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Service role key exposed via public environment variable");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-798");
    });

    it("detects VITE_SUPABASE_SERVICE_ROLE env variable reference", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "src/config.ts": 'const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE;',
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Service role key exposed via public environment variable");
      expect(finding).toBeDefined();
    });

    it("detects serviceRoleKey in a 'use client' file", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "components/DataTable.tsx": `
"use client";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(url, process.env.serviceRoleKey!);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Service role key referenced in client-side code");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
    });

    it("does not flag service_role in a server-only API route", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "app/api/admin/route.ts": `
import { createClient } from "@supabase/supabase-js";

// Server-only: service role is safe here
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);
`,
      });
      const results = await agent.scan(files);
      const serviceRoleFindings = results.filter(
        (r) =>
          r.title === "Service role key referenced in client-side code" ||
          r.title === "Service role key exposed via public environment variable",
      );
      expect(serviceRoleFindings).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Check 8: Public storage bucket
  // ---------------------------------------------------------------------------

  describe("scan() — Check 8: public storage bucket", () => {
    it("detects storage.objects SELECT policy with USING (true)", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/001_storage.sql": `
CREATE POLICY "public read"
ON storage.objects FOR SELECT
USING (true);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Public storage bucket allows unrestricted SELECT");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-284");
    });

    it("detects inline storage.objects USING(true) policy", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/002_storage.sql": `
CREATE POLICY "open" ON storage.objects FOR SELECT USING(true);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Public storage bucket allows unrestricted SELECT");
      expect(finding).toBeDefined();
    });

    it("does not flag storage policies that require auth", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/003_storage.sql": `
CREATE POLICY "auth read"
ON storage.objects FOR SELECT
USING (auth.uid() = owner);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Public storage bucket allows unrestricted SELECT");
      expect(finding).toBeUndefined();
    });

    it("does not flag INSERT or UPDATE storage policies with USING(true)", async () => {
      // USING(true) only applies to SELECT in this check
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/migrations/004_storage.sql": `
CREATE POLICY "allow upload"
ON storage.objects FOR INSERT
WITH CHECK (auth.uid() IS NOT NULL);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Public storage bucket allows unrestricted SELECT");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 9: Unfiltered select
  // ---------------------------------------------------------------------------

  describe("scan() — Check 9: unfiltered SELECT query", () => {
    it("detects .from().select('*') without a filter", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/data.ts": `
import { supabase } from "./supabase";

export async function getAllOrders() {
  const { data } = await supabase.from('orders').select('*');
  return data;
}
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Unfiltered Supabase SELECT query without row filter");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("MEDIUM");
      expect(finding!.cwe).toBe("CWE-200");
    });

    it("detects .select() without column list and without filter", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/data.ts": `
const { data } = await supabase.from('messages').select();
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Unfiltered Supabase SELECT query without row filter");
      expect(finding).toBeDefined();
    });

    it("does not flag queries that include .eq() filter", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/data.ts": `
const { data } = await supabase.from('orders').select('*').eq('user_id', userId);
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Unfiltered Supabase SELECT query without row filter");
      expect(finding).toBeUndefined();
    });

    it("does not flag queries that include .match() filter", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/data.ts": `
const { data } = await supabase.from('orders').select('*').match({ user_id: userId });
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Unfiltered Supabase SELECT query without row filter");
      expect(finding).toBeUndefined();
    });

    it("does not flag test files", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "lib/data.test.ts": `
const { data } = await supabase.from('orders').select('*');
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Unfiltered Supabase SELECT query without row filter");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Check 10: Edge Function without JWT verification
  // ---------------------------------------------------------------------------

  describe("scan() — Check 10: Edge Function without JWT verification", () => {
    it("flags an Edge Function that never reads the Authorization header", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/functions/send-email/index.ts": `
import { serve } from "https://deno.land/std/http/server.ts";

serve(async (req) => {
  const body = await req.json();
  await sendEmail(body.to, body.subject);
  return new Response(JSON.stringify({ ok: true }));
});
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Edge Function does not verify JWT authorization");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-306");
    });

    it("flags a nested Edge Function path without auth check", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "project/supabase/functions/process-webhook/index.ts": `
serve(async (req) => {
  const payload = await req.json();
  processPayload(payload);
  return new Response("ok");
});
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Edge Function does not verify JWT authorization");
      expect(finding).toBeDefined();
    });

    it("does not flag an Edge Function that reads the Authorization header", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/functions/protected/index.ts": `
import { serve } from "https://deno.land/std/http/server.ts";
import { createClient } from "@supabase/supabase-js";

serve(async (req) => {
  const authHeader = req.headers.get('Authorization');
  if (!authHeader) return new Response("Unauthorized", { status: 401 });

  const supabase = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const { data: { user } } = await supabase.auth.getUser();
  return Response.json({ user });
});
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Edge Function does not verify JWT authorization");
      expect(finding).toBeUndefined();
    });

    it("does not flag an Edge Function that calls supabase.auth.getUser", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "supabase/functions/me/index.ts": `
serve(async (req) => {
  const { data: { user } } = await supabase.auth.getUser(token);
  if (!user) return new Response("Unauthorized", { status: 401 });
  return Response.json(user);
});
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Edge Function does not verify JWT authorization");
      expect(finding).toBeUndefined();
    });

    it("does not flag regular TypeScript files outside supabase/functions/", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "@supabase/supabase-js": "^2" } }',
        "src/server/handler.ts": `
export async function handleRequest(req: Request) {
  const body = await req.json();
  return body;
}
`,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Edge Function does not verify JWT authorization");
      expect(finding).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Clean project — zero findings
  // ---------------------------------------------------------------------------

  describe("scan() — clean project returns zero relevant findings", () => {
    it("a well-configured Supabase project produces no security findings", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
site_url = "https://myapp.com"
enable_signup = true
enable_confirmations = true
`,
        "supabase/migrations/001_schema.sql": `
CREATE TABLE orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  total numeric NOT NULL
);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_orders"
  ON orders FOR SELECT
  USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION user_order_count()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE cnt integer;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  SELECT COUNT(*) INTO cnt FROM orders WHERE user_id = auth.uid();
  RETURN cnt;
END;
$$;
`,
        "supabase/functions/orders/index.ts": `
import { serve } from "https://deno.land/std/http/server.ts";

serve(async (req) => {
  const authHeader = req.headers.get('Authorization');
  if (!authHeader) return new Response("Unauthorized", { status: 401 });
  return Response.json({ ok: true });
});
`,
        "app/api/orders/route.ts": `
import { createClient } from "@supabase/supabase-js";

// Server-side only — service role is safe here
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET() {
  const { data } = await supabase.from('orders').select('*').eq('user_id', userId);
  return Response.json(data);
}
`,
        "package.json": JSON.stringify({
          dependencies: { "@supabase/supabase-js": "^2.39.0" },
        }),
      });

      const results = await agent.scan(files);
      expect(results).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // getChecks
  // ---------------------------------------------------------------------------

  describe("getChecks()", () => {
    const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

    it("returns non-empty array of check definitions", () => {
      const checks = agent.getChecks();
      expect(checks.length).toBeGreaterThan(0);
    });

    it("every check has required fields", () => {
      const checks = agent.getChecks();
      for (const check of checks) {
        expect(check.id).toBeTruthy();
        expect(check.name).toBeTruthy();
        expect(VALID_SEVERITIES.has(check.severity)).toBe(true);
      }
    });

    it("check IDs are unique", () => {
      const checks = agent.getChecks();
      const ids = checks.map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("check IDs follow supabase: prefix convention", () => {
      const checks = agent.getChecks();
      for (const check of checks) {
        expect(check.id).toMatch(/^supabase:/);
      }
    });

    it("scan findings have checkIds matching declared checks", async () => {
      // Use existing fixture files that are known to trigger findings across
      // several checks: admin API in client, disable RLS, permissive policy,
      // service role key in client, and signup without confirmation.
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
enable_signup = true
`,
        "supabase/migrations/001_bad.sql": `
CREATE TABLE secrets (id uuid PRIMARY KEY, value text);

CREATE POLICY "open" ON secrets USING (true);
ALTER TABLE secrets DISABLE ROW LEVEL SECURITY;
`,
        "components/Admin.tsx": `
"use client";
const result = supabase.auth.admin.listUsers();
`,
        "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }),
      });

      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      const declaredIds = new Set(agent.getChecks().map((c) => c.id));
      for (const result of results) {
        expect(result.checkId).toBeTruthy();
        expect(declaredIds.has(result.checkId as string)).toBe(true);
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Result structure
  // ---------------------------------------------------------------------------

  describe("scan() — result structure", () => {
    it("every finding has required fields with valid values", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
enable_signup = true
`,
        "supabase/migrations/001_bad.sql": `
CREATE TABLE secrets (id uuid PRIMARY KEY, value text);

CREATE POLICY "open" ON secrets USING (true);
ALTER TABLE secrets DISABLE ROW LEVEL SECURITY;
`,
        "components/Admin.tsx": `
"use client";
const result = supabase.auth.admin.listUsers();
`,
        "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }),
      });

      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      for (const result of results) {
        expect(result.title).toBeTruthy();
        expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(result.severity);
        expect(result.file).toBeTruthy();
        expect(result.line).toBeGreaterThan(0);
        expect(result.description).toBeTruthy();
        expect(result.fix).toBeTruthy();
      }
    });

    it("all findings with CWE refs match the CWE-NNN format", async () => {
      const files = makeFiles({
        "supabase/config.toml": `
[auth]
enable_signup = true
`,
        "supabase/migrations/001_bad.sql": `
CREATE TABLE secrets (id uuid PRIMARY KEY, value text);
CREATE POLICY "open" ON secrets USING (true);
`,
        "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "^2" } }),
      });

      const results = await agent.scan(files);
      const withCwe = results.filter((r) => r.cwe);
      expect(withCwe.length).toBeGreaterThan(0);
      for (const r of withCwe) {
        expect(r.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });
});
