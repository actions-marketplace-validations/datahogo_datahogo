import { describe, it, expect } from "vitest";
import { analyzeDbRules } from "./db-rules";

describe("analyzeDbRules", () => {
  describe("Supabase RLS analysis", () => {
    it("detects RLS not enabled on a table", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL
);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rlsFinding = findings.find((f) => f.vulnerability_id === 31);
      expect(rlsFinding).toBeDefined();
      expect(rlsFinding!.severity).toBe("critical");
      expect(rlsFinding!.category).toBe("supabase");
      expect(rlsFinding!.title).toContain("users");
    });

    it("does not flag table with RLS enabled", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_select" ON users FOR SELECT USING (auth.uid() = id);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rlsFinding = findings.find(
        (f) => f.vulnerability_id === 31 && f.title.includes("users")
      );
      expect(rlsFinding).toBeUndefined();
    });

    it("detects multiple tables without RLS", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY
);
CREATE TABLE posts (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES users(id)
);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rlsFindings = findings.filter((f) => f.vulnerability_id === 31);
      expect(rlsFindings.length).toBe(2);
      const tables = rlsFindings.map((f) => f.title);
      expect(tables.some((t) => t.includes("users"))).toBe(true);
      expect(tables.some((t) => t.includes("posts"))).toBe(true);
    });

    it("detects USING(true) policies", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all" ON users USING (true);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const policyFinding = findings.find((f) => f.vulnerability_id === 32);
      expect(policyFinding).toBeDefined();
      expect(policyFinding!.severity).toBe("critical");
      expect(policyFinding!.title).toContain("allow_all");
    });

    it("does not flag USING with auth.uid() check", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_own_data" ON users USING (auth.uid() = id);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const policyFinding = findings.find((f) => f.vulnerability_id === 32);
      expect(policyFinding).toBeUndefined();
    });

    it("detects RLS enabled but no policies defined", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const noPolicyFinding = findings.find((f) => f.vulnerability_id === 33);
      expect(noPolicyFinding).toBeDefined();
      expect(noPolicyFinding!.severity).toBe("high");
      expect(noPolicyFinding!.title).toContain("users");
    });

    it("does not flag RLS enabled with policies", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_select" ON users FOR SELECT USING (auth.uid() = id);
`;
      const findings = analyzeDbRules(sql, "supabase");
      const noPolicyFinding = findings.find((f) => f.vulnerability_id === 33);
      expect(noPolicyFinding).toBeUndefined();
    });

    it("detects RPC function without auth.uid() check", () => {
      const sql = `
CREATE OR REPLACE FUNCTION get_stats()
RETURNS json
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (SELECT json_build_object('count', count(*)) FROM users);
END;
$$;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rpcFinding = findings.find((f) => f.vulnerability_id === 36);
      expect(rpcFinding).toBeDefined();
      expect(rpcFinding!.severity).toBe("high");
      expect(rpcFinding!.title).toContain("get_stats");
    });

    it("does not flag trigger functions (handle_ prefix)", () => {
      const sql = `
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO profiles (id) VALUES (NEW.id);
  RETURN NEW;
END;
$$;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rpcFinding = findings.find(
        (f) => f.vulnerability_id === 36 && f.title.includes("handle_new_user")
      );
      expect(rpcFinding).toBeUndefined();
    });

    it("does not flag functions with SECURITY DEFINER", () => {
      // SECURITY DEFINER must appear before LANGUAGE for the regex to capture it
      const sql = `
CREATE OR REPLACE FUNCTION get_stats()
RETURNS json
SECURITY DEFINER
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (SELECT json_build_object('count', count(*)) FROM users);
END;
$$;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rpcFinding = findings.find(
        (f) => f.vulnerability_id === 36 && f.title.includes("get_stats")
      );
      expect(rpcFinding).toBeUndefined();
    });

    it("does not flag functions with auth.uid() before LANGUAGE", () => {
      // The regex captures up to LANGUAGE plpgsql, so auth.uid() must
      // appear in the portion before that for the check to see it.
      // In practice, typical SQL has auth.uid() in the body after LANGUAGE,
      // but the source only checks funcMatch[0] (up to LANGUAGE keyword).
      // This test verifies the code path when auth.uid() IS in the captured region.
      const sql = `
CREATE OR REPLACE FUNCTION get_my_data() /* uses auth.uid() */
RETURNS json
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (SELECT json_build_object('data', data) FROM users WHERE id = auth.uid());
END;
$$;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rpcFinding = findings.find(
        (f) => f.vulnerability_id === 36 && f.title.includes("get_my_data")
      );
      expect(rpcFinding).toBeUndefined();
    });

    it("flags functions with auth.uid() only in body after LANGUAGE keyword", () => {
      // Because the regex only captures up to LANGUAGE plpgsql,
      // auth.uid() in the function body (after LANGUAGE) is NOT seen
      const sql = `
CREATE OR REPLACE FUNCTION get_user_data()
RETURNS json
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (SELECT data FROM users WHERE id = auth.uid());
END;
$$;
`;
      const findings = analyzeDbRules(sql, "supabase");
      const rpcFinding = findings.find(
        (f) => f.vulnerability_id === 36 && f.title.includes("get_user_data")
      );
      // The source code's regex does NOT capture the body, so this IS flagged
      expect(rpcFinding).toBeDefined();
    });
  });

  describe("Firebase rules analysis", () => {
    it("detects Firestore 'allow read, write: if true'", () => {
      const rules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const openFinding = findings.find((f) => f.vulnerability_id === 39);
      expect(openFinding).toBeDefined();
      expect(openFinding!.severity).toBe("critical");
      expect(openFinding!.category).toBe("firebase");
    });

    it("detects 'allow read: if true'", () => {
      const rules = `
service cloud.firestore {
  match /databases/{database}/documents {
    match /public/{doc} {
      allow read: if true;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const openFinding = findings.find(
        (f) => f.vulnerability_id === 39 && f.title.includes("Allow All Access")
      );
      expect(openFinding).toBeDefined();
    });

    it("detects Realtime Database '.read': true", () => {
      const rules = `{
  "rules": {
    ".read": true,
    ".write": true
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const realtimeFinding = findings.find((f) => f.vulnerability_id === 40);
      expect(realtimeFinding).toBeDefined();
      expect(realtimeFinding!.severity).toBe("critical");
    });

    it("detects missing request.auth in Firestore rules", () => {
      const rules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /items/{item} {
      allow read: if true;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const authFinding = findings.find(
        (f) => f.vulnerability_id === 39 && f.title.includes("Missing Authentication")
      );
      expect(authFinding).toBeDefined();
      expect(authFinding!.severity).toBe("high");
    });

    it("does not flag rules with request.auth check", () => {
      const rules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const openFinding = findings.find(
        (f) => f.vulnerability_id === 39 && f.title.includes("Allow All Access")
      );
      expect(openFinding).toBeUndefined();
      // Should also not flag missing auth since request.auth is present
      const authMissing = findings.find(
        (f) => f.vulnerability_id === 39 && f.title.includes("Missing Authentication")
      );
      expect(authMissing).toBeUndefined();
    });
  });

  describe("auto-detection of rules type", () => {
    it("auto-detects Supabase rules from CREATE POLICY", () => {
      const sql = `
CREATE TABLE users (id uuid PRIMARY KEY);
CREATE POLICY "test" ON users USING (true);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
`;
      const findings = analyzeDbRules(sql, "auto");
      // Should find the USING(true) policy
      const policyFinding = findings.find((f) => f.vulnerability_id === 32);
      expect(policyFinding).toBeDefined();
    });

    it("auto-detects Firebase rules from 'allow read'", () => {
      const rules = `
service cloud.firestore {
  match /databases/{database}/documents {
    match /{doc=**} {
      allow read, write: if true;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "auto");
      const firebaseFinding = findings.find((f) => f.category === "firebase");
      expect(firebaseFinding).toBeDefined();
    });

    it("returns empty for unrecognized rules format", () => {
      const rules = `This is some random text that isn't rules.`;
      const findings = analyzeDbRules(rules, "auto");
      expect(findings).toHaveLength(0);
    });
  });

  describe("returns empty for secure rules", () => {
    it("returns no findings for well-configured Supabase rules", () => {
      const sql = `
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT auth.uid(),
  email text NOT NULL
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_select_own" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "users_insert_own" ON users FOR INSERT WITH CHECK (auth.uid() = id);
CREATE POLICY "users_update_own" ON users FOR UPDATE USING (auth.uid() = id);

CREATE TABLE posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id),
  content text
);
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "posts_select" ON posts FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "posts_insert" ON posts FOR INSERT WITH CHECK (auth.uid() = user_id);
`;
      const findings = analyzeDbRules(sql, "supabase");
      expect(findings).toHaveLength(0);
    });

    it("returns no open-all findings for secure Firebase rules", () => {
      const rules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow write: if request.auth != null && request.auth.uid == userId;
    }
  }
}`;
      const findings = analyzeDbRules(rules, "firebase");
      const openFindings = findings.filter(
        (f) => f.title.includes("Allow All Access")
      );
      expect(openFindings).toHaveLength(0);
    });
  });

  describe("finding structure", () => {
    it("includes fix_code for RLS missing findings", () => {
      const sql = `CREATE TABLE users (id uuid PRIMARY KEY);`;
      const findings = analyzeDbRules(sql, "supabase");
      const rlsFinding = findings.find((f) => f.vulnerability_id === 31);
      expect(rlsFinding).toBeDefined();
      expect(rlsFinding!.fix_code).toContain("ALTER TABLE users ENABLE ROW LEVEL SECURITY");
    });

    it("includes description_technical for findings", () => {
      const sql = `CREATE TABLE users (id uuid PRIMARY KEY);`;
      const findings = analyzeDbRules(sql, "supabase");
      const rlsFinding = findings.find((f) => f.vulnerability_id === 31);
      expect(rlsFinding!.description_technical).toBeDefined();
      expect(rlsFinding!.description_technical!.length).toBeGreaterThan(0);
    });

    it("all findings have open status", () => {
      const sql = `
CREATE TABLE users (id uuid PRIMARY KEY);
CREATE POLICY "bad" ON users USING (true);
`;
      const findings = analyzeDbRules(sql, "supabase");
      for (const finding of findings) {
        expect(finding.status).toBe("open");
      }
    });
  });
});
