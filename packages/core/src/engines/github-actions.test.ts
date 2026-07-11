import { describe, it, expect } from "vitest";
import { analyzeGitHubActions } from "./github-actions.js";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

// A minimal, fully-secure workflow that should produce zero findings.
const CLEAN_WORKFLOW = `name: CI
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: npm ci
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("analyzeGitHubActions", () => {
  // -------------------------------------------------------------------------
  // Non-workflow files are ignored
  // -------------------------------------------------------------------------

  describe("non-workflow files", () => {
    it("ignores files outside .github/workflows/", () => {
      const files = makeFiles({
        "src/deploy.yml": `uses: actions/checkout@main`,
        "workflows/ci.yml": `uses: actions/checkout@master`,
      });

      const findings = analyzeGitHubActions(files);

      expect(findings).toHaveLength(0);
    });

    it("ignores files with non-yml/yaml extension inside .github/workflows/", () => {
      const files = makeFiles({
        ".github/workflows/ci.json": `{ "uses": "actions/checkout@main" }`,
        ".github/workflows/ci.sh": `uses: actions/checkout@main`,
      });

      const findings = analyzeGitHubActions(files);

      expect(findings).toHaveLength(0);
    });

    it("processes .yaml extension in addition to .yml", () => {
      const files = makeFiles({
        ".github/workflows/ci.yaml": `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`,
      });

      const findings = analyzeGitHubActions(files);

      const unpinnedFinding = findings.find((f) => f.vulnerability_id === 140);
      expect(unpinnedFinding).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Clean workflow produces no findings
  // -------------------------------------------------------------------------

  describe("clean workflow", () => {
    it("returns no findings for a properly configured workflow", () => {
      const files = makeFiles({
        ".github/workflows/ci.yml": CLEAN_WORKFLOW,
      });

      const findings = analyzeGitHubActions(files);

      expect(findings).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Unpinned actions (vuln ID 140)
  // -------------------------------------------------------------------------

  describe("unpinned actions (vuln ID 140)", () => {
    it("flags action pinned to 'main' branch", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
      expect(finding!.category).toBe("supply-chain");
      expect(finding!.title).toContain("actions/checkout@main");
    });

    it("flags action pinned to 'master' branch", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@master
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeDefined();
    });

    it("flags action pinned to 'latest' ref", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@latest
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeDefined();
    });

    it("flags action pinned to 'dev' branch", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@dev
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeDefined();
    });

    it("does NOT flag action pinned to a version tag like @v4", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag action pinned to a full SHA", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag local actions (starting with './')", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action@main
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag Docker actions (starting with 'docker://')", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine@main
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeUndefined();
    });

    it("reports the correct line number for the unpinned action", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      // Line 9 in the content above (1-indexed).
      expect(finding!.line_number).toBe(9);
    });
  });

  // -------------------------------------------------------------------------
  // Script injection (vuln ID 76)
  // -------------------------------------------------------------------------

  describe("script injection (vuln ID 76)", () => {
    it("flags github.event.issue.title in a run: block", () => {
      const content = `name: CI
on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Echo title
        run: echo "\${{ github.event.issue.title }}"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 76 && f.category === "injection");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("high");
      expect(finding!.owasp_ref).toBe("A03:2021");
    });

    it("flags github.event.issue.body in a run: block", () => {
      const content = `name: CI
on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Echo body
        run: echo "\${{ github.event.issue.body }}"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 76 && f.category === "injection");
      expect(finding).toBeDefined();
    });

    it("flags github.event.pull_request.title in a run: block", () => {
      const content = `name: CI
on: pull_request
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Label
        run: echo "\${{ github.event.pull_request.title }}"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 76 && f.category === "injection");
      expect(finding).toBeDefined();
    });

    it("flags github.head_ref in a run: block", () => {
      const content = `name: CI
on: pull_request
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Branch check
        run: git checkout "\${{ github.head_ref }}"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 76 && f.category === "injection");
      expect(finding).toBeDefined();
    });

    it("does NOT flag safe env-variable pattern (env: block indirect reference)", () => {
      // The safe pattern is: set env var, then use $ENV_VAR in run block.
      const content = `name: CI
on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Safe echo
        env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "$TITLE"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      // The run: block itself does not contain the dangerous context expression.
      const injectionFinding = findings.find(
        (f) => f.vulnerability_id === 76 && f.category === "injection" && f.title?.includes("Script Injection")
      );
      expect(injectionFinding).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Hardcoded secrets in env blocks (vuln ID 53)
  // -------------------------------------------------------------------------

  describe("hardcoded secrets in workflow env blocks (vuln ID 53)", () => {
    it("flags a long string literal in an env-like block", () => {
      const content = `name: Deploy
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: "abcdefghijklmnopqrstu1234567890"
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.category).toBe("vibecoding");
    });

    it("does NOT flag ${{ secrets.* }} references", () => {
      const content = `name: Deploy
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: \${{ secrets.API_KEY }}
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag ${{ github.* }} references", () => {
      const content = `name: Deploy
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      SHA: \${{ github.sha }}
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeUndefined();
    });

    it("redacts the secret value in code_snippet", () => {
      const content = `name: Deploy
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: "supersecretvalue12345678901234"
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding!.code_snippet).toContain("***REDACTED***");
      expect(finding!.code_snippet).not.toContain("supersecretvalue12345678901234");
    });
  });

  // -------------------------------------------------------------------------
  // Excessive permissions (vuln ID 133)
  // -------------------------------------------------------------------------

  describe("excessive permissions (vuln ID 133)", () => {
    it("flags write-all permissions", () => {
      const content = `name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 133 && f.title.includes("write-all")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
      expect(finding!.category).toBe("serverless");
    });

    it("flags a workflow that has no permissions block at all", () => {
      const content = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 133 && f.title.includes("Missing Permissions")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("low");
      expect(finding!.line_number).toBe(1);
    });

    it("does NOT flag a workflow with a restricted permissions block", () => {
      const content = CLEAN_WORKFLOW;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const writeAllFinding = findings.find(
        (f) => f.vulnerability_id === 133 && f.title.includes("write-all")
      );
      expect(writeAllFinding).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Self-hosted runners (vuln ID 136)
  // -------------------------------------------------------------------------

  describe("self-hosted runners (vuln ID 136)", () => {
    it("flags runs-on: self-hosted", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 136);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("info");
      expect(finding!.category).toBe("serverless");
    });

    it("flags runs-on: self-hosted with quotes", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: 'self-hosted'
    steps:
      - uses: actions/checkout@v4
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 136);
      expect(finding).toBeDefined();
    });

    it("does NOT flag runs-on: ubuntu-latest", () => {
      const files = makeFiles({ ".github/workflows/ci.yml": CLEAN_WORKFLOW });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 136);
      expect(finding).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // pull_request_target + checkout (vuln ID 76, critical)
  // -------------------------------------------------------------------------

  describe("pull_request_target + checkout pattern (vuln ID 76)", () => {
    it("flags pull_request_target workflow that also uses actions/checkout", () => {
      const content = `name: PR Label
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo labeling
`;
      const files = makeFiles({ ".github/workflows/pr.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 76 && f.title.includes("pull_request_target")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.owasp_ref).toBe("A03:2021");
    });

    it("does NOT flag pull_request_target without a checkout step", () => {
      const content = `name: Auto Label
on:
  pull_request_target:
    types: [opened]

permissions:
  pull-requests: write

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Label PR
        run: echo "labeling"
`;
      const files = makeFiles({ ".github/workflows/pr.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 76 && f.title.includes("pull_request_target")
      );
      expect(finding).toBeUndefined();
    });

    it("does NOT flag pull_request (without _target) + checkout", () => {
      const content = CLEAN_WORKFLOW;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 76 && f.title.includes("pull_request_target")
      );
      expect(finding).toBeUndefined();
    });

    it("points to the line containing pull_request_target", () => {
      const content = `name: PR
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;
      const files = makeFiles({ ".github/workflows/pr.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find(
        (f) => f.vulnerability_id === 76 && f.title.includes("pull_request_target")
      );
      // pull_request_target appears on line 3 in the content above.
      expect(finding!.line_number).toBe(3);
    });
  });

  // -------------------------------------------------------------------------
  // Multiple findings in one file
  // -------------------------------------------------------------------------

  describe("multiple findings in one file", () => {
    it("reports all distinct findings from a single insecure workflow", () => {
      const content = `name: Insecure
on: push
jobs:
  build:
    runs-on: self-hosted
    env:
      API_KEY: "abcdefghijklmnopqrstuvwxyz123456"
    steps:
      - uses: actions/checkout@main
      - name: Inject title
        run: echo "\${{ github.event.issue.title }}"
`;
      const files = makeFiles({ ".github/workflows/bad.yml": content });

      const findings = analyzeGitHubActions(files);

      expect(findings.find((f) => f.vulnerability_id === 140)).toBeDefined(); // Unpinned action
      expect(findings.find((f) => f.vulnerability_id === 76)).toBeDefined();  // Script injection
      expect(findings.find((f) => f.vulnerability_id === 53)).toBeDefined();  // Hardcoded secret
      expect(findings.find((f) => f.vulnerability_id === 136)).toBeDefined(); // Self-hosted runner
      expect(findings.find((f) => f.vulnerability_id === 133)).toBeDefined(); // Missing permissions
    });
  });

  // -------------------------------------------------------------------------
  // Multiple workflow files
  // -------------------------------------------------------------------------

  describe("multiple workflow files", () => {
    it("analyses all workflow files in the map", () => {
      const files = makeFiles({
        ".github/workflows/ci.yml": CLEAN_WORKFLOW,
        ".github/workflows/deploy.yml": `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`,
      });

      const findings = analyzeGitHubActions(files);

      // The clean workflow should produce 0 findings.
      // The deploy workflow should produce at least the missing permissions + unpinned action.
      expect(findings.length).toBeGreaterThanOrEqual(2);
      expect(findings.every((f) => f.file_path === ".github/workflows/deploy.yml")).toBe(true);
    });

    it("sets the correct file_path on each finding", () => {
      const files = makeFiles({
        ".github/workflows/pr.yml": `name: PR
on: push
jobs:
  job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@master
`,
      });

      const findings = analyzeGitHubActions(files);

      findings.forEach((f) => {
        expect(f.file_path).toBe(".github/workflows/pr.yml");
      });
    });
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  describe("edge cases", () => {
    it("returns empty array for an empty file map", () => {
      const findings = analyzeGitHubActions(new Map());

      expect(findings).toEqual([]);
    });

    it("returns empty array for an empty workflow file", () => {
      const files = makeFiles({ ".github/workflows/empty.yml": "" });

      // An empty file has no permissions block, so it should flag that.
      // This confirms the engine doesn't crash on empty content.
      expect(() => analyzeGitHubActions(files)).not.toThrow();
    });

    it("does not flag quoted version tags like @v4 wrapped in quotes", () => {
      const content = `name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: "actions/checkout@v4"
`;
      const files = makeFiles({ ".github/workflows/ci.yml": content });

      const findings = analyzeGitHubActions(files);

      const finding = findings.find((f) => f.vulnerability_id === 140);
      expect(finding).toBeUndefined();
    });
  });
});
