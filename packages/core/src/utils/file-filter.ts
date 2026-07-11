const SCANNABLE_EXTENSIONS = [
  // JavaScript / TypeScript
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  // Languages covered by the multi-tech scan agents
  ".py", ".go", ".java", ".kt", ".kts", ".php", ".cs", ".fs",
  ".rb", ".rs", ".dart",
  // Config / data formats (includes pyproject.toml, Cargo.toml, etc.)
  ".json", ".yaml", ".yml", ".toml", ".gradle", ".sql", ".rules",
  ".csproj", ".fsproj", ".sln",
  ".env", ".env.local", ".env.production",
];

const SCANNABLE_EXACT_FILES = [
  ".gitignore", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
  ".dockerignore", "Makefile", ".npmrc", ".yarnrc",
  "vercel.json", "netlify.toml", "tsconfig.json",
  ".eslintrc.json", ".eslintrc.js", ".prettierrc",
  "next.config.js", "next.config.ts", "next.config.mjs",
  "firebase.json", "firestore.rules", "storage.rules",
  "supabase/config.toml",
  ".env.example",
  // Manifests the TechDetector relies on for non-JS stacks
  "requirements.txt", "Pipfile", "go.mod", "go.sum",
  "pom.xml", "Gemfile", "Gemfile.lock",
];

const SKIP_DIRECTORIES = [
  "node_modules", ".next", ".git", "dist", "build", ".cache",
  "coverage", ".nyc_output", "__pycache__", ".venv",
];

const MAX_FILE_SIZE = 500_000; // 500KB - skip very large files

export function isRelevantFile(filePath: string): boolean {
  // Skip hidden/build directories (allow .github for workflow scanning)
  const parts = filePath.split("/");
  for (const part of parts.slice(0, -1)) {
    if (part === ".github") continue; // Allow .github/workflows/
    if (SKIP_DIRECTORIES.includes(part)) return false;
    if (part.startsWith(".") && part !== ".") return false; // Skip other hidden dirs
  }

  const fileName = parts[parts.length - 1];

  // Check exact file matches
  if (SCANNABLE_EXACT_FILES.includes(fileName)) return true;

  // Check extensions
  return SCANNABLE_EXTENSIONS.some(ext => fileName.endsWith(ext));
}

export function filterFiles(files: Map<string, string>): Map<string, string> {
  const filtered = new Map<string, string>();
  for (const [path, content] of files) {
    if (isRelevantFile(path) && content.length <= MAX_FILE_SIZE) {
      filtered.set(path, content);
    }
  }
  return filtered;
}

export function getFileLanguage(filePath: string): string {
  const ext = filePath.split(".").pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    ts: "typescript", tsx: "typescript",
    js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
    json: "json", yaml: "yaml", yml: "yaml",
    sql: "sql", rules: "text",
    env: "dotenv",
  };
  return langMap[ext || ""] || "text";
}
