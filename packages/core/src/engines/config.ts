// Config analyzer engine - checks configuration files for security issues
// Analyzes: Dockerfile, next.config, package.json, .gitignore, etc.

import type { FindingData } from "./types.js";

export function analyzeConfig(
  files: Map<string, string>
): FindingData[] {
  const findings: FindingData[] = [];

  for (const [filePath, content] of files) {
    const fileName = filePath.split("/").pop() || "";

    if (fileName === "Dockerfile" || fileName.endsWith(".dockerfile")) {
      findings.push(...analyzeDockerfile(content, filePath));
    }
    if (fileName === "next.config.js" || fileName === "next.config.ts" || fileName === "next.config.mjs") {
      findings.push(...analyzeNextConfig(content, filePath));
    }
    if (fileName === "package.json" && !filePath.includes("node_modules")) {
      findings.push(...analyzePackageJson(content, filePath));
    }
    if (fileName === ".gitignore") {
      findings.push(...analyzeGitignore(content, filePath, files));
    }
    if (fileName === "docker-compose.yml" || fileName === "docker-compose.yaml") {
      findings.push(...analyzeDockerCompose(content, filePath));
    }
    if (fileName === "tsconfig.json" && !filePath.includes("node_modules")) {
      findings.push(...analyzeTsConfig(content, filePath));
    }
    if (fileName === "vercel.json") {
      findings.push(...analyzeVercelConfig(content, filePath));
    }
  }

  return findings;
}

function analyzeDockerfile(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  // Check for running as root (no USER instruction)
  // Skip if FROM scratch or distroless (no shell, USER is irrelevant)
  const baseImage = lines.find((l) => /^FROM\s+/i.test(l.trim()));
  const isMinimalImage = baseImage && /(?:scratch|distroless|busybox)/i.test(baseImage);
  const hasUserInstruction = lines.some((l) =>
    /^USER\s+/i.test(l.trim())
  );
  if (!hasUserInstruction && !isMinimalImage) {
    findings.push({
      vulnerability_id: 148,
      severity: "medium",
      category: "docker",
      title: "Container Running as Root",
      file_path: filePath,
      code_snippet: "# No USER instruction found in Dockerfile",
      owasp_ref: "A05:2021",
      status: "open",
      confidence: "low",
    });
  }

  // Check for latest tag
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^FROM\s+\S+:latest/i.test(line)) {
      findings.push({
        vulnerability_id: 149,
        severity: "low",
        category: "docker",
        title: "Using :latest Tag in Dockerfile",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line,
        status: "open",
        confidence: "medium",
      });
    }

    // Check for secrets in Dockerfile — skip if value references build arg or env var
    if (/^(?:ENV|ARG)\s+(?:.*(?:PASSWORD|SECRET|KEY|TOKEN|PRIVATE))/i.test(line)) {
      const hasHardcodedValue = /[=]\s*[^$\s{][^\s]+/.test(line);
      findings.push({
        vulnerability_id: 150,
        severity: hasHardcodedValue ? "critical" : "medium",
        category: "docker",
        title: "Secrets in Dockerfile ENV/ARG",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line,
        status: "open",
        confidence: hasHardcodedValue ? "high" : "low",
      });
    }

    // Check for COPY .env — skip .env.example, .env.template, .env.sample
    if (/^COPY\s+.*\.env(?!\.example|\.template|\.sample)/i.test(line)) {
      findings.push({
        vulnerability_id: 150,
        severity: "critical",
        category: "docker",
        title: "Copying .env File into Docker Image",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line,
        status: "open",
        confidence: "high",
      });
    }
  }

  // Check for HEALTHCHECK
  const hasHealthcheck = lines.some((l) =>
    /^HEALTHCHECK/i.test(l.trim())
  );
  if (!hasHealthcheck) {
    findings.push({
      vulnerability_id: 152,
      severity: "low",
      category: "docker",
      title: "No HEALTHCHECK in Dockerfile",
      file_path: filePath,
      code_snippet: "# No HEALTHCHECK instruction found",
      status: "open",
      confidence: "low",
    });
  }

  return findings;
}

function analyzeNextConfig(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for exposed source maps
    if (/productionBrowserSourceMaps\s*:\s*true/i.test(line)) {
      findings.push({
        vulnerability_id: 49,
        severity: "medium",
        category: "react-nextjs",
        title: "Source Maps Exposed in Production",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
        confidence: "high",
      });
    }

    // Check for permissive headers/CORS
    if (/Access-Control-Allow-Origin.*\*/i.test(line)) {
      findings.push({
        vulnerability_id: 50,
        severity: "medium",
        category: "react-nextjs",
        title: "Open CORS in Next.js Config",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
        confidence: "high",
      });
    }
  }

  // Check if poweredByHeader is explicitly disabled
  if (!content.includes("poweredByHeader") || !/poweredByHeader\s*:\s*false/.test(content)) {
    findings.push({
      vulnerability_id: 4,
      severity: "low",
      category: "react-nextjs",
      title: "X-Powered-By Header Not Disabled",
      file_path: filePath,
      code_snippet: "// Missing: poweredByHeader: false in next.config",
      fix_description: "Add poweredByHeader: false to your next.config to prevent disclosing Next.js",
      owasp_ref: "A05:2021",
      status: "open",
      confidence: "medium",
    });
  }

  return findings;
}

function analyzePackageJson(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];

  try {
    const pkg = JSON.parse(content);

    // Check for suspicious install scripts
    if (pkg.scripts) {
      const suspiciousScripts = ["preinstall", "postinstall", "install"];
      for (const script of suspiciousScripts) {
        const value = pkg.scripts[script];
        if (value && (/curl|wget|bash|sh\s+-c|eval|exec/i.test(value))) {
          findings.push({
            vulnerability_id: 139,
            severity: "high",
            category: "supply-chain",
            title: "Suspicious Install Script in package.json",
            file_path: filePath,
            code_snippet: `"${script}": "${value}"`,
            status: "open",
            confidence: "medium",
          });
        }
      }
    }

  } catch {
    // Invalid JSON - not a security issue per se
  }

  return findings;
}

function analyzeGitignore(
  content: string,
  filePath: string,
  allFiles: Map<string, string>
): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n").map((l) => l.trim());

  // Check if .env is ignored
  const hasEnvIgnore = lines.some(
    (l) => l === ".env" || l === ".env*" || l === ".env.local"
  );
  if (!hasEnvIgnore) {
    findings.push({
      vulnerability_id: 168,
      severity: "medium",
      category: "config",
      title: "Inadequate .gitignore - Missing .env",
      file_path: filePath,
      code_snippet: "# .env is not listed in .gitignore",
      status: "open",
      confidence: "high",
    });
  }

  // Check if .env.example exists
  if (!allFiles.has(".env.example")) {
    findings.push({
      vulnerability_id: 165,
      severity: "low",
      category: "config",
      title: "No .env.example File",
      code_snippet: "Project is missing .env.example for documenting required env vars",
      status: "open",
      confidence: "low",
    });
  }

  // Check if lockfile exists
  const hasLockfile =
    allFiles.has("package-lock.json") ||
    allFiles.has("yarn.lock") ||
    allFiles.has("pnpm-lock.yaml");
  if (allFiles.has("package.json") && !hasLockfile) {
    findings.push({
      vulnerability_id: 141,
      severity: "medium",
      category: "supply-chain",
      title: "Missing Lockfile",
      code_snippet: "No package-lock.json, yarn.lock, or pnpm-lock.yaml found",
      status: "open",
      confidence: "high",
    });
  }

  return findings;
}

function analyzeDockerCompose(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Privileged mode
    if (/privileged\s*:\s*true/i.test(line)) {
      findings.push({
        vulnerability_id: 148,
        severity: "critical",
        category: "docker",
        title: "Docker Compose: Privileged Container",
        description_technical: "Container runs in privileged mode, giving it full host access",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
        confidence: "high",
      });
    }

    // Dangerous volume mounts
    if (/volumes:/.test(line)) {
      const nextLines = lines.slice(i + 1, i + 10).join("\n");
      if (/["']?\/?(?:var\/run\/docker\.sock|\/etc|\/root|\/proc|\/sys)/.test(nextLines)) {
        findings.push({
          vulnerability_id: 148,
          severity: "high",
          category: "docker",
          title: "Docker Compose: Sensitive Volume Mount",
          description_technical: "Container mounts a sensitive host path (docker.sock, /etc, /root, /proc, /sys)",
          file_path: filePath,
          line_number: i + 1,
          code_snippet: lines.slice(i, i + 4).join("\n"),
          status: "open",
          confidence: "high",
        });
      }
    }

    // Database without password
    if (/(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*:\s*["']?\s*["']?$/i.test(line)) {
      findings.push({
        vulnerability_id: 101,
        severity: "critical",
        category: "database",
        title: "Docker Compose: Database Without Password",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
        confidence: "high",
      });
    }

    // Default database credentials
    if (/(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*:\s*["']?(?:postgres|root|admin|password|secret|test|123456|changeme)["']?\s*$/i.test(line)) {
      findings.push({
        vulnerability_id: 101,
        severity: "critical",
        category: "database-connection",
        title: "Docker Compose: Default Database Credentials",
        description_technical: "Database uses default/weak credentials. Use strong, unique passwords via secrets management.",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim().replace(/:\s*["']?(.*)["']?/, ": ***REDACTED***"),
        status: "open",
        confidence: "high",
      });
    }

    // Database port exposed to host without restriction
    if (/ports:/.test(line)) {
      const nextLines = lines.slice(i + 1, i + 5).join("\n");
      if (/["']?(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379|9200|9300|5984):/.test(nextLines)) {
        findings.push({
          vulnerability_id: 148,
          severity: "high",
          category: "database-connection",
          title: "Docker Compose: Database Port Exposed to Host",
          description_technical: "Database port is mapped to the host. In production, databases should only be accessible via internal network.",
          file_path: filePath,
          line_number: i + 1,
          code_snippet: lines.slice(i, i + 3).join("\n"),
          status: "open",
          confidence: "medium",
        });
      }
    }

    // Redis without password
    if (/redis/i.test(line) && i > 0) {
      const serviceBlock = lines.slice(Math.max(0, i - 5), i + 15).join("\n");
      if (/image\s*:\s*["']?redis/i.test(serviceBlock) && !/requirepass|--requirepass|REDIS_PASSWORD/i.test(serviceBlock)) {
        if (/command|entrypoint/i.test(line) === false && /image\s*:\s*["']?redis/i.test(line)) {
          findings.push({
            vulnerability_id: 101,
            severity: "high",
            category: "database-connection",
            title: "Docker Compose: Redis Without Password",
            description_technical: "Redis service has no password configured. Use --requirepass or REDIS_PASSWORD.",
            file_path: filePath,
            line_number: i + 1,
            code_snippet: line.trim(),
            status: "open",
            confidence: "medium",
          });
        }
      }
    }

    // network_mode: host
    if (/network_mode\s*:\s*["']?host/i.test(line)) {
      findings.push({
        vulnerability_id: 148,
        severity: "medium",
        category: "docker",
        title: "Docker Compose: Host Network Mode",
        description_technical: "Container uses host networking, bypassing Docker network isolation",
        file_path: filePath,
        line_number: i + 1,
        code_snippet: line.trim(),
        status: "open",
        confidence: "medium",
      });
    }
  }

  return findings;
}

function analyzeTsConfig(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];

  try {
    const config = JSON.parse(content);
    const compilerOptions = config.compilerOptions || {};

    if (compilerOptions.strict === false) {
      findings.push({
        vulnerability_id: 166,
        severity: "low",
        category: "config",
        title: "TypeScript Strict Mode Disabled",
        description_technical: "tsconfig.json has strict: false. Strict mode catches many potential bugs at compile time.",
        file_path: filePath,
        code_snippet: '"strict": false',
        status: "open",
        confidence: "medium",
      });
    }

    if (!compilerOptions.strict && compilerOptions.noImplicitAny === false) {
      findings.push({
        vulnerability_id: 166,
        severity: "low",
        category: "config",
        title: "TypeScript noImplicitAny Disabled",
        description_technical: "noImplicitAny is false, allowing implicit 'any' types which bypass type safety.",
        file_path: filePath,
        code_snippet: '"noImplicitAny": false',
        status: "open",
        confidence: "medium",
      });
    }
  } catch {
    // Invalid JSON - skip
  }

  return findings;
}

function analyzeVercelConfig(content: string, filePath: string): FindingData[] {
  const findings: FindingData[] = [];

  try {
    const config = JSON.parse(content);

    // Check for env vars with secret-looking values
    if (config.env) {
      for (const [key, value] of Object.entries(config.env)) {
        if (
          typeof value === "string" &&
          /(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE)/i.test(key) &&
          value.length > 10 &&
          !value.startsWith("@") // Vercel secret references start with @
        ) {
          findings.push({
            vulnerability_id: 53,
            severity: "critical",
            category: "vibecoding",
            title: `Secret in vercel.json: ${key}`,
            description_technical: "Environment variable with secret-looking value is hardcoded in vercel.json. Use Vercel Environment Variables UI or @secret references instead.",
            file_path: filePath,
            code_snippet: `"${key}": "***REDACTED***"`,
            owasp_ref: "A07:2021",
            status: "open",
            confidence: "high",
          });
        }
      }
    }
  } catch {
    // Invalid JSON - skip
  }

  return findings;
}
