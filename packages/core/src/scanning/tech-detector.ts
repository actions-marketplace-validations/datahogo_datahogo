// Automatic technology detection from repository files.
// Analyzes package manifests, config files, and imports to determine
// which technologies a project uses. This drives which ScanAgents run.

import type { Technology } from "./types.js";

interface DetectionRule {
  tech: Technology;
  /** File path patterns to check for existence. */
  files?: RegExp[];
  /** If a matching file is found, check its content against these patterns. */
  contentPatterns?: RegExp[];
  /** Check package.json dependencies for these package names. */
  npmDeps?: string[];
}

const DETECTION_RULES: DetectionRule[] = [
  // --- JavaScript / TypeScript ecosystem ---
  {
    tech: "nodejs",
    files: [/^package\.json$/],
  },
  {
    tech: "nextjs",
    npmDeps: ["next"],
    files: [/^next\.config\.[tjm]s$/],
  },
  {
    tech: "react",
    npmDeps: ["react", "react-dom"],
  },
  {
    tech: "express",
    npmDeps: ["express"],
  },
  {
    tech: "fastify",
    npmDeps: ["fastify"],
  },
  {
    tech: "hono",
    npmDeps: ["hono"],
  },
  {
    tech: "koa",
    npmDeps: ["koa"],
  },
  {
    tech: "nestjs",
    npmDeps: ["@nestjs/core"],
  },
  {
    tech: "react-native",
    npmDeps: ["react-native"],
    files: [/^app\.json$/],
  },
  {
    tech: "expo",
    npmDeps: ["expo"],
    files: [/^app\.json$/, /^app\.config\.[tj]s$/],
  },
  {
    tech: "prisma",
    npmDeps: ["prisma", "@prisma/client"],
    files: [/prisma\/schema\.prisma$/],
  },
  {
    tech: "graphql",
    npmDeps: ["graphql", "apollo-server", "@apollo/server", "type-graphql"],
  },
  {
    tech: "stripe",
    npmDeps: ["stripe"],
  },
  {
    tech: "mongodb",
    npmDeps: ["mongodb", "mongoose"],
  },
  {
    tech: "redis",
    npmDeps: ["redis", "ioredis"],
  },

  {
    tech: "vue",
    npmDeps: ["vue"],
  },
  {
    tech: "angular",
    npmDeps: ["@angular/core"],
  },
  {
    tech: "svelte",
    npmDeps: ["svelte"],
  },

  // --- Python ecosystem ---
  {
    tech: "python",
    files: [/^requirements\.txt$/, /^pyproject\.toml$/, /^setup\.py$/, /^Pipfile$/],
  },
  {
    tech: "django",
    files: [/^requirements\.txt$/, /^pyproject\.toml$/],
    contentPatterns: [/django/i],
  },
  {
    tech: "flask",
    files: [/^requirements\.txt$/, /^pyproject\.toml$/],
    contentPatterns: [/flask/i],
  },
  {
    tech: "fastapi",
    files: [/^requirements\.txt$/, /^pyproject\.toml$/],
    contentPatterns: [/fastapi/i],
  },

  // --- Go ---
  {
    tech: "go",
    files: [/^go\.mod$/],
  },

  // --- Java / Kotlin ---
  {
    tech: "java",
    files: [/^pom\.xml$/, /^build\.gradle(?:\.kts)?$/],
  },
  {
    tech: "spring",
    files: [/^pom\.xml$/, /^build\.gradle(?:\.kts)?$/],
    contentPatterns: [/spring-boot|springframework/i],
  },
  {
    tech: "kotlin",
    files: [/^build\.gradle\.kts$/],
    contentPatterns: [/kotlin/i],
  },

  // --- PHP ---
  {
    tech: "php",
    files: [/^composer\.json$/],
  },
  {
    tech: "laravel",
    files: [/^composer\.json$/],
    contentPatterns: [/laravel/i],
  },

  // --- Ruby ---
  {
    tech: "ruby",
    files: [/^Gemfile$/],
  },
  {
    tech: "rails",
    files: [/^Gemfile$/],
    contentPatterns: [/rails/i],
  },

  // --- Dart / Flutter ---
  {
    tech: "dart",
    files: [/^pubspec\.yaml$/],
  },
  {
    tech: "flutter",
    files: [/^pubspec\.yaml$/],
    contentPatterns: [/flutter/i],
  },

  // --- .NET ---
  {
    tech: "dotnet",
    files: [/\.csproj$/, /\.fsproj$/, /\.sln$/],
  },

  // --- Rust ---
  {
    tech: "rust",
    files: [/^Cargo\.toml$/],
  },

  // --- Infrastructure ---
  {
    tech: "docker",
    files: [/^Dockerfile$/, /^docker-compose\.ya?ml$/],
  },

  // --- BaaS ---
  {
    tech: "firebase",
    files: [/^firebase\.json$/, /^\.firebaserc$/, /^firestore\.rules$/],
    npmDeps: ["firebase", "firebase-admin"],
  },
  {
    tech: "supabase",
    files: [/^supabase\/config\.toml$/],
    npmDeps: ["@supabase/supabase-js"],
  },
];

export interface TechDetectionResult {
  technologies: Technology[];
  /** Raw details: which rule matched and how. */
  details: Map<Technology, string>;
}

/**
 * Detect technologies used in a repository by analyzing file names and content.
 * Works with the existing Map<string, string> file representation.
 */
export function detectTechnologies(files: Map<string, string>): TechDetectionResult {
  const detected = new Set<Technology>();
  const details = new Map<Technology, string>();
  const filePaths = [...files.keys()];

  // Parse package.json deps once (used by many rules)
  const allNpmDeps = extractNpmDeps(files);

  for (const rule of DETECTION_RULES) {
    if (detected.has(rule.tech)) continue;

    // Check npm dependencies
    if (rule.npmDeps) {
      const matchedDep = rule.npmDeps.find((dep) => allNpmDeps.has(dep));
      if (matchedDep) {
        detected.add(rule.tech);
        details.set(rule.tech, `npm dependency: ${matchedDep}`);
        continue;
      }
    }

    // Check file existence + optional content patterns
    if (rule.files) {
      for (const filePattern of rule.files) {
        const matchingFile = filePaths.find((fp) => filePattern.test(fp));
        if (!matchingFile) continue;

        if (!rule.contentPatterns) {
          // File existence alone is enough
          detected.add(rule.tech);
          details.set(rule.tech, `file: ${matchingFile}`);
          break;
        }

        // Check file content
        const content = files.get(matchingFile);
        if (!content) continue;

        const matchedPattern = rule.contentPatterns.find((p) => p.test(content));
        if (matchedPattern) {
          detected.add(rule.tech);
          details.set(rule.tech, `file: ${matchingFile} (content match)`);
          break;
        }
      }
    }
  }

  return {
    technologies: [...detected].sort(),
    details,
  };
}

/** Extract all dependency names from package.json (deps + devDeps). */
function extractNpmDeps(files: Map<string, string>): Set<string> {
  const deps = new Set<string>();
  const packageJson = files.get("package.json");
  if (!packageJson) return deps;

  try {
    const pkg = JSON.parse(packageJson);
    for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
      if (pkg[key] && typeof pkg[key] === "object") {
        for (const name of Object.keys(pkg[key])) {
          deps.add(name);
        }
      }
    }
  } catch {
    // Malformed package.json — skip
  }

  return deps;
}
