import { describe, it, expect } from "vitest";
import { detectTechnologies } from "./tech-detector";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

describe("detectTechnologies", () => {
  describe("Node.js / JavaScript ecosystem", () => {
    it("detects nodejs from package.json", () => {
      const files = makeFiles({ "package.json": '{ "name": "my-app" }' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nodejs");
    });

    it("detects nextjs from next dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({
          dependencies: { next: "14.0.0", react: "18.0.0" },
        }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nextjs");
      expect(result.technologies).toContain("react");
      expect(result.technologies).toContain("nodejs");
    });

    it("detects nextjs from next.config.ts", () => {
      const files = makeFiles({
        "package.json": "{}",
        "next.config.ts": "export default { reactStrictMode: true }",
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nextjs");
    });

    it("detects express from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { express: "4.18.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("express");
    });

    it("detects fastify from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { fastify: "4.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("fastify");
    });

    it("detects hono from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { hono: "3.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("hono");
    });

    it("detects koa from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { koa: "2.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("koa");
    });

    it("detects nestjs from @nestjs/core", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { "@nestjs/core": "10.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nestjs");
    });

    it("detects react-native and expo", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({
          dependencies: { "react-native": "0.72.0", expo: "49.0.0" },
        }),
        "app.json": '{ "expo": {} }',
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("react-native");
      expect(result.technologies).toContain("expo");
    });

    it("detects prisma from schema file", () => {
      const files = makeFiles({
        "package.json": "{}",
        "prisma/schema.prisma": "generator client { provider = \"prisma-client-js\" }",
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("prisma");
    });

    it("detects graphql from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { graphql: "16.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("graphql");
    });

    it("detects stripe from dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { stripe: "13.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("stripe");
    });

    it("detects mongodb from mongoose", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { mongoose: "7.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("mongodb");
    });

    it("detects redis from ioredis", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { ioredis: "5.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("redis");
    });

    it("detects devDependencies too", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ devDependencies: { prisma: "5.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("prisma");
    });
  });

  describe("Python ecosystem", () => {
    it("detects python from requirements.txt", () => {
      const files = makeFiles({ "requirements.txt": "flask==2.0.0\nrequests==2.28.0" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("python");
      expect(result.technologies).toContain("flask");
    });

    it("detects django from pyproject.toml", () => {
      const files = makeFiles({
        "pyproject.toml": '[project]\ndependencies = ["django>=4.2"]',
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("python");
      expect(result.technologies).toContain("django");
    });

    it("detects fastapi from requirements.txt", () => {
      const files = makeFiles({ "requirements.txt": "fastapi==0.100.0\nuvicorn" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("fastapi");
    });

    it("does not detect django if requirements.txt has no django", () => {
      const files = makeFiles({ "requirements.txt": "requests==2.28.0" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("python");
      expect(result.technologies).not.toContain("django");
    });
  });

  describe("Go", () => {
    it("detects go from go.mod", () => {
      const files = makeFiles({ "go.mod": "module github.com/user/app\ngo 1.21" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("go");
    });
  });

  describe("Java / Kotlin", () => {
    it("detects java from pom.xml", () => {
      const files = makeFiles({ "pom.xml": "<project><groupId>com.example</groupId></project>" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("java");
    });

    it("detects spring from pom.xml with spring-boot", () => {
      const files = makeFiles({
        "pom.xml": "<dependency>org.springframework.boot:spring-boot-starter</dependency>",
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("java");
      expect(result.technologies).toContain("spring");
    });

    it("detects kotlin from build.gradle.kts", () => {
      const files = makeFiles({
        "build.gradle.kts": 'plugins { kotlin("jvm") version "1.9.0" }',
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("java");
      expect(result.technologies).toContain("kotlin");
    });
  });

  describe("PHP", () => {
    it("detects php from composer.json", () => {
      const files = makeFiles({ "composer.json": '{ "require": {} }' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("php");
    });

    it("detects laravel from composer.json", () => {
      const files = makeFiles({
        "composer.json": '{ "require": { "laravel/framework": "^10.0" } }',
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("laravel");
    });
  });

  describe("Ruby", () => {
    it("detects ruby from Gemfile", () => {
      const files = makeFiles({ "Gemfile": 'source "https://rubygems.org"\ngem "sinatra"' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("ruby");
    });

    it("detects rails from Gemfile", () => {
      const files = makeFiles({ "Gemfile": 'gem "rails", "~> 7.0"' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("rails");
    });
  });

  describe("Dart / Flutter", () => {
    it("detects dart from pubspec.yaml", () => {
      const files = makeFiles({ "pubspec.yaml": "name: my_app\nenvironment:\n  sdk: '>=3.0.0'" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("dart");
    });

    it("detects flutter from pubspec.yaml", () => {
      const files = makeFiles({ "pubspec.yaml": "dependencies:\n  flutter:\n    sdk: flutter" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("dart");
      expect(result.technologies).toContain("flutter");
    });
  });

  describe(".NET", () => {
    it("detects dotnet from .csproj", () => {
      const files = makeFiles({ "MyApp.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\">" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("dotnet");
    });
  });

  describe("Rust", () => {
    it("detects rust from Cargo.toml", () => {
      const files = makeFiles({ "Cargo.toml": '[package]\nname = "my-app"' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("rust");
    });
  });

  describe("Infrastructure", () => {
    it("detects docker from Dockerfile", () => {
      const files = makeFiles({ "Dockerfile": "FROM node:20-slim" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("docker");
    });

    it("detects docker from docker-compose.yml", () => {
      const files = makeFiles({ "docker-compose.yml": "services:\n  web:" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("docker");
    });
  });

  describe("BaaS", () => {
    it("detects firebase from firebase.json", () => {
      const files = makeFiles({ "firebase.json": '{ "hosting": {} }' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("firebase");
    });

    it("detects firebase from npm dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { "firebase-admin": "11.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("firebase");
    });

    it("detects supabase from config.toml", () => {
      const files = makeFiles({ "supabase/config.toml": '[api]\nenabled = true' });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("supabase");
    });

    it("detects supabase from npm dependency", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("supabase");
    });
  });

  describe("complex projects", () => {
    it("detects multiple technologies in a full-stack project", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({
          dependencies: {
            next: "14.0.0",
            react: "18.2.0",
            "@supabase/supabase-js": "2.0.0",
            stripe: "13.0.0",
          },
        }),
        "Dockerfile": "FROM node:20",
        "supabase/config.toml": "[api]",
      });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nodejs");
      expect(result.technologies).toContain("nextjs");
      expect(result.technologies).toContain("react");
      expect(result.technologies).toContain("supabase");
      expect(result.technologies).toContain("stripe");
      expect(result.technologies).toContain("docker");
    });

    it("returns sorted technologies", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({
          dependencies: { stripe: "1.0", react: "18.0", next: "14.0" },
        }),
      });
      const result = detectTechnologies(files);
      const sorted = [...result.technologies].sort();
      expect(result.technologies).toEqual(sorted);
    });

    it("includes detection details", () => {
      const files = makeFiles({
        "package.json": JSON.stringify({ dependencies: { fastify: "4.0.0" } }),
      });
      const result = detectTechnologies(files);
      expect(result.details.get("fastify")).toBe("npm dependency: fastify");
    });
  });

  describe("empty / minimal repos", () => {
    it("returns empty for no files", () => {
      const result = detectTechnologies(new Map());
      expect(result.technologies).toHaveLength(0);
    });

    it("returns empty for non-manifest files only", () => {
      const files = makeFiles({ "README.md": "# Hello", "src/index.ts": "console.log('hi')" });
      const result = detectTechnologies(files);
      expect(result.technologies).toHaveLength(0);
    });

    it("handles malformed package.json gracefully", () => {
      const files = makeFiles({ "package.json": "not valid json {{{" });
      const result = detectTechnologies(files);
      expect(result.technologies).toContain("nodejs");
      // Should not crash, just won't detect npm deps
    });
  });
});
