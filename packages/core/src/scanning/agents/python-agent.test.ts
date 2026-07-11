import { describe, it, expect } from "vitest";
import { PythonScanAgent } from "./python-agent";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

// --- Fixture: Django project ---
const DJANGO_SETTINGS = `
import os

SECRET_KEY = 'super-secret-key-that-should-not-be-here'
DEBUG = True
ALLOWED_HOSTS = ['*']
CORS_ALLOW_ALL_ORIGINS = True

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'corsheaders',
]
`;

const DJANGO_REQUIREMENTS = `Django==4.2.10
djangorestframework==3.14.0
requests==2.30.0
psycopg2-binary==2.9.9
`;

// --- Fixture: FastAPI project ---
const FASTAPI_MAIN = `
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/users")
async def get_users():
    return db.get_all_users()

@app.post("/admin/delete")
async def delete_user(user_id: str):
    return db.delete(user_id)

@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"user": user}
`;

const FASTAPI_REQUIREMENTS = `fastapi==0.100.0
uvicorn==0.23.0
sqlalchemy==2.0.0
`;

// --- Fixture: Flask project ---
const FLASK_APP = `
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/health')
def health():
    return jsonify(status='ok')

@app.route('/users')
def get_users():
    return jsonify(users=db.get_all())

@app.route('/admin/settings', methods=['POST'])
def update_settings():
    return jsonify(ok=True)
`;

const FLASK_REQUIREMENTS = `flask==2.3.2
requests==2.28.0
gunicorn==21.2.0
`;

// --- Fixture: SQL injection examples ---
const SQL_INJECTION_CODE = `
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def search_users(name):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    return cursor.fetchall()

def safe_query(user_id):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
`;

const DJANGO_RAW_QUERY = `
from myapp.models import User

def get_user(user_id):
    return User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")

def search(name):
    return User.objects.raw("SELECT * FROM auth_user WHERE name = '{}'".format(name))

def safe_raw(user_id):
    return User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
`;

const SQL_CONCAT = `
import psycopg2

def find_user(name):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchone()
`;

// --- Fixture: .env file with secrets ---
const DOT_ENV = `
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
SECRET_KEY=my-super-secret-key-123456
API_TOKEN=sk-1234567890abcdef
DEBUG=true
`;

const DOT_ENV_EXAMPLE = `
DATABASE_URL=
SECRET_KEY=
API_TOKEN=
DEBUG=false
`;

// --- Fixture: Pickle usage ---
const PICKLE_CODE = `
import pickle
import json

def load_user_data(data):
    return pickle.loads(data)

def load_cache(file_path):
    with open(file_path, 'rb') as f:
        return pickle.load(f)

def safe_load(data):
    return json.loads(data)
`;

// --- Fixture: Clean project (no vulnerabilities) ---
const CLEAN_DJANGO_SETTINGS = `
import os

SECRET_KEY = os.environ['SECRET_KEY']
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
CORS_ALLOWED_ORIGINS = [
    'https://myapp.com',
]
`;

const agent = new PythonScanAgent();

describe("PythonScanAgent", () => {
  describe("getMetadata", () => {
    it("returns correct metadata", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("python-agent");
      expect(meta.version).toBe("1.0.0");
      expect(meta.technologies).toEqual(["python", "django", "flask", "fastapi"]);
    });
  });

  describe("detect()", () => {
    it("detects requirements.txt", async () => {
      const files = makeFiles({ "requirements.txt": "flask==2.0.0" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects Pipfile", async () => {
      const files = makeFiles({ "Pipfile": "[packages]\nflask = \"*\"" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects pyproject.toml", async () => {
      const files = makeFiles({ "pyproject.toml": "[project]\nname = \"myapp\"" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects setup.py", async () => {
      const files = makeFiles({ "setup.py": "from setuptools import setup" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects nested requirements.txt", async () => {
      const files = makeFiles({ "backend/requirements.txt": "django==4.2" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns false for non-Python projects", async () => {
      const files = makeFiles({
        "package.json": '{ "dependencies": { "next": "14.0" } }',
        "src/index.ts": "console.log('hello')",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });
  });

  describe("scan() — Django misconfigurations", () => {
    it("detects DEBUG=True", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
      });
      const results = await agent.scan(files);
      const debugResult = results.find((r) => r.title === "Django DEBUG mode enabled");
      expect(debugResult).toBeDefined();
      expect(debugResult!.severity).toBe("HIGH");
      expect(debugResult!.cwe).toBe("CWE-215");
    });

    it("detects hardcoded SECRET_KEY", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
      });
      const results = await agent.scan(files);
      const secretResult = results.find((r) => r.title === "Django SECRET_KEY hardcoded in source");
      expect(secretResult).toBeDefined();
      expect(secretResult!.severity).toBe("CRITICAL");
      expect(secretResult!.cwe).toBe("CWE-798");
    });

    it("detects ALLOWED_HOSTS=['*']", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
      });
      const results = await agent.scan(files);
      const hostsResult = results.find((r) => r.title === "Django ALLOWED_HOSTS accepts all domains");
      expect(hostsResult).toBeDefined();
      expect(hostsResult!.severity).toBe("HIGH");
    });

    it("detects CORS_ALLOW_ALL_ORIGINS=True", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
      });
      const results = await agent.scan(files);
      const corsResult = results.find((r) => r.title === "Django CORS allows all origins");
      expect(corsResult).toBeDefined();
      expect(corsResult!.severity).toBe("MEDIUM");
    });

    it("does not flag clean Django settings", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": CLEAN_DJANGO_SETTINGS,
      });
      const results = await agent.scan(files);
      const djangoMisconfigs = results.filter((r) =>
        r.title.startsWith("Django "),
      );
      expect(djangoMisconfigs).toHaveLength(0);
    });
  });

  describe("scan() — FastAPI issues", () => {
    it("detects endpoints without Depends() auth", async () => {
      const files = makeFiles({
        "requirements.txt": FASTAPI_REQUIREMENTS,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);
      const noAuthResults = results.filter(
        (r) => r.title === "FastAPI endpoint without auth dependency",
      );
      // /users and /admin/delete should be flagged, /health and /protected should not
      expect(noAuthResults.length).toBe(2);
    });

    it("does not flag /health endpoint", async () => {
      const files = makeFiles({
        "requirements.txt": FASTAPI_REQUIREMENTS,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);
      const healthResult = results.find(
        (r) => r.title === "FastAPI endpoint without auth dependency" && r.line === 12,
      );
      expect(healthResult).toBeUndefined();
    });

    it("does not flag endpoints with Depends()", async () => {
      const files = makeFiles({
        "requirements.txt": FASTAPI_REQUIREMENTS,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);
      // The /protected endpoint has Depends() so should not be flagged
      const protectedFlagged = results.find(
        (r) => r.title === "FastAPI endpoint without auth dependency" && r.description.includes("/protected"),
      );
      expect(protectedFlagged).toBeUndefined();
    });

    it("detects open CORS", async () => {
      const files = makeFiles({
        "requirements.txt": FASTAPI_REQUIREMENTS,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);
      const corsResult = results.find((r) => r.title === "FastAPI CORS allows all origins");
      expect(corsResult).toBeDefined();
    });
  });

  describe("scan() — Flask issues", () => {
    it("detects routes without auth decorator", async () => {
      const files = makeFiles({
        "requirements.txt": FLASK_REQUIREMENTS,
        "app.py": FLASK_APP,
      });
      const results = await agent.scan(files);
      const noAuthResults = results.filter(
        (r) => r.title === "Flask route without authentication",
      );
      // /users and /admin/settings should be flagged, /health should not
      expect(noAuthResults.length).toBe(2);
    });

    it("does not flag /health endpoint", async () => {
      const files = makeFiles({
        "requirements.txt": FLASK_REQUIREMENTS,
        "app.py": FLASK_APP,
      });
      const results = await agent.scan(files);
      const healthFlagged = results.filter(
        (r) => r.title === "Flask route without authentication",
      ).some((r) => {
        const lines = FLASK_APP.split("\n");
        return lines[r.line - 1]?.includes("/health");
      });
      expect(healthFlagged).toBe(false);
    });

    it("detects CORS(app) as open CORS", async () => {
      const files = makeFiles({
        "requirements.txt": FLASK_REQUIREMENTS,
        "app.py": FLASK_APP,
      });
      const results = await agent.scan(files);
      const corsResult = results.find((r) => r.title === "Flask CORS allows all origins");
      expect(corsResult).toBeDefined();
    });

    it("does not flag route with @login_required", async () => {
      const protectedFlask = `
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@login_required
@app.route('/admin')
def admin():
    return 'admin panel'
`;
      const files = makeFiles({
        "requirements.txt": FLASK_REQUIREMENTS,
        "app.py": protectedFlask,
      });
      const results = await agent.scan(files);
      const adminFlagged = results.find(
        (r) => r.title === "Flask route without authentication",
      );
      expect(adminFlagged).toBeUndefined();
    });
  });

  describe("scan() — SQL injection", () => {
    it("detects cursor.execute with f-string", async () => {
      const files = makeFiles({
        "requirements.txt": "psycopg2==2.9.9",
        "db.py": SQL_INJECTION_CODE,
      });
      const results = await agent.scan(files);
      const fStringResult = results.find(
        (r) => r.title === "SQL injection via cursor.execute() with string interpolation",
      );
      expect(fStringResult).toBeDefined();
      expect(fStringResult!.severity).toBe("CRITICAL");
      expect(fStringResult!.cwe).toBe("CWE-89");
    });

    it("detects cursor.execute with .format()", async () => {
      const files = makeFiles({
        "requirements.txt": "psycopg2==2.9.9",
        "db.py": SQL_INJECTION_CODE,
      });
      const results = await agent.scan(files);
      const formatResults = results.filter(
        (r) => r.title === "SQL injection via cursor.execute() with string interpolation",
      );
      expect(formatResults.length).toBe(2); // f-string and .format()
    });

    it("detects Django .raw() with f-string", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "queries.py": DJANGO_RAW_QUERY,
      });
      const results = await agent.scan(files);
      const rawResult = results.find(
        (r) => r.title === "SQL injection via Django .raw() with string interpolation",
      );
      expect(rawResult).toBeDefined();
      expect(rawResult!.severity).toBe("CRITICAL");
    });

    it("detects Django .raw() with .format()", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "queries.py": DJANGO_RAW_QUERY,
      });
      const results = await agent.scan(files);
      const formatResults = results.filter(
        (r) => r.title === "SQL injection via Django .raw() with string interpolation",
      );
      expect(formatResults.length).toBe(2);
    });

    it("detects string concatenation in execute()", async () => {
      const files = makeFiles({
        "requirements.txt": "psycopg2==2.9.9",
        "db.py": SQL_CONCAT,
      });
      const results = await agent.scan(files);
      const concatResult = results.find(
        (r) => r.title === "SQL injection via string concatenation in query",
      );
      expect(concatResult).toBeDefined();
    });

    it("does not flag parameterized queries", async () => {
      const safeCode = `
import sqlite3

def get_user(user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
`;
      const files = makeFiles({
        "requirements.txt": "psycopg2==2.9.9",
        "db.py": safeCode,
      });
      const results = await agent.scan(files);
      const sqlResults = results.filter((r) => r.title.includes("SQL injection"));
      expect(sqlResults).toHaveLength(0);
    });
  });

  describe("scan() — committed .env files", () => {
    it("detects .env file with secrets", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        ".env": DOT_ENV,
      });
      const results = await agent.scan(files);
      const envResult = results.find((r) => r.title === "Secret committed in .env file");
      expect(envResult).toBeDefined();
      expect(envResult!.severity).toBe("CRITICAL");
      expect(envResult!.file).toBe(".env");
      expect(envResult!.cwe).toBe("CWE-540");
    });

    it("detects .env.local", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        ".env.local": "SECRET_KEY=abc123xyz789",
      });
      const results = await agent.scan(files);
      const envResult = results.find((r) => r.title === "Secret committed in .env file");
      expect(envResult).toBeDefined();
    });

    it("detects .env.production", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        ".env.production": "API_TOKEN=sk-prod-key-12345678",
      });
      const results = await agent.scan(files);
      const envResult = results.find((r) => r.title === "Secret committed in .env file");
      expect(envResult).toBeDefined();
    });

    it("ignores .env.example files", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        ".env.example": DOT_ENV_EXAMPLE,
      });
      const results = await agent.scan(files);
      const envResult = results.find((r) => r.title === "Secret committed in .env file");
      expect(envResult).toBeUndefined();
    });

    it("ignores .env files without sensitive keys", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        ".env": "DEBUG=true\nPORT=8000\nHOST=localhost",
      });
      const results = await agent.scan(files);
      const envResult = results.find((r) => r.title === "Secret committed in .env file");
      expect(envResult).toBeUndefined();
    });
  });

  describe("scan() — unsafe pickle", () => {
    it("detects pickle.loads()", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        "utils.py": PICKLE_CODE,
      });
      const results = await agent.scan(files);
      const pickleResults = results.filter(
        (r) => r.title === "Unsafe pickle deserialization",
      );
      expect(pickleResults.length).toBe(2); // pickle.loads and pickle.load
    });

    it("reports correct severity and CWE", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        "utils.py": PICKLE_CODE,
      });
      const results = await agent.scan(files);
      const pickleResult = results.find(
        (r) => r.title === "Unsafe pickle deserialization",
      );
      expect(pickleResult!.severity).toBe("CRITICAL");
      expect(pickleResult!.cwe).toBe("CWE-502");
    });

    it("does not flag json.loads()", async () => {
      const safeCode = `
import json

def load_data(data):
    return json.loads(data)
`;
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        "utils.py": safeCode,
      });
      const results = await agent.scan(files);
      const pickleResults = results.filter(
        (r) => r.title === "Unsafe pickle deserialization",
      );
      expect(pickleResults).toHaveLength(0);
    });
  });

  describe("scan() — vulnerable dependencies", () => {
    it("detects known vulnerable Django version", async () => {
      const files = makeFiles({
        "requirements.txt": "Django==4.2.10\n",
      });
      const results = await agent.scan(files);
      const djangoVuln = results.find((r) =>
        r.title.includes("Vulnerable dependency: Django"),
      );
      expect(djangoVuln).toBeDefined();
      expect(djangoVuln!.severity).toBe("HIGH");
      expect(djangoVuln!.title).toContain("CVE-2024-27351");
    });

    it("detects vulnerable requests version", async () => {
      const files = makeFiles({
        "requirements.txt": "requests==2.28.0\n",
      });
      const results = await agent.scan(files);
      const reqVuln = results.find((r) =>
        r.title.includes("Vulnerable dependency: requests"),
      );
      expect(reqVuln).toBeDefined();
      expect(reqVuln!.title).toContain("CVE-2023-32681");
    });

    it("does not flag versions above maxSafe", async () => {
      const files = makeFiles({
        "requirements.txt": "Django==5.0.0\nrequests==2.32.0\n",
      });
      const results = await agent.scan(files);
      const vulnDeps = results.filter((r) =>
        r.title.startsWith("Vulnerable dependency:"),
      );
      expect(vulnDeps).toHaveLength(0);
    });

    it("handles packages without version pinning", async () => {
      const files = makeFiles({
        "requirements.txt": "django\nflask\n",
      });
      const results = await agent.scan(files);
      // No version means we can't compare, should not flag
      const vulnDeps = results.filter((r) =>
        r.title.startsWith("Vulnerable dependency:"),
      );
      expect(vulnDeps).toHaveLength(0);
    });

    it("skips comment and flag lines in requirements.txt", async () => {
      const files = makeFiles({
        "requirements.txt": "# Django app\n-r base.txt\nDjango==5.0.0\n",
      });
      const results = await agent.scan(files);
      const vulnDeps = results.filter((r) =>
        r.title.startsWith("Vulnerable dependency:"),
      );
      expect(vulnDeps).toHaveLength(0);
    });

    it("handles packages with extras", async () => {
      const files = makeFiles({
        "requirements.txt": "urllib3[socks]==1.26.15\n",
      });
      const results = await agent.scan(files);
      const urlVuln = results.find((r) =>
        r.title.includes("Vulnerable dependency: urllib3"),
      );
      expect(urlVuln).toBeDefined();
    });
  });

  describe("scan() — full project fixtures", () => {
    it("Django project: finds all expected issues", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "myapp/settings.py": DJANGO_SETTINGS,
        "myapp/views.py": DJANGO_RAW_QUERY,
        ".env": DOT_ENV,
      });
      const results = await agent.scan(files);

      // Should find: DEBUG, SECRET_KEY, ALLOWED_HOSTS, CORS, .raw() SQLi x2, .env secrets, vulnerable deps
      expect(results.length).toBeGreaterThanOrEqual(7);

      const titles = results.map((r) => r.title);
      expect(titles).toContain("Django DEBUG mode enabled");
      expect(titles).toContain("Django SECRET_KEY hardcoded in source");
      expect(titles).toContain("Django ALLOWED_HOSTS accepts all domains");
      expect(titles).toContain("Django CORS allows all origins");
      expect(titles).toContain("Secret committed in .env file");
    });

    it("FastAPI project: finds all expected issues", async () => {
      const files = makeFiles({
        "requirements.txt": FASTAPI_REQUIREMENTS,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);

      const titles = results.map((r) => r.title);
      expect(titles).toContain("FastAPI endpoint without auth dependency");
      expect(titles).toContain("FastAPI CORS allows all origins");
    });

    it("Flask project: finds all expected issues", async () => {
      const files = makeFiles({
        "requirements.txt": FLASK_REQUIREMENTS,
        "app.py": FLASK_APP,
      });
      const results = await agent.scan(files);

      const titles = results.map((r) => r.title);
      expect(titles).toContain("Flask route without authentication");
      expect(titles).toContain("Flask CORS allows all origins");
    });

    it("clean project: reports zero Django/Flask/FastAPI misconfigs", async () => {
      const cleanMain = `
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp.com"],
)

@app.get("/users")
async def get_users(user = Depends(get_current_user)):
    return db.get_users()
`;
      const files = makeFiles({
        "requirements.txt": "fastapi==0.110.0\nuvicorn==0.24.0\n",
        "main.py": cleanMain,
      });
      const results = await agent.scan(files);

      const frameworkIssues = results.filter(
        (r) =>
          r.title.includes("Django") ||
          r.title.includes("FastAPI") ||
          r.title.includes("Flask") ||
          r.title.includes("SQL injection") ||
          r.title.includes("pickle") ||
          r.title.includes(".env"),
      );
      expect(frameworkIssues).toHaveLength(0);
    });
  });

  describe("scan() — result structure", () => {
    it("every result has required fields", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
        "db.py": SQL_INJECTION_CODE,
        ".env": DOT_ENV,
        "utils.py": PICKLE_CODE,
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

    it("results include CWE references", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
        "db.py": SQL_INJECTION_CODE,
      });
      const results = await agent.scan(files);
      const withCwe = results.filter((r) => r.cwe);
      expect(withCwe.length).toBeGreaterThan(0);
      for (const result of withCwe) {
        expect(result.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });

  describe("getChecks()", () => {
    it("returns non-empty array of check definitions", () => {
      expect(agent.getChecks().length).toBeGreaterThan(0);
    });

    it("every check has required fields", () => {
      const validSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      for (const check of agent.getChecks()) {
        expect(check.id).toBeTruthy();
        expect(check.name).toBeTruthy();
        expect(validSeverities).toContain(check.severity);
      }
    });

    it("check IDs are unique", () => {
      const ids = agent.getChecks().map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("check IDs follow python: prefix convention", () => {
      for (const check of agent.getChecks()) {
        expect(check.id).toMatch(/^python:/);
      }
    });

    it("scan findings have checkIds matching declared checks", async () => {
      const files = makeFiles({
        "requirements.txt": DJANGO_REQUIREMENTS,
        "settings.py": DJANGO_SETTINGS,
        "myapp/views.py": DJANGO_RAW_QUERY,
        "db.py": SQL_INJECTION_CODE,
        ".env": DOT_ENV,
        "utils.py": PICKLE_CODE,
        "main.py": FASTAPI_MAIN,
      });
      const results = await agent.scan(files);
      const declaredIds = new Set(agent.getChecks().map((c) => c.id));

      for (const result of results) {
        if (result.checkId !== undefined) {
          expect(declaredIds.has(result.checkId)).toBe(true);
        }
      }
    });
  });
});
