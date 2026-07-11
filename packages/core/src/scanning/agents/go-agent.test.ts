import { describe, it, expect } from "vitest";
import { GoScanAgent } from "./go-agent.js";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

const GO_MOD = `module github.com/example/myapp

go 1.21

require (
    github.com/gorilla/mux v1.8.1
    gopkg.in/yaml.v3 v3.0.1
)
`;

// --- Fixture: vulnerable Go files ---

const SQL_INJECTION_CODE = `package db

import (
    "database/sql"
    "fmt"
)

func GetUser(db *sql.DB, id string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
}

func GetUserRow(db *sql.DB, id string) {
    db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}

func DeleteUser(db *sql.DB, id string) {
    db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", id))
}

func SafeGetUser(db *sql.DB, id string) {
    db.Query("SELECT * FROM users WHERE id = $1", id)
}
`;

const ERROR_IN_RESPONSE_CODE = `package handlers

import (
    "fmt"
    "net/http"
)

func HandleGet(w http.ResponseWriter, r *http.Request) {
    data, err := fetchData()
    if err != nil {
        fmt.Fprintf(w, "Error: %v", err)
        return
    }
    fmt.Fprintf(w, "OK")
}

func HandlePost(w http.ResponseWriter, r *http.Request) {
    err := processData()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}
`;

const HTTP_WITHOUT_TLS_CODE = `package main

import "net/http"

func main() {
    http.ListenAndServe(":8080", nil)
}
`;

const HTTP_WITH_TLS_CODE = `package main

import "net/http"

func main() {
    http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
`;

// Dangerous: string concatenation inside exec.Command args — high confidence.
const CMD_INJECTION_CONCAT_CODE = `package exec

import "os/exec"

func RunCommand(userInput string) {
    exec.Command("sh", "-c", "echo " + userInput)
}
`;

// Dangerous: fmt.Sprintf used to build the command string — medium confidence.
const CMD_INJECTION_SPRINTF_CODE = `package exec

import (
    "fmt"
    "os/exec"
)

func RunFormatted(name string) {
    exec.Command(fmt.Sprintf("tool-%s", name))
}
`;

// Dangerous: request input directly on same line as exec.Command — high confidence.
const CMD_INJECTION_REQUEST_SAMELINE_CODE = `package handlers

import (
    "net/http"
    "os/exec"
)

func HandleRun(w http.ResponseWriter, r *http.Request) {
    exec.Command("runner", r.FormValue("cmd"))
}
`;

// Safe: simple variable arg, no concat, no same-line request input.
const CMD_INJECTION_SAFE_VAR_CODE = `package exec

import "os/exec"

func RunGit(tag string) {
    exec.Command("git", tag)
}

func RunLs(arg string) {
    exec.Command("ls", arg)
}
`;

const TEMPLATE_HTML_CODE = `package templates

import "html/template"

func RenderUserInput(input string) template.HTML {
    return template.HTML(input)
}
`;

const HARDCODED_CRED_CODE = `package config

var (
    password = "super-secret-pass"
    apiKey   = "sk-1234567890abcdef"
    secret   = "my-jwt-secret-key"
    token    = "ghp_1234567890abcde"
)
`;

const HARDCODED_CRED_FROM_ENV = `package config

import (
    "os"
    "github.com/spf13/viper"
)

var password = os.Getenv("DB_PASSWORD")
var apiKey   = viper.GetString("API_KEY")
`;

const WEAK_HASH_CODE = `package crypto

import (
    "crypto/md5"
    "crypto/sha1"
)

func HashMd5(data []byte) []byte {
    h := md5.New()
    return h.Sum(data)
}

func HashSha1(data []byte) []byte {
    h := sha1.New()
    return h.Sum(data)
}
`;

const WEAK_HASH_USAGE_CODE = `package util

import "crypto/md5"

func Checksum(data []byte) [16]byte {
    return md5.Sum(data)
}
`;

const HTTP_HANDLER_CODE = `package main

import "net/http"

func main() {
    http.HandleFunc("/users", listUsers)
    http.HandleFunc("/admin", adminPanel)
    http.HandleFunc("/health", healthCheck)
    http.ListenAndServe(":8080", nil)
}
`;

const HTTP_HANDLER_WITH_AUTH = `package main

import (
    "net/http"
    "myapp/middleware"
)

func main() {
    mux := http.NewServeMux()
    mux.Handle("/users", middleware.Auth(http.HandlerFunc(listUsers)))
    http.ListenAndServe(":8080", mux)
}
`;

const CORS_WILDCARD_CODE = `package handlers

import "net/http"

func EnableCors(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
}
`;

const CORS_SPECIFIC_ORIGIN_CODE = `package handlers

import "net/http"

func EnableCors(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "https://myapp.com")
}
`;

// Path traversal: file op and request input on the SAME line.
const PATH_TRAVERSAL_CODE = `package handlers

import (
    "net/http"
    "os"
)

func ServeFile(w http.ResponseWriter, r *http.Request) {
    data, _ := os.ReadFile(r.FormValue("file"))
    w.Write(data)
}

func ServeOpen(w http.ResponseWriter, r *http.Request) {
    f, _ := os.Open(r.URL.Query().Get("path"))
    defer f.Close()
}
`;

const YAML_UNSAFE_CODE = `package config

import "gopkg.in/yaml.v3"

func ParseConfig(data []byte) {
    var result interface{}
    yaml.Unmarshal(data, &result)
}
`;

const YAML_UNSAFE_MAP_CODE = `package config

import "gopkg.in/yaml.v3"

func ParseArbitrary(data []byte) map[string]interface{} {
    var out map[string]interface{}
    yaml.Unmarshal(data, &out)
    return out
}
`;

const HTTP_CLIENT_NO_TIMEOUT_CODE = `package client

import "net/http"

var defaultClient = &http.Client{}

func Fetch(url string) (*http.Response, error) {
    return defaultClient.Get(url)
}

func Post(url string, body interface{}) (*http.Response, error) {
    client := http.Client{}
    return client.Post(url, "application/json", nil)
}
`;

const HTTP_DEFAULT_CLIENT_CODE = `package client

import "net/http"

func FetchData(url string) (*http.Response, error) {
    return http.Get(url)
}

func PostData(url string) (*http.Response, error) {
    return http.Post(url, "application/json", nil)
}
`;

const HTTP_CLIENT_WITH_TIMEOUT_CODE = `package client

import (
    "net/http"
    "time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

func Fetch(url string) (*http.Response, error) {
    return httpClient.Get(url)
}
`;

const CLEAN_GO_CODE = `package main

import (
    "database/sql"
    "net/http"
)

func GetUser(db *sql.DB, id string) {
    db.Query("SELECT * FROM users WHERE id = $1", id)
}

func main() {
    http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
`;

// ----- Tests -----

const agent = new GoScanAgent();

describe("GoScanAgent", () => {
  describe("getMetadata()", () => {
    it("returns correct metadata", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("go-agent");
      expect(meta.version).toBe("1.0.0");
      expect(meta.technologies).toEqual(["go"]);
    });
  });

  describe("detect()", () => {
    it("returns true for root-level go.mod", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": "package main" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns true for nested go.mod", async () => {
      const files = makeFiles({ "backend/go.mod": GO_MOD, "backend/main.go": "package main" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns false when no go.mod is present", async () => {
      const files = makeFiles({
        "package.json": '{ "name": "app" }',
        "src/index.ts": "console.log('hi')",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });

    it("does not mistake go.sum for go.mod", async () => {
      const files = makeFiles({ "go.sum": "github.com/gorilla/mux v1.8.1 h1:..." });
      expect(await agent.detect(files)).toBe(false);
    });
  });

  describe("scan() — check 1: SQL injection via fmt.Sprintf", () => {
    it("detects db.Query(fmt.Sprintf(", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": SQL_INJECTION_CODE });
      const results = await agent.scan(files);
      const sqlResults = results.filter((r) => r.cwe === "CWE-89");
      expect(sqlResults.length).toBeGreaterThanOrEqual(1);
    });

    it("detects db.Exec(fmt.Sprintf( and db.QueryRow(fmt.Sprintf(", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": SQL_INJECTION_CODE });
      const results = await agent.scan(files);
      const sqlResults = results.filter((r) => r.title === "SQL injection via fmt.Sprintf in query");
      // Three vulnerable calls: Query, QueryRow, Exec
      expect(sqlResults.length).toBe(3);
    });

    it("does not flag parameterized queries", async () => {
      const safe = `package db
import "database/sql"
func GetUser(db *sql.DB, id string) {
    db.Query("SELECT * FROM users WHERE id = $1", id)
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-89")).toHaveLength(0);
    });

    it("reports CRITICAL severity and CWE-89", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": SQL_INJECTION_CODE });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.cwe === "CWE-89");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
    });
  });

  describe("scan() — check 2: error details in HTTP response", () => {
    it("detects fmt.Fprintf(w, ..., err)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": ERROR_IN_RESPONSE_CODE });
      const results = await agent.scan(files);
      const errResults = results.filter((r) => r.cwe === "CWE-209");
      expect(errResults.length).toBeGreaterThanOrEqual(1);
    });

    it("detects http.Error(w, err.Error(), ...)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": ERROR_IN_RESPONSE_CODE });
      const results = await agent.scan(files);
      const errResults = results.filter((r) => r.cwe === "CWE-209");
      // Both fmt.Fprintf with err and http.Error(w, err.Error()) should be flagged
      expect(errResults.length).toBe(2);
    });

    it("does not flag fmt.Fprintf without err", async () => {
      const safe = `package handlers
import (
    "fmt"
    "net/http"
)
func Handle(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "OK")
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-209")).toHaveLength(0);
    });

    it("reports MEDIUM severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": ERROR_IN_RESPONSE_CODE });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.cwe === "CWE-209");
      expect(finding!.severity).toBe("MEDIUM");
    });
  });

  describe("scan() — check 3: HTTP without TLS", () => {
    it("detects http.ListenAndServe(", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_WITHOUT_TLS_CODE });
      const results = await agent.scan(files);
      const tlsResults = results.filter((r) => r.cwe === "CWE-319");
      expect(tlsResults).toHaveLength(1);
    });

    it("does not flag http.ListenAndServeTLS(", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_WITH_TLS_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-319")).toHaveLength(0);
    });

    it("reports MEDIUM severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_WITHOUT_TLS_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-319")!.severity).toBe("MEDIUM");
    });
  });

  describe("scan() — check 4: command injection", () => {
    it("detects exec.Command with string concatenation (high confidence)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "exec.go": CMD_INJECTION_CONCAT_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-78")).toHaveLength(1);
    });

    it("detects exec.Command with fmt.Sprintf (medium confidence)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "exec.go": CMD_INJECTION_SPRINTF_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-78")).toHaveLength(1);
    });

    it("detects exec.Command with r.FormValue on same line (high confidence)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": CMD_INJECTION_REQUEST_SAMELINE_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-78")).toHaveLength(1);
    });

    it("does not flag exec.Command with only string literals", async () => {
      const safe = `package main
import "os/exec"
func List() {
    exec.Command("ls", "-la")
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-78")).toHaveLength(0);
    });

    it("does not flag exec.Command with simple variable args (no concat, no same-line input)", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "exec.go": CMD_INJECTION_SAFE_VAR_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-78")).toHaveLength(0);
    });

    it("reports CRITICAL severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "exec.go": CMD_INJECTION_CONCAT_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-78")!.severity).toBe("CRITICAL");
    });
  });

  describe("scan() — check 5: template.HTML() bypass", () => {
    it("detects template.HTML( with unsanitized input", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "templates.go": TEMPLATE_HTML_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-79")).toHaveLength(1);
    });

    it("does not flag code without template.HTML", async () => {
      const safe = `package templates
import "html/template"
func Render(t *template.Template, data interface{}) error {
    return t.Execute(nil, data)
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "templates.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-79")).toHaveLength(0);
    });

    it("does not flag template.HTML( when argument is sanitized via bluemonday", async () => {
      const sanitized = `package templates
import (
    "html/template"
    "github.com/microcosm-cc/bluemonday"
)
func Render(input string) template.HTML {
    p := bluemonday.UGCPolicy()
    return template.HTML(p.Sanitize(input))
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "templates.go": sanitized });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-79")).toHaveLength(0);
    });

    it("does not flag template.HTML( when argument uses html.EscapeString", async () => {
      const escaped = `package templates
import (
    "html"
    "html/template"
)
func Render(input string) template.HTML {
    return template.HTML(html.EscapeString(input))
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "templates.go": escaped });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-79")).toHaveLength(0);
    });

    it("reports HIGH severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "templates.go": TEMPLATE_HTML_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-79")!.severity).toBe("HIGH");
    });
  });

  describe("scan() — check 6: hardcoded credentials", () => {
    it("detects hardcoded password, apiKey, secret, token", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": HARDCODED_CRED_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-798").length).toBeGreaterThanOrEqual(4);
    });

    it("does not flag credentials read from environment", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": HARDCODED_CRED_FROM_ENV });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-798")).toHaveLength(0);
    });

    it("does not flag comment lines", async () => {
      const commented = `package config
// password = "super-secret-pass"
// token = "hardcoded-token-value"
`;
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": commented });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-798")).toHaveLength(0);
    });

    it("does not flag short values (less than 8 chars)", async () => {
      const shortCred = `package config
var password = "abc"
var token = "short"
`;
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": shortCred });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-798")).toHaveLength(0);
    });

    it("reports CRITICAL severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": HARDCODED_CRED_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-798")!.severity).toBe("CRITICAL");
    });
  });

  describe("scan() — check 7: weak hash algorithm", () => {
    it("detects crypto/md5 import", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "crypto.go": WEAK_HASH_CODE });
      const results = await agent.scan(files);
      const md5Results = results.filter((r) => r.title.includes("MD5"));
      expect(md5Results.length).toBeGreaterThanOrEqual(1);
    });

    it("detects crypto/sha1 import", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "crypto.go": WEAK_HASH_CODE });
      const results = await agent.scan(files);
      const sha1Results = results.filter((r) => r.title.includes("SHA-1"));
      expect(sha1Results.length).toBeGreaterThanOrEqual(1);
    });

    it("detects md5.Sum usage", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "util.go": WEAK_HASH_USAGE_CODE });
      const results = await agent.scan(files);
      const hashResults = results.filter((r) => r.cwe === "CWE-328");
      expect(hashResults.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag crypto/sha256", async () => {
      const safe = `package crypto
import "crypto/sha256"
func Hash(data []byte) []byte {
    h := sha256.New()
    return h.Sum(data)
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "crypto.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-328")).toHaveLength(0);
    });

    it("reports HIGH severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "crypto.go": WEAK_HASH_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-328")!.severity).toBe("HIGH");
    });
  });

  describe("scan() — check 8: HTTP handler without auth middleware", () => {
    it("detects http.HandleFunc without auth in file", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_HANDLER_CODE });
      const results = await agent.scan(files);
      const authResults = results.filter((r) => r.cwe === "CWE-306");
      // /health should be skipped; /users and /admin should be flagged
      expect(authResults.length).toBe(2);
    });

    it("does not flag files with auth middleware references", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_HANDLER_WITH_AUTH });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-306")).toHaveLength(0);
    });

    it("does not flag /health, /public, /static, /favicon paths", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_HANDLER_CODE });
      const results = await agent.scan(files);
      const authResults = results.filter((r) => r.cwe === "CWE-306");
      // None of the findings should point to the /health handler
      const linesInFile = HTTP_HANDLER_CODE.split("\n");
      for (const r of authResults) {
        expect(linesInFile[r.line - 1]).not.toContain("/health");
      }
    });

    it("reports MEDIUM severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": HTTP_HANDLER_CODE });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.cwe === "CWE-306");
      expect(finding!.severity).toBe("MEDIUM");
    });
  });

  describe("scan() — check 9: CORS wildcard", () => {
    it("detects Access-Control-Allow-Origin set to * on same line", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": CORS_WILDCARD_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-942")).toHaveLength(1);
    });

    it("does not flag specific origin", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": CORS_SPECIFIC_ORIGIN_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-942")).toHaveLength(0);
    });

    it("detects wildcard across adjacent lines", async () => {
      const multiline = `package handlers
import "net/http"
func Cors(w http.ResponseWriter) {
    w.Header().Set("Access-Control-Allow-Origin",
        "*")
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "cors.go": multiline });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-942")).toHaveLength(1);
    });

    it("reports MEDIUM severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": CORS_WILDCARD_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-942")!.severity).toBe("MEDIUM");
    });
  });

  describe("scan() — check 10: path traversal", () => {
    it("detects os.ReadFile with r.FormValue on same line", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": PATH_TRAVERSAL_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-22").length).toBeGreaterThanOrEqual(1);
    });

    it("detects both os.Open and os.ReadFile with same-line request input", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": PATH_TRAVERSAL_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-22").length).toBe(2);
    });

    it("does not flag file operations where input is assigned on a previous line", async () => {
      // The old 5-line context window flagged this; the new same-line-only check should not.
      const splitLine = `package handlers
import (
    "net/http"
    "os"
)
func ServeFile(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("file")
    data, _ := os.ReadFile(name)
    w.Write(data)
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": splitLine });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-22")).toHaveLength(0);
    });

    it("does not flag file operations with static paths", async () => {
      const safe = `package static
import "os"
func LoadConfig() ([]byte, error) {
    return os.ReadFile("config/app.yaml")
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "static.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-22")).toHaveLength(0);
    });

    it("does not flag file operations where filepath.Clean sanitizes the path", async () => {
      const cleaned = `package handlers
import (
    "net/http"
    "os"
    "path/filepath"
)
func ServeFile(w http.ResponseWriter, r *http.Request) {
    data, _ := os.ReadFile(filepath.Clean(r.FormValue("file")))
    w.Write(data)
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": cleaned });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-22")).toHaveLength(0);
    });

    it("reports HIGH severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "handlers.go": PATH_TRAVERSAL_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-22")!.severity).toBe("HIGH");
    });
  });

  describe("scan() — check 11: unsafe YAML deserialization", () => {
    it("detects yaml.Unmarshal with interface{} on same line", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": YAML_UNSAFE_CODE });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-502")).toHaveLength(1);
    });

    it("detects yaml.Unmarshal with map[string]interface{} on same line", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": YAML_UNSAFE_MAP_CODE });
      const results = await agent.scan(files);
      // map[string]interface{} contains interface{} so it should match
      expect(results.filter((r) => r.cwe === "CWE-502")).toHaveLength(1);
    });

    it("does not flag yaml.Unmarshal into a typed struct", async () => {
      const safe = `package config
import "gopkg.in/yaml.v3"
type Config struct {
    Host string \`yaml:"host"\`
    Port int    \`yaml:"port"\`
}
func ParseConfig(data []byte) Config {
    var cfg Config
    yaml.Unmarshal(data, &cfg)
    return cfg
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": safe });
      const results = await agent.scan(files);
      expect(results.filter((r) => r.cwe === "CWE-502")).toHaveLength(0);
    });

    it("reports HIGH severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "config.go": YAML_UNSAFE_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-502")!.severity).toBe("HIGH");
    });
  });

  describe("scan() — check 12: HTTP client without timeout", () => {
    it("detects &http.Client{} without Timeout", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": HTTP_CLIENT_NO_TIMEOUT_CODE });
      const results = await agent.scan(files);
      const timeoutResults = results.filter((r) => r.cwe === "CWE-400");
      expect(timeoutResults.length).toBeGreaterThanOrEqual(1);
    });

    it("detects http.Get() and http.Post() default client usage", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": HTTP_DEFAULT_CLIENT_CODE });
      const results = await agent.scan(files);
      const timeoutResults = results.filter((r) => r.cwe === "CWE-400");
      expect(timeoutResults.length).toBe(2); // http.Get and http.Post
    });

    it("does not flag &http.Client{Timeout: ...}", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": HTTP_CLIENT_WITH_TIMEOUT_CODE });
      const results = await agent.scan(files);
      // Only the http.Get call within the method could be flagged — but here it uses the named client
      const noTimeoutClient = results.filter(
        (r) => r.cwe === "CWE-400" && r.title.includes("created without timeout"),
      );
      expect(noTimeoutClient).toHaveLength(0);
    });

    it("detects multiline &http.Client{} struct without Timeout in the block", async () => {
      const multiline = `package client
import (
    "net/http"
    "time"
)
var c = &http.Client{
    Transport: http.DefaultTransport,
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": multiline });
      const results = await agent.scan(files);
      const noTimeout = results.filter(
        (r) => r.cwe === "CWE-400" && r.title.includes("created without timeout"),
      );
      expect(noTimeout.length).toBeGreaterThanOrEqual(1);
    });

    it("does not flag multiline &http.Client{} struct that includes Timeout field", async () => {
      const multilineWithTimeout = `package client
import (
    "net/http"
    "time"
)
var c = &http.Client{
    Timeout:   30 * time.Second,
    Transport: http.DefaultTransport,
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": multilineWithTimeout });
      const results = await agent.scan(files);
      const noTimeout = results.filter(
        (r) => r.cwe === "CWE-400" && r.title.includes("created without timeout"),
      );
      expect(noTimeout).toHaveLength(0);
    });

    it("reports MEDIUM severity", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "client.go": HTTP_DEFAULT_CLIENT_CODE });
      const results = await agent.scan(files);
      expect(results.find((r) => r.cwe === "CWE-400")!.severity).toBe("MEDIUM");
    });
  });

  describe("scan() — SQL injection confidence", () => {
    it("assigns high confidence to %s in query string", async () => {
      const code = `package db
import (
    "database/sql"
    "fmt"
)
func GetUser(db *sql.DB, id string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": code });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.cwe === "CWE-89") as (typeof results[0] & { confidence?: string }) | undefined;
      expect(finding).toBeDefined();
      expect(finding!.confidence).toBe("high");
    });

    it("assigns low confidence to %d-only query string (type-safe integer)", async () => {
      const code = `package db
import (
    "database/sql"
    "fmt"
)
func GetById(db *sql.DB, id int) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}`;
      const files = makeFiles({ "go.mod": GO_MOD, "db.go": code });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.cwe === "CWE-89") as (typeof results[0] & { confidence?: string }) | undefined;
      expect(finding).toBeDefined();
      expect(finding!.confidence).toBe("low");
    });
  });

  describe("scan() — result structure", () => {
    it("every result has all required fields including confidence", async () => {
      const files = makeFiles({
        "go.mod": GO_MOD,
        "db.go": SQL_INJECTION_CODE,
        "handlers.go": ERROR_IN_RESPONSE_CODE,
        "main.go": HTTP_WITHOUT_TLS_CODE,
        "config.go": HARDCODED_CRED_CODE,
        "crypto.go": WEAK_HASH_CODE,
      });
      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      for (const r of results) {
        expect(r.title).toBeTruthy();
        expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(r.severity);
        expect(r.file).toBeTruthy();
        expect(r.line).toBeGreaterThan(0);
        expect(r.description).toBeTruthy();
        expect(r.fix).toBeTruthy();
        // Every finding must carry a confidence rating.
        expect(["high", "medium", "low"]).toContain((r as typeof r & { confidence?: string }).confidence);
      }
    });

    it("all results include a CWE reference", async () => {
      const files = makeFiles({
        "go.mod": GO_MOD,
        "db.go": SQL_INJECTION_CODE,
        "config.go": HARDCODED_CRED_CODE,
        "crypto.go": WEAK_HASH_CODE,
      });
      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      for (const r of results) {
        expect(r.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });

  describe("scan() — clean project", () => {
    it("returns zero findings for clean Go code", async () => {
      const files = makeFiles({ "go.mod": GO_MOD, "main.go": CLEAN_GO_CODE });
      const results = await agent.scan(files);
      expect(results).toHaveLength(0);
    });

    it("skips non-.go files", async () => {
      const files = makeFiles({
        "go.mod": GO_MOD,
        "README.md": "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))",
        "notes.txt": "password = \"secret-in-text-file\"",
      });
      const results = await agent.scan(files);
      expect(results).toHaveLength(0);
    });
  });

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

    it("check IDs follow go: prefix convention", () => {
      const checks = agent.getChecks();
      for (const check of checks) {
        expect(check.id).toMatch(/^go:/);
      }
    });

    it("scan findings have checkIds matching declared checks", async () => {
      const files = makeFiles({
        "go.mod": GO_MOD,
        "db.go": SQL_INJECTION_CODE,
        "handlers.go": ERROR_IN_RESPONSE_CODE,
        "main.go": HTTP_WITHOUT_TLS_CODE,
        "exec.go": CMD_INJECTION_CONCAT_CODE,
        "templates.go": TEMPLATE_HTML_CODE,
        "config.go": HARDCODED_CRED_CODE,
        "crypto.go": WEAK_HASH_CODE,
        "cors.go": CORS_WILDCARD_CODE,
        "path.go": PATH_TRAVERSAL_CODE,
        "yaml.go": YAML_UNSAFE_CODE,
        "client.go": HTTP_CLIENT_NO_TIMEOUT_CODE,
      });
      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      const declaredIds = new Set(agent.getChecks().map((c) => c.id));
      for (const result of results) {
        expect(result.checkId).toBeTruthy();
        expect(declaredIds.has(result.checkId!)).toBe(true);
      }
    });
  });
});
