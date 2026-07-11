// Code pattern analysis engine - detects insecure code patterns
// In production, this would call Semgrep. For now, uses regex-based detection.

import type { FindingData, FindingConfidence } from "./types.js";

interface PatternRule {
  id: number;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  pattern: RegExp;
  fileFilter?: RegExp;
  owasp?: string;
  confidence?: FindingConfidence;
  // If true, this rule is suppressed when project-level middleware handles it
  suppressedByMiddleware?: boolean;
  // If set, the rule only fires when this pattern ALSO matches somewhere in the
  // same file. Used to require corroborating context (e.g. an actual LLM SDK
  // call) so a broad match doesn't misfire in unrelated code.
  requiresNearby?: RegExp;
}

const PATTERN_RULES: PatternRule[] = [
  // === Broken Access Control ===
  {
    id: 1,
    name: "API Route Without Auth Check",
    severity: "high",
    category: "web-owasp",
    pattern: /export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{(?:(?!auth\.getUser|getUser|getSession|verifyAuth|requireAuth|Bearer|authorization|CRON_SECRET|WORKER_API_KEY|verifySignature)[\s\S]){0,500}(?:Response\.json|NextResponse)/,
    fileFilter: /\/api\/(?!webhook|auth)/,
    owasp: "A01:2021",
  },
  // === Injection ===
  {
    id: 5,
    name: "Potential SQL Injection",
    severity: "critical",
    category: "web-owasp",
    pattern: /(?:\$queryRaw|\.query|sequelize\.query|execute)\s*\(\s*`[^`]*\$\{/,
    owasp: "A03:2021",
  },
  {
    id: 61,
    name: "eval() with Dynamic Input",
    severity: "critical",
    category: "vibecoding",
    pattern: /(?:eval|Function)\s*\(\s*(?:[^"'`)\s]|`[^`]*\$\{)/,
    owasp: "A03:2021",
  },
  // === Cryptographic Failures ===
  {
    id: 2,
    name: "Weak Hash Algorithm (MD5/SHA1)",
    severity: "high",
    category: "web-owasp",
    pattern: /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/,
    owasp: "A02:2021",
  },
  {
    id: 125,
    name: "Math.random for Security Purpose",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|id|nonce|salt)[\s\S]{0,30}Math\.random/i,
    owasp: "A02:2021",
  },
  {
    id: 126,
    name: "JWT Algorithm None Allowed",
    severity: "critical",
    category: "cryptography",
    pattern: /algorithms\s*:\s*\[.*["']none["']/i,
  },
  // === XSS ===
  // dangerouslySetInnerHTML is handled as a special case in analyzePatterns()
  // because we need file-level context (imports, variable sources) to reduce false positives.
  {
    id: 86,
    name: "DOM-based XSS Risk",
    severity: "high",
    category: "frontend",
    pattern: /(?:document\.write|\.innerHTML\s*=)\s*(?:.*(?:location|document\.URL|window\.name|document\.referrer))/,
    owasp: "A03:2021",
  },
  // === Token Storage ===
  {
    id: 47,
    name: "Tokens Stored in localStorage",
    severity: "high",
    category: "react-nextjs",
    pattern: /localStorage\.setItem\s*\(\s*["'](?:token|jwt|auth|session|access_token|refresh_token)["']/i,
    owasp: "A07:2021",
  },
  // === Security Misconfiguration ===
  {
    id: 4,
    name: "Open CORS Policy",
    severity: "medium",
    category: "web-owasp",
    pattern: /Access-Control-Allow-Origin['":\s]*['"]\*['"]/,
    owasp: "A05:2021",
  },
  {
    id: 50,
    name: "CORS Wildcard in API Route",
    severity: "medium",
    category: "react-nextjs",
    pattern: /(?:headers\.set|res\.setHeader)\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\)/,
    fileFilter: /\/api\//,
  },
  // === Supabase Specific ===
  {
    id: 34,
    name: "Supabase Service Role Key in Client Code",
    severity: "critical",
    category: "supabase",
    pattern: /NEXT_PUBLIC_.*SERVICE_ROLE|["']use client["'][\s\S]*service_role/i,
    owasp: "A07:2021",
  },
  {
    id: 31,
    name: "RLS Disabled on Table",
    severity: "critical",
    category: "supabase",
    // Fixed: \Z is not valid JS regex — use $ (matches end of string without /m flag).
    // This checks that between this CREATE TABLE and the next (or end of file),
    // there is no ENABLE ROW LEVEL SECURITY statement.
    pattern: /CREATE\s+TABLE(?:(?!ENABLE\s+ROW\s+LEVEL\s+SECURITY)[\s\S])*?(?=CREATE\s+TABLE|$)/i,
    fileFilter: /\.sql$/,
    confidence: "medium",
  },
  {
    id: 32,
    name: "RLS Policy with USING(true)",
    severity: "critical",
    category: "supabase",
    pattern: /CREATE\s+POLICY[\s\S]*?USING\s*\(\s*true\s*\)/i,
    fileFilter: /\.sql$/,
  },
  // === Input Validation ===
  {
    id: 54,
    name: "No Input Validation on API Route",
    severity: "medium",
    category: "vibecoding",
    pattern: /(?:req\.body|request\.json\(\))[\s\S]{0,100}(?:\.insert|\.update|\.create)(?![\s\S]{0,200}(?:safeParse|parse|validate|schema|zod))/,
    fileFilter: /\/api\//,
  },
  // === JWT Issues ===
  {
    id: 56,
    name: "JWT Without Expiration",
    severity: "high",
    category: "vibecoding",
    pattern: /jwt\.sign\s*\([^)]*(?!\bexpiresIn\b|\bexp\b)[^)]*\)/,
  },
  // === Verbose Errors ===
  {
    id: 59,
    name: "Verbose Error Response",
    severity: "medium",
    category: "vibecoding",
    // Only flag when error object properties (.stack, .message) are directly
    // inside the JSON response body — not generic string messages like { error: "Unauthorized" }.
    // [^}]* prevents matching across multiple object literals (no greedy [\s\S]).
    pattern: /Response\.json\s*\(\s*\{[^}]*(?:\.stack|\.trace|(?:err|error|e)\.message)[^}]*\}\s*,\s*\{\s*status:\s*5/,
    fileFilter: /\/api\//,
    confidence: "medium",
  },
  {
    id: 134,
    name: "Environment Variables Logged",
    severity: "high",
    category: "serverless",
    pattern: /console\.log\s*\(\s*process\.env/,
  },
  // === Auth Patterns ===
  {
    id: 57,
    name: "Auth Logic in Frontend Only",
    severity: "high",
    category: "vibecoding",
    pattern: /["']use client["'][\s\S]*?(?:isAdmin|isAuth|role\s*===|user\.role)/,
    fileFilter: /\.(?:tsx|jsx)$/,
  },
  // === Open Redirect ===
  {
    id: 119,
    name: "Open Redirect",
    severity: "medium",
    category: "logic",
    pattern: /(?:redirect|location\.href|window\.location)\s*[=(]\s*(?:req\.query|searchParams\.get|params)/,
    owasp: "A01:2021",
  },
  // === Prototype Pollution ===
  {
    id: 128,
    name: "Potential Prototype Pollution",
    severity: "high",
    category: "javascript",
    pattern: /(?:Object\.assign|\.\.\.(?:req\.body|body|params|query))[\s\S]{0,50}(?:\.update|\.create|\.insert)/,
  },
  // === Certificate Validation ===
  {
    id: 124,
    name: "TLS Certificate Validation Disabled",
    severity: "critical",
    category: "cryptography",
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/,
  },
  // === Debug/Test Routes ===
  {
    id: 116,
    name: "Debug Route in Production",
    severity: "medium",
    category: "logic",
    pattern: /(?:\/debug|\/test|\/seed|\/admin-test)[\s'"]/,
    fileFilter: /(?:route|router|app)\./,
  },
  // === File/Path Issues ===
  {
    id: 106,
    name: "Path Traversal Risk",
    severity: "high",
    category: "files",
    pattern: /(?:readFile|createReadStream|readdir|unlink|writeFile)\s*\([^)]*(?:req\.|params\.|query\.)/,
    owasp: "A01:2021",
  },
  // === WebSocket ===
  {
    id: 199,
    name: "WebSocket Without Authentication",
    severity: "high",
    category: "api",
    pattern: /(?:new\s+WebSocket|ws\.on\s*\(\s*["']connection["'])(?:(?!auth|token|verify|session)[\s\S]){0,300}/,
  },

  // =============================================
  // EXPANDED PATTERNS — Injections (IDs 72-76)
  // =============================================
  {
    id: 72,
    name: "XML External Entity (XXE) Risk",
    severity: "high",
    category: "injection",
    pattern: /(?:DOMParser|xml2js\.parse|parseString|libxmljs\.parseXml|fast-xml-parser)(?:(?!disableEntities|noent.*false|DISALLOW_DOCTYPE)[\s\S]){0,200}/,
    owasp: "A03:2021",
  },
  {
    id: 73,
    name: "HTTP Header Injection (CRLF)",
    severity: "medium",
    category: "injection",
    pattern: /(?:res\.setHeader|response\.headers\.set|res\.writeHead)\s*\([^,]*,\s*(?:req\.|params\.|query\.|searchParams\.get)/,
    owasp: "A03:2021",
  },
  {
    id: 74,
    name: "Log Injection — Unsanitized User Input in Logs",
    severity: "low",
    category: "injection",
    pattern: /(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug))\s*\([^)]*(?:req\.body|req\.query|req\.params|searchParams\.get)/,
    owasp: "A09:2021",
  },
  {
    id: 75,
    name: "Command Injection Risk",
    severity: "critical",
    category: "injection",
    pattern: /(?:child_process\.exec|execSync|exec)\s*\(\s*(?:`[^`]*\$\{|[^"'`\s]+\s*\+\s*(?:req\.|params\.|query\.|body\.))/,
    owasp: "A03:2021",
  },
  {
    id: 76,
    name: "Server-Side Template Injection (SSTI)",
    severity: "critical",
    category: "injection",
    pattern: /(?:ejs\.render|pug\.render|Handlebars\.compile|nunjucks\.renderString|mustache\.render)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/,
    owasp: "A03:2021",
  },

  // =============================================
  // Auth Expanded (IDs 77-85)
  // =============================================
  {
    id: 78,
    name: "Authentication Endpoint Without Rate Limiting",
    severity: "medium",
    category: "auth",
    pattern: /(?:\/login|\/signin|\/auth|\/register|\/signup|\/reset-password)[\s\S]{0,500}(?:export\s+async\s+function\s+POST)(?:(?!rateLimit|rateLimiter|throttle|limiter)[\s\S]){0,500}/,
    fileFilter: /\/api\//,
    owasp: "A07:2021",
    confidence: "low",
    suppressedByMiddleware: true,
  },
  {
    id: 79,
    name: "Password Reset Token in URL",
    severity: "medium",
    category: "auth",
    pattern: /(?:reset|forgot|recover).*(?:token|code)[\s\S]{0,100}(?:searchParams|query\.|req\.query)/i,
    owasp: "A07:2021",
  },
  {
    id: 82,
    name: "User Enumeration via Error Message",
    severity: "low",
    category: "auth",
    pattern: /(?:["'](?:user\s+not\s+found|email\s+not\s+registered|no\s+account\s+found|invalid\s+username|username\s+does\s+not\s+exist)["'])/i,
    fileFilter: /\/api\//,
    owasp: "A07:2021",
  },
  {
    id: 85,
    name: "OAuth Missing State Parameter",
    severity: "high",
    category: "auth",
    pattern: /(?:authorize\?|oauth.*\?)(?:(?!state=)[\s\S]){0,200}(?:client_id|redirect_uri)/i,
    owasp: "A07:2021",
  },

  // =============================================
  // Frontend Expanded (IDs 86-93)
  // =============================================
  {
    id: 88,
    name: "PostMessage Without Origin Verification",
    severity: "medium",
    category: "frontend",
    pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:function|\()\s*\w*\s*[){](?:(?!\.origin|event\.source)[\s\S]){0,300}/,
    fileFilter: /\.(?:tsx|jsx|ts|js)$/,
    owasp: "A01:2021",
  },
  {
    id: 89,
    name: "Insecure CDN Link (HTTP)",
    severity: "medium",
    category: "frontend",
    pattern: /(?:src|href)\s*=\s*["']http:\/\/(?:cdn|cdnjs|unpkg|jsdelivr|ajax\.googleapis)/,
    fileFilter: /\.(?:tsx|jsx|html)$/,
  },
  {
    id: 91,
    name: "Potential Regular Expression DoS (ReDoS)",
    severity: "medium",
    category: "frontend",
    pattern: /new\s+RegExp\s*\(\s*(?:[^"'`)\s]|`[^`]*\$\{)/,
    // Only flag in API routes and request handlers where user input could reach the regex.
    // Internal tools and analyzers use controlled/extracted data, not raw user input.
    fileFilter: /(?:\/api\/|\/server|\.server\.|route\.|controller|handler|middleware)/i,
    owasp: "A03:2021",
  },
  {
    id: 92,
    name: "Insecure Iframe — Missing Sandbox",
    severity: "medium",
    category: "frontend",
    pattern: /<iframe(?:(?!sandbox)[\s\S]){0,200}(?:src\s*=)/i,
    fileFilter: /\.(?:tsx|jsx|html)$/,
  },

  // =============================================
  // APIs Expanded (IDs 94-100)
  // =============================================
  {
    id: 96,
    name: "API Route Without Rate Limiting",
    severity: "medium",
    category: "api",
    pattern: /export\s+async\s+function\s+(?:GET|POST|PUT|PATCH|DELETE)(?:(?!rateLimit|rateLimiter|throttle|limiter)[\s\S]){20,1000}/,
    fileFilter: /\/api\/(?!webhook)/,
    owasp: "A04:2023",
    confidence: "low",
    suppressedByMiddleware: true,
  },
  {
    id: 98,
    name: "Mass Assignment — Request Body Directly to Database",
    severity: "high",
    category: "api",
    pattern: /(?:\.update|\.create|\.insert|\.upsert)\s*\(\s*(?:req\.body|body|await\s+request\.json\(\))\s*\)/,
    fileFilter: /\/api\//,
    owasp: "A01:2021",
  },
  {
    id: 99,
    name: "Excessive Data Exposure — SELECT *",
    severity: "medium",
    category: "api",
    pattern: /\.select\s*\(\s*["']\*["']\s*\)/,
    fileFilter: /\/api\//,
    owasp: "A03:2023",
  },

  // =============================================
  // Database General (IDs 101-105)
  // =============================================
  {
    id: 102,
    name: "NoSQL Injection Risk",
    severity: "high",
    category: "database",
    pattern: /\.find\s*\(\s*(?:req\.body|req\.query|body|JSON\.parse)/,
    owasp: "A03:2021",
  },
  {
    id: 103,
    name: "ORM Injection — Raw Query with User Input",
    severity: "high",
    category: "database",
    pattern: /(?:\$queryRaw|\.raw|Sequelize\.literal|knex\.raw)\s*\(\s*(?:`[^`]*\$\{|[^"'`]+\+)/,
    // Only flag in server/API files — marketing pages and components use code examples
    // that contain raw query patterns as educational content (JSX string literals)
    fileFilter: /(?:\/api\/|\/lib\/|\/server|\.server\.|route\.|controller|handler|model|service)/i,
    owasp: "A03:2021",
  },

  // =============================================
  // Files & Media (IDs 106-112)
  // =============================================
  {
    id: 107,
    name: "File Upload Without Type Validation",
    severity: "high",
    category: "files",
    pattern: /(?:multer|formidable|busboy|multiparty)(?:(?!fileFilter|mimetype|allowedTypes|accept)[\s\S]){0,500}(?:upload|file|single|array|fields)/i,
    owasp: "A04:2021",
  },
  {
    id: 108,
    name: "File Upload Without Size Limit",
    severity: "medium",
    category: "files",
    pattern: /(?:multer|formidable|busboy)(?:(?!limits|maxFileSize|maxSize|fileSizeLimit)[\s\S]){0,500}(?:upload|single|array)/i,
    owasp: "A04:2021",
  },
  {
    id: 110,
    name: "Insecure Temp File Creation",
    severity: "medium",
    category: "files",
    pattern: /(?:writeFileSync|createWriteStream)\s*\(\s*(?:["']\/tmp\/|os\.tmpdir\(\))/,
  },

  // =============================================
  // Race Conditions & Logic (IDs 113-120)
  // =============================================
  {
    id: 114,
    name: "Price or Amount Accepted from Client Input",
    severity: "critical",
    category: "logic",
    pattern: /(?:price|amount|total|cost|quantity)\s*[=:]\s*(?:req\.body|body|params|query)\./i,
    fileFilter: /\/api\//,
    owasp: "A04:2021",
  },
  {
    id: 115,
    name: "TOCTOU — Time of Check to Time of Use",
    severity: "medium",
    category: "logic",
    pattern: /(?:existsSync|accessSync|statSync)\s*\([^)]+\)[\s\S]{0,100}(?:readFileSync|unlinkSync|writeFileSync)/,
    // Only flag in API routes and server handlers where concurrent requests matter.
    // Build-time utilities (content loaders, scripts) are single-threaded and safe.
    fileFilter: /(?:\/api\/|\/server|\.server\.|route\.|controller|handler|middleware)/i,
  },

  // =============================================
  // JavaScript/Node (IDs 128-131)
  // =============================================
  {
    id: 129,
    name: "Unsafe Deserialization",
    severity: "critical",
    category: "javascript",
    pattern: /(?:serialize|unserialize|deserialize|node-serialize|serialize-javascript)\s*\(\s*(?:req\.|body|params|query|JSON\.parse)/i,
    owasp: "A08:2021",
  },
  {
    id: 130,
    name: "Buffer Allocation Without Fill",
    severity: "medium",
    category: "javascript",
    pattern: /Buffer\.allocUnsafe\s*\(|new\s+Buffer\s*\(\s*\d/,
  },
  {
    id: 131,
    name: "Synchronous Operation Blocking Event Loop",
    severity: "low",
    category: "javascript",
    pattern: /(?:readFileSync|writeFileSync|execSync|spawnSync|accessSync)\s*\(/,
    fileFilter: /\/api\//,
  },

  // =============================================
  // Serverless & Cloud (IDs 132-136)
  // =============================================
  {
    id: 133,
    name: "Function with Overly Broad Permissions",
    severity: "medium",
    category: "serverless",
    pattern: /(?:policy|permissions|role)[\s\S]{0,100}(?:["']\*["']|AdministratorAccess|FullAccess)/i,
    fileFilter: /(?:serverless|sam|template|cdk|terraform)/,
  },
  {
    id: 135,
    name: "Verbose Error in Production Response",
    severity: "medium",
    category: "serverless",
    // Only flag when error object properties are interpolated INTO the response body.
    // Safe pattern: console.error(e.message) then return { error: "generic string" }
    // Unsafe pattern: return Response.json({ error: e.message }) — exposes internals.
    // Increase lookahead distance but skip blocks that log to console first (safe pattern).
    pattern: /catch\s*\(\s*(\w+)\s*\)\s*\{(?:(?!console\.(?:error|warn|log))[\s\S]){0,80}(?:Response\.json|res\.(?:json|send))\s*\(\s*\{[^}]*(?:\1\.stack|\1\.message|\1\.toString\(\))/,
    fileFilter: /\/api\//,
    confidence: "medium",
  },

  // =============================================
  // Supply Chain (IDs 137-141)
  // =============================================
  {
    id: 138,
    name: "Suspicious Postinstall Script",
    severity: "high",
    category: "supply-chain",
    pattern: /["'](?:postinstall|preinstall|install)["']\s*:\s*["'][^"']*(?:curl|wget|bash|sh\s|node\s+-e|eval)/,
    fileFilter: /package\.json$/,
  },

  // =============================================
  // Crypto Expanded (IDs 121-127)
  // =============================================
  {
    id: 121,
    name: "Hardcoded Encryption Key",
    severity: "critical",
    category: "cryptography",
    pattern: /(?:createCipher|createCipheriv|createDecipher|createDecipheriv)\s*\([^)]*["'][^"']{8,}["']/,
    owasp: "A02:2021",
  },
  {
    id: 122,
    name: "ECB Mode Used for Encryption",
    severity: "high",
    category: "cryptography",
    pattern: /(?:aes|des|blowfish|rc4).*ecb/i,
    owasp: "A02:2021",
  },
  {
    id: 123,
    name: "Static IV for Encryption",
    severity: "high",
    category: "cryptography",
    pattern: /(?:iv|nonce|initVector)\s*=\s*(?:Buffer\.from\s*\(\s*["']|["'][0-9a-f]{16,}["'])/i,
    owasp: "A02:2021",
  },

  // =============================================
  // Framework-agnostic patterns (Express/Fastify/Hono/Koa)
  // These detect issues in ANY Node.js backend, not just Next.js
  // =============================================

  // Express/Fastify route without auth middleware
  // In Fastify: fastify.post('/path', handler) = no auth (bad)
  //             fastify.post('/path', { preHandler }, handler) = has auth (good)
  // In Express: app.post('/path', handler) = no auth (bad)
  //             app.post('/path', authMiddleware, handler) = has auth (good)
  // We flag write routes (POST/PUT/PATCH/DELETE) that go directly to a handler function
  {
    id: 1,
    name: "Express/Fastify Route Without Auth Middleware",
    severity: "high",
    category: "web-owasp",
    pattern: /(?:app|router|fastify)\s*\.(?:post|put|patch|delete)\s*\(\s*["']\/(?!health|webhook|public|auth|login|register|signup|stripe)[^"']*["']\s*,\s*(?:async\s+)?(?:\([^{)]*\)|(?:req|request|ctx))\s*(?:=>|{)/,
    fileFilter: /(?:route|controller|handler)/i,
    owasp: "A01:2021",
  },

  // CORS configured with wildcard in Express/Fastify
  {
    id: 50,
    name: "CORS Wildcard in Express/Fastify",
    severity: "medium",
    category: "web-owasp",
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|["']\*["'])/,
    owasp: "A05:2021",
  },

  // Error handler leaking stack traces
  {
    id: 173,
    name: "Error Handler Exposes Stack Trace",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:res|reply)\.(?:status|code)\s*\(\s*5\d\d\s*\)\.?\s*(?:json|send)\s*\(\s*\{[^}]*(?:stack|\.message|err\.toString)/,
    fileFilter: /(?:route|controller|handler|middleware|error)/i,
  },

  // Prisma $queryRaw / $executeRaw with template literals (SQL injection)
  {
    id: 5,
    name: "Prisma Raw Query with Template Literal",
    severity: "critical",
    category: "web-owasp",
    pattern: /prisma\.\$(?:queryRaw|executeRaw)\s*\(\s*`[^`]*\$\{/,
    owasp: "A03:2021",
  },

  // Missing HTTPS redirect
  {
    id: 66,
    name: "Server Without HTTPS/TLS Configuration",
    severity: "medium",
    category: "headers",
    pattern: /(?:\.listen\s*\(\s*\{[^}]*host\s*:\s*["']0\.0\.0\.0|http\.createServer)(?:(?!https|ssl|tls|cert)[\s\S]){0,500}/,
    // Exclude Next.js projects (behind Vercel/reverse proxy), Docker workers, etc.
    fileFilter: /(?:server|index|app)\.[tj]s$/,
    confidence: "low",
    // Suppressed when project has Dockerfile, vercel.json, railway.json, or next.config
    // (these deploy behind reverse proxies that handle TLS)
    suppressedByMiddleware: true,
  },

  // Sensitive data in URL params
  {
    id: 93,
    name: "Sensitive Data in URL Path or Query",
    severity: "medium",
    category: "frontend",
    pattern: /(?:redirect|url|href|location)\s*[=:]\s*[`"'][^`"']*(?:token=|password=|secret=|key=|api_key=|apiKey=)/i,
    owasp: "A07:2021",
  },

  // Console.log in production routes
  {
    id: 172,
    name: "Console.log with Sensitive Data in Route",
    severity: "medium",
    category: "error-logging",
    pattern: /console\.log\s*\([^)]*(?:password|token|secret|apiKey|api_key|authorization|cookie)/i,
    fileFilter: /(?:route|controller|handler|middleware)/i,
  },

  // =============================================
  // AI / LLM Security
  // =============================================
  {
    id: 75,
    name: "Prompt Injection — User Input in LLM Prompt",
    severity: "high",
    category: "ai-llm",
    // Match user input flowing into a prompt/messages template or a messages
    // array. The generic `content` variable name is intentionally NOT a
    // trigger: it collides with HTML/email/file "content" everywhere.
    pattern: /(?:prompt|messages)\s*[=:]\s*`[^`]*\$\{[^}]*(?:req\.|body\.|query\.|params\.|userInput|userMessage|userPrompt)|(?:messages\.push|\.concat)\s*\(\s*\{[^}]*(?:req\.|body\.|query\.|userInput|userMessage|userPrompt)/,
    // Only fire in files that actually talk to an LLM. Without this guard the
    // rule misfired on email/HTML templates that interpolate user input.
    requiresNearby: /anthropic|openai|\bllm\b|\bclaude\b|\bgpt-?\d|langchain|cohere|mistral|ollama|messages\.create|chat\.completions|completions\.create|generateText|streamText|role:\s*["'](?:system|user|assistant)["']/i,
    owasp: "A03:2021",
  },
  {
    id: 53,
    name: "PII Sent to External AI API",
    severity: "high",
    category: "ai-llm",
    // Only flag when PII fields are sent to known AI/LLM providers.
    // Internal APIs, email services (Resend, SendGrid), and non-AI fetches are safe.
    pattern: /(?:anthropic|openai|cohere|replicate|huggingface|ai\.run|completions\.create|messages\.create|chat\.completions)[\s\S]{0,200}(?:email|password|ssn|creditCard|phoneNumber|dateOfBirth|socialSecurity)/i,
    confidence: "medium",
  },
  {
    id: 53,
    name: "AI API Key Exposed in Frontend",
    severity: "critical",
    category: "ai-llm",
    pattern: /(?:NEXT_PUBLIC_|window\.|globalThis\.)(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|AI_API_KEY|CLAUDE_API_KEY)/,
    owasp: "A07:2021",
  },
  {
    id: 61,
    name: "AI-Generated Code Executed Dynamically",
    severity: "critical",
    category: "ai-llm",
    pattern: /(?:eval|Function|vm\.run)\s*\([^)]*(?:completion|response|aiOutput|generated|llmResult|chat)/i,
    owasp: "A03:2021",
  },

  // =============================================
  // Database Connection Security
  // =============================================
  {
    id: 101,
    name: "Database Connection Without SSL",
    severity: "high",
    category: "database-connection",
    pattern: /(?:createPool|createConnection|new\s+(?:Pool|Client|Sequelize|Knex))\s*\(\s*\{(?:(?!ssl|sslmode)[\s\S]){0,500}\}\s*\)/,
    fileFilter: /(?:db|database|prisma|knex|sequelize|connection|pool)/i,
  },
  {
    id: 148,
    name: "Database Publicly Accessible (0.0.0.0 Bind)",
    severity: "critical",
    category: "database-connection",
    pattern: /(?:bind_address|host|listen)\s*[=:]\s*["']0\.0\.0\.0["']/,
    fileFilter: /(?:config|docker|compose|\.env|yml|yaml)/,
  },
  {
    id: 101,
    name: "Default Database Credentials",
    severity: "critical",
    category: "database-connection",
    pattern: /(?:postgres:postgres|root:root|admin:admin|user:password|sa:sa|mysql:mysql)@/,
  },
  {
    id: 101,
    name: "Database Connection String with Inline Password",
    severity: "high",
    category: "database-connection",
    pattern: /(?:postgresql|mysql|mongodb|redis|amqp):\/\/\w+:[^@\s"']{3,}@(?!localhost|127\.0\.0\.1)/,
  },
  {
    id: 101,
    name: "MongoDB Connection Without Authentication",
    severity: "critical",
    category: "database-connection",
    pattern: /mongodb:\/\/(?!.*(?:authSource|auth_source))(?:\w+@)?(?:(?!localhost|127\.0\.0\.1)[\w.-]+)/,
  },
  {
    id: 101,
    name: "Redis Without Authentication",
    severity: "high",
    category: "database-connection",
    pattern: /(?:redis:\/\/(?!.*:.*@)|new\s+Redis\s*\(\s*\{(?:(?!password|auth)[\s\S]){0,300}\})(?:(?!localhost|127\.0\.0\.1)[\s\S]){0,100}/,
  },
  {
    id: 53,
    name: "Database Credentials Logged",
    severity: "high",
    category: "database-connection",
    pattern: /console\.(?:log|info|warn|error)\s*\([^)]*(?:DATABASE_URL|DB_PASSWORD|DB_HOST|connectionString|SUPABASE_SERVICE_ROLE)/,
  },
  {
    id: 2,
    name: "Database SSL Certificate Validation Disabled",
    severity: "high",
    category: "database-connection",
    pattern: /(?:ssl|tls)\s*:\s*\{[\s\S]*?rejectUnauthorized\s*:\s*false/,
  },
  {
    id: 101,
    name: "Hardcoded Database Host",
    severity: "medium",
    category: "database-connection",
    pattern: /(?:host|hostname)\s*[=:]\s*["'](?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w-]+\.(?:rds\.amazonaws\.com|database\.azure\.com|cloudsql\.google\.com|supabase\.co))["']/,
  },

  // =============================================
  // Cloud Provider Security
  // =============================================
  {
    id: 4,
    name: "S3 Bucket Public Access",
    severity: "critical",
    category: "cloud",
    pattern: /(?:BlockPublicAccess\s*[=:]\s*false|ACL\s*[=:]\s*["']public-read|s3:PutBucketPolicy[\s\S]{0,200}["']\*["'])/i,
    owasp: "A05:2021",
  },
  {
    id: 10,
    name: "Cloud Metadata SSRF Vector",
    severity: "critical",
    category: "cloud",
    pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)/,
    owasp: "A10:2021",
  },
  {
    id: 53,
    name: "AWS Credentials Hardcoded",
    severity: "critical",
    category: "cloud",
    pattern: /(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["'][A-Za-z0-9/+=]{20,}["']/i,
  },
  {
    id: 1,
    name: "IAM Policy Overly Permissive",
    severity: "high",
    category: "cloud",
    pattern: /["']Action["']\s*:\s*["']\*["'][\s\S]{0,100}["']Resource["']\s*:\s*["']\*["']/,
    fileFilter: /(?:policy|iam|role|permission|terraform|cdk|cloudformation)/i,
  },
  {
    id: 1,
    name: "Cloud Function Without Auth",
    severity: "high",
    category: "cloud",
    pattern: /(?:--allow-unauthenticated|allUsers|allAuthenticatedUsers|FunctionUrlAuthType\.NONE)/,
    fileFilter: /(?:serverless|template|cdk|terraform|yml|yaml)/,
  },

  // =============================================
  // Infrastructure as Code
  // =============================================
  {
    id: 53,
    name: "Terraform State File Committed",
    severity: "critical",
    category: "iac",
    pattern: /terraform\.tfstate|"serial"\s*:\s*\d+[\s\S]{0,100}"lineage"/,
    fileFilter: /(?:tfstate|terraform)/,
  },
  {
    id: 53,
    name: "Infrastructure Credentials in Code",
    severity: "critical",
    category: "iac",
    pattern: /(?:access_key|secret_key|api_token|subscription_id)\s*=\s*["'][^"']{10,}["']/,
    fileFilter: /\.(?:tf|hcl|yaml|yml)$/,
  },
  {
    id: 148,
    name: "Kubernetes Privileged Container",
    severity: "high",
    category: "iac",
    pattern: /privileged\s*:\s*true/,
    fileFilter: /\.(?:yaml|yml)$/,
  },
  {
    id: 53,
    name: "Helm/K8s Secrets in Plain Values",
    severity: "high",
    category: "iac",
    pattern: /(?:password|secret|token|apiKey)\s*:\s*["']?[A-Za-z0-9+/=]{8,}["']?/,
    fileFilter: /values\.ya?ml$/,
  },

  // =============================================
  // CI/CD Pipeline Security
  // =============================================
  {
    id: 140,
    name: "Unpinned GitHub Action",
    severity: "high",
    category: "cicd",
    pattern: /uses\s*:\s*[\w-]+\/[\w-]+@(?:main|master|latest|v\d+)\s*$/m,
    fileFilter: /\.github\/workflows\//,
  },
  {
    id: 75,
    name: "GitHub Actions Script Injection",
    severity: "critical",
    category: "cicd",
    pattern: /run\s*:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body|head\.ref)/,
    fileFilter: /\.github\/workflows\//,
    owasp: "A03:2021",
  },
  {
    id: 133,
    name: "Workflow Permissions Too Broad",
    severity: "medium",
    category: "cicd",
    pattern: /permissions\s*:\s*write-all/,
    fileFilter: /\.github\/workflows\//,
  },

  // =============================================
  // WebSocket & Real-time
  // =============================================
  {
    id: 1,
    name: "WebSocket Missing Origin Validation",
    severity: "high",
    category: "websocket",
    pattern: /(?:ws\.on|wss\.on|io\.on)\s*\(\s*["']connection["']\s*,(?:(?!verifyClient|origin|allowRequest)[\s\S]){0,500}/,
  },
  {
    id: 197,
    name: "WebSocket Without Message Rate Limiting",
    severity: "medium",
    category: "websocket",
    pattern: /(?:ws|socket)\.on\s*\(\s*["']message["']\s*,(?:(?!rateLimit|throttle|bucket)[\s\S]){0,500}/,
  },

  // =============================================
  // 1. ReDoS — Vulnerable Static Regex Patterns
  // Detect regex with nested quantifiers that cause catastrophic backtracking.
  // These are language-agnostic since all regex engines suffer from this.
  // =============================================
  {
    id: 91,
    name: "ReDoS — Nested Quantifiers in Regex",
    severity: "medium",
    category: "redos",
    pattern: /(?:new\s+RegExp|re\.compile|regexp\.MustCompile|Pattern\.compile|preg_match|Regex)\s*\(\s*["'`\/](?:[^"'`\/]*(?:\([^)]*[+*]\)[+*]|\([^)]*\|[^)]*\)[+*]))["'`\/]/,
    owasp: "A06:2021",
    confidence: "medium",
  },
  {
    id: 91,
    name: "ReDoS — Regex with Overlapping Alternation",
    severity: "medium",
    category: "redos",
    pattern: /(?:\/|["'`])(?:[^\/"'`]*(?:\(\?:[^)]+\|[^)]+\)\+|\([^)]+\)\{\d+,\}))(?:\/|["'`])/,
    fileFilter: /(?:\/api\/|\/server|\.server\.|route\.|controller|handler|middleware|validator|sanitiz)/i,
    owasp: "A06:2021",
    confidence: "low",
  },

  // =============================================
  // 2. Sensitive Data in Logs — Multi-language
  // Detect logging calls that include sensitive variable names.
  // =============================================

  // Python: print/logging with sensitive data
  {
    id: 172,
    name: "Sensitive Data Logged (Python)",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:print\s*\(|logging\.(?:info|warning|error|debug|critical)\s*\(|logger\.(?:info|warning|error|debug)\s*\()[^)]*(?:password|token|secret|api_key|apikey|authorization|credit_card|ssn|private_key)/i,
    fileFilter: /\.py$/,
    owasp: "A09:2021",
  },
  // Go: log/fmt with sensitive data
  {
    id: 172,
    name: "Sensitive Data Logged (Go)",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:log\.(?:Print|Printf|Println|Fatal|Fatalf)\s*\(|fmt\.(?:Print|Printf|Println|Fprintf)\s*\()[^)]*(?:password|token|secret|apiKey|api_key|authorization|creditCard|ssn|privateKey)/i,
    fileFilter: /\.go$/,
    owasp: "A09:2021",
  },
  // Java: logger/System.out with sensitive data
  {
    id: 172,
    name: "Sensitive Data Logged (Java)",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:logger\.(?:info|warn|error|debug)\s*\(|System\.out\.print(?:ln)?\s*\(|Log\.(?:d|e|i|w|v)\s*\()[^)]*(?:password|token|secret|apiKey|api_key|authorization|creditCard|ssn|privateKey)/i,
    fileFilter: /\.(?:java|kt)$/,
    owasp: "A09:2021",
  },
  // PHP: error_log/var_dump with sensitive data
  {
    id: 172,
    name: "Sensitive Data Logged (PHP)",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:error_log\s*\(|var_dump\s*\(|print_r\s*\(|Log::(?:info|warning|error|debug)\s*\()[^)]*(?:password|token|secret|api_key|apikey|authorization|credit_card|ssn|private_key)/i,
    fileFilter: /\.php$/,
    owasp: "A09:2021",
  },
  // C#: logger/Console with sensitive data
  {
    id: 172,
    name: "Sensitive Data Logged (C#)",
    severity: "medium",
    category: "error-logging",
    pattern: /(?:Console\.Write(?:Line)?\s*\(|_logger\.Log(?:Information|Warning|Error|Debug)?\s*\(|Debug\.(?:Log|Write)\s*\()[^)]*(?:password|token|secret|apiKey|api_key|authorization|creditCard|ssn|privateKey)/i,
    fileFilter: /\.cs$/,
    owasp: "A09:2021",
  },

  // =============================================
  // 3. Insecure Randomness — Multi-language
  // Detect non-cryptographic RNG used for security-sensitive values.
  // =============================================

  // Python: random module for security
  {
    id: 125,
    name: "Insecure Random for Security Purpose (Python)",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|nonce|salt|otp|password|code)[\s\S]{0,40}random\.(?:random|randint|choice|randrange|getrandbits)\s*\(/i,
    fileFilter: /\.py$/,
    owasp: "A02:2021",
  },
  // Go: math/rand for security
  {
    id: 125,
    name: "Insecure Random for Security Purpose (Go)",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|nonce|salt|otp|password)[\s\S]{0,40}(?:rand\.(?:Int|Intn|Float|Read|New)\s*\(|"math\/rand")/i,
    fileFilter: /\.go$/,
    owasp: "A02:2021",
  },
  // Java: java.util.Random for security
  {
    id: 125,
    name: "Insecure Random for Security Purpose (Java)",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|nonce|salt|otp|password)[\s\S]{0,40}(?:new\s+Random\s*\(|ThreadLocalRandom\.current\(\)\.next|Random\(\)\.next)/i,
    fileFilter: /\.(?:java|kt)$/,
    owasp: "A02:2021",
  },
  // PHP: rand/mt_rand for security
  {
    id: 125,
    name: "Insecure Random for Security Purpose (PHP)",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|nonce|salt|otp|password)[\s\S]{0,40}(?:rand\s*\(|mt_rand\s*\(|array_rand\s*\(|shuffle\s*\()/i,
    fileFilter: /\.php$/,
    owasp: "A02:2021",
  },
  // C#: System.Random for security
  {
    id: 125,
    name: "Insecure Random for Security Purpose (C#)",
    severity: "high",
    category: "cryptography",
    pattern: /(?:token|secret|key|session|nonce|salt|otp|password)[\s\S]{0,40}(?:new\s+Random\s*\(|Random\.Shared\.Next)/i,
    fileFilter: /\.cs$/,
    owasp: "A02:2021",
  },

  // =============================================
  // 4. Hardcoded Internal IPs & Staging URLs
  // Detect private IPs and dev/staging URLs in production code.
  // =============================================
  {
    id: 4,
    name: "Hardcoded Internal IP Address",
    severity: "low",
    category: "misconfiguration",
    pattern: /["'`]https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?/,
    owasp: "A05:2021",
    confidence: "medium",
  },
  {
    id: 4,
    name: "Hardcoded Localhost URL in Source",
    severity: "low",
    category: "misconfiguration",
    pattern: /["'`]https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?(?:\/[^"'`]*)?["'`]/,
    // Only flag in source files that are likely production code, not config/env/docker
    fileFilter: /(?:\/api\/|\/lib\/|\/src\/|\/app\/|\/server|route\.|controller|service|handler)/i,
    owasp: "A05:2021",
    confidence: "low",
  },
  {
    id: 4,
    name: "Staging/Dev URL Hardcoded in Source",
    severity: "low",
    category: "misconfiguration",
    pattern: /["'`]https?:\/\/(?:staging|dev|test|qa|uat|sandbox|preprod|stg)[\.-]/i,
    // Exclude test/config files where these URLs are expected
    fileFilter: /(?:\/api\/|\/lib\/|\/src\/|\/app\/|\/server|route\.|controller|service|handler)/i,
    owasp: "A05:2021",
    confidence: "low",
  },

  // =============================================
  // 5. Mass Assignment — Multi-language
  // Detect request body spread directly into database operations.
  // =============================================

  // Python: **request.data or Model(**data) without whitelist
  {
    id: 98,
    name: "Mass Assignment — Request Data to Model (Python)",
    severity: "high",
    category: "api",
    pattern: /(?:Model|\.objects\.create|\.objects\.update|serializer\.save|\.update_or_create)\s*\(\s*\*\*\s*(?:request\.data|request\.POST|data|kwargs)/,
    fileFilter: /\.py$/,
    owasp: "A08:2021",
  },
  // Go: json.Decode directly into DB model without field whitelist
  {
    id: 98,
    name: "Mass Assignment — JSON Decode to Model (Go)",
    severity: "high",
    category: "api",
    pattern: /json\.NewDecoder\s*\([^)]*\)\.Decode\s*\(\s*&\s*\w+\s*\)[\s\S]{0,100}(?:\.Create|\.Save|\.Update|\.Insert|db\.Exec)/,
    fileFilter: /\.go$/,
    owasp: "A08:2021",
    confidence: "low",
  },
  // PHP: $request->all() passed to create/update
  {
    id: 98,
    name: "Mass Assignment — Request All to Model (PHP)",
    severity: "high",
    category: "api",
    pattern: /(?:::create|::update|->fill|->update|->insert)\s*\(\s*\$request->all\s*\(\s*\)/,
    fileFilter: /\.php$/,
    owasp: "A08:2021",
  },
  // Java: @ModelAttribute without @Valid or BindingResult
  {
    id: 98,
    name: "Mass Assignment — Unvalidated Model Binding (Java)",
    severity: "medium",
    category: "api",
    pattern: /@ModelAttribute\s+(?:(?!@Valid|BindingResult)[\s\S]){0,100}(?:save|update|create|persist)/,
    fileFilter: /\.(?:java|kt)$/,
    owasp: "A08:2021",
    confidence: "low",
  },
];

export function analyzePatterns(
  files: Map<string, string>
): FindingData[] {
  const allFindings: FindingData[] = [];

  // Pre-scan: detect project-level security infrastructure
  const projectFeatures = detectProjectFeatures(files);

  for (const [filePath, content] of files) {
    for (const rule of PATTERN_RULES) {
      // Apply file filter if defined
      if (rule.fileFilter && !rule.fileFilter.test(filePath)) continue;

      // Skip non-source files
      if (!isSourceFile(filePath)) continue;

      // Skip rules suppressed by project-level middleware/infrastructure
      if (rule.suppressedByMiddleware && projectFeatures.hasMiddlewareRateLimit) continue;

      // Require corroborating context in the same file, if the rule demands it
      if (rule.requiresNearby) {
        rule.requiresNearby.lastIndex = 0;
        if (!rule.requiresNearby.test(content)) continue;
      }

      // Reset regex state
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(content);

      if (match) {
        const lineNumber = getLineNumber(content, match.index);
        const snippet = getSnippet(content, lineNumber);

        allFindings.push({
          vulnerability_id: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.name,
          file_path: filePath,
          line_number: lineNumber,
          code_snippet: snippet,
          owasp_ref: rule.owasp,
          status: "open",
          confidence: rule.confidence ?? "medium",
        });
      }
    }
  }

  // File-level special checks — dangerouslySetInnerHTML with file-level context
  runDangerousHtmlChecks(files, allFindings);

  // File-level absence checks — detect when a project is MISSING security features
  runAbsenceChecks(files, allFindings);

  return allFindings;
}

interface ProjectFeatures {
  hasMiddlewareRateLimit: boolean;
  hasReverseProxy: boolean;
  hasGlobalAuth: boolean;        // Project has global auth middleware/config
  hasGlobalCors: boolean;        // Project has CORS configured centrally
  hasHelmet: boolean;            // Project uses helmet or similar security headers lib
  hasInputValidation: boolean;   // Project uses Zod, Joi, class-validator, etc.
}

/**
 * Detect project-level security infrastructure that makes per-route checks redundant.
 * For example, if middleware.ts handles rate limiting, individual API routes
 * don't need their own rate limiting.
 */
function detectProjectFeatures(files: Map<string, string>): ProjectFeatures {
  let hasMiddlewareRateLimit = false;
  let hasReverseProxy = false;
  let hasGlobalAuth = false;
  let hasGlobalCors = false;
  let hasHelmet = false;
  let hasInputValidation = false;

  for (const [filePath, content] of files) {
    const fileName = filePath.split("/").pop() || "";

    // === Rate Limiting Detection ===
    // Next.js middleware
    if (/middleware\.[tj]sx?$/.test(fileName) || /rate.?limit/i.test(fileName)) {
      if (/rateLimit|rate.?limit|throttle|limiter|req.*per.*(?:min|sec|hour|window)/i.test(content)) {
        hasMiddlewareRateLimit = true;
      }
    }
    // Express/Fastify global middleware
    if (/app\.use\s*\(\s*(?:rateLimit|rateLimiter|createRateLimiter|slowDown)/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }
    // Django rate limiting
    if (/django[_-]ratelimit|rest_framework\.throttling|DEFAULT_THROTTLE_CLASSES/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }
    // Spring Boot rate limiting
    if (/RateLimiter|bucket4j|resilience4j|Bucket4j|@RateLimited/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }
    // Laravel rate limiting
    if (/RateLimiter::for|ThrottleRequests|throttle:/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }
    // Go rate limiting
    if (/golang\.org\/x\/time\/rate|rate\.NewLimiter|httprate|tollbooth/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }
    // ASP.NET rate limiting
    if (/AddRateLimiter|UseRateLimiter|RateLimiting/i.test(content)) {
      hasMiddlewareRateLimit = true;
    }

    // === Global Auth Detection ===
    // Next.js / Express middleware auth
    if (/middleware\.[tj]sx?$/.test(fileName)) {
      if (/auth|session|getUser|getSession|verifyAuth|requireAuth/i.test(content)) {
        hasGlobalAuth = true;
      }
    }
    // Express passport / auth middleware
    if (/app\.use\s*\(\s*(?:passport|authenticate|requireAuth|verifyToken|authMiddleware|isAuthenticated)/i.test(content)) {
      hasGlobalAuth = true;
    }
    // Django auth middleware
    if (/AuthenticationMiddleware|LoginRequiredMiddleware|REST_FRAMEWORK.*DEFAULT_PERMISSION_CLASSES.*IsAuthenticated/i.test(content)) {
      hasGlobalAuth = true;
    }
    // Spring Security
    if (/@EnableWebSecurity|@EnableGlobalMethodSecurity|@EnableMethodSecurity|WebSecurityConfigurerAdapter|SecurityFilterChain/i.test(content)) {
      hasGlobalAuth = true;
    }
    // Laravel auth middleware in kernel
    if (/Kernel\.php|bootstrap\/app/i.test(filePath)) {
      if (/Authenticate::class|'auth'|auth:sanctum|auth:api/i.test(content)) {
        hasGlobalAuth = true;
      }
    }
    // Go auth middleware
    if (/authMiddleware|RequireAuth|JWTMiddleware|AuthRequired/i.test(content) && /\.Use\s*\(|\.With\s*\(/i.test(content)) {
      hasGlobalAuth = true;
    }
    // ASP.NET auth
    if (/AddAuthentication|UseAuthentication|AddAuthorization|UseAuthorization/i.test(content)) {
      hasGlobalAuth = true;
    }

    // === CORS Detection ===
    if (/helmet|cors\s*\(\s*\{|CORS_ALLOWED_ORIGINS|@CrossOrigin|AllowedOrigins|WithOrigins/i.test(content)) {
      hasGlobalCors = true;
    }

    // === Security Headers (helmet, etc.) ===
    if (/import.*helmet|require.*helmet|app\.use\s*\(\s*helmet/i.test(content)) {
      hasHelmet = true;
    }
    if (/SecurityHeadersMiddleware|SECURE_HSTS|X-Content-Type-Options|ContentSecurityPolicy/i.test(content)) {
      hasHelmet = true;
    }

    // === Input Validation Detection ===
    if (/import.*(?:zod|joi|yup|class-validator|superstruct|valibot|ajv)/i.test(content)) {
      hasInputValidation = true;
    }
    if (/@Valid|@Validated|@RequestBody.*@Valid|ValidationPipe/i.test(content)) {
      hasInputValidation = true;
    }

    // === Reverse Proxy Detection ===
    if (fileName === "Dockerfile" || fileName === "vercel.json" || fileName === "railway.json" ||
        fileName === "next.config.ts" || fileName === "next.config.js" || fileName === "next.config.mjs" ||
        fileName === "nginx.conf" || fileName === "Caddyfile" || fileName === "traefik.yml") {
      hasReverseProxy = true;
    }
  }

  return { hasMiddlewareRateLimit, hasReverseProxy, hasGlobalAuth, hasGlobalCors, hasHelmet, hasInputValidation };
}

// Safe sources for dangerouslySetInnerHTML at the file level.
// If the file imports/uses any of these, the HTML content is trusted.
const SAFE_HTML_SOURCES = [
  /import.*(?:codeToHtml|shiki|highlight|rehype|remark)/,  // Syntax highlighters
  /import.*DOMPurify/,                                       // Sanitizers
  /(?:codeToHtml|highlightCode|highlight)\s*\(/,             // Highlighter calls
  /DOMPurify\.sanitize\s*\(/,                                // Sanitizer calls
  /JSON\.stringify\s*\(/,                                     // JSON-LD serialization
  /application\/ld\+json/,                                    // JSON-LD script tags
  /compileMDX|serialize|bundleMDX|getPostBySlug|\.mdx?$/i,   // MDX/Markdown compiled content
];

/**
 * File-level dangerouslySetInnerHTML check.
 * Instead of checking the single line, we check the entire file for
 * safe content sources (Shiki, DOMPurify, MDX, JSON-LD, etc.).
 * Only flags dangerouslySetInnerHTML when the file has NO safe source indicators.
 */
function runDangerousHtmlChecks(files: Map<string, string>, findings: FindingData[]): void {
  for (const [filePath, content] of files) {
    if (!/\.(?:tsx|jsx)$/.test(filePath)) continue;

    const htmlMatch = /dangerouslySetInnerHTML\s*=\s*\{\s*\{.*__html/.exec(content);
    if (!htmlMatch) continue;

    // Check if the file uses any safe HTML source
    const hasSafeSource = SAFE_HTML_SOURCES.some((pattern) => pattern.test(content));
    if (hasSafeSource) continue;

    const lineNumber = getLineNumber(content, htmlMatch.index);
    const snippet = getSnippet(content, lineNumber);

    findings.push({
      vulnerability_id: 46,
      severity: "high",
      category: "react-nextjs",
      title: "dangerouslySetInnerHTML Without Sanitization",
      file_path: filePath,
      line_number: lineNumber,
      code_snippet: snippet,
      owasp_ref: "A03:2021",
      status: "open",
      confidence: "medium",
    });
  }
}

/**
 * Absence checks: scan across ALL files to detect when a project is
 * missing security headers middleware, rate limiting, etc.
 * These can't be done per-file — we need to look at the whole project.
 */
function runAbsenceChecks(files: Map<string, string>, findings: FindingData[]): void {
  let hasExpressOrFastify = false;
  let hasHelmet = false;
  let hasRateLimiting = false;
  let hasCors = false;
  let appFile = "";
  let appFileLine = 0;

  for (const [filePath, content] of files) {
    // Detect the main app/server file (prefer src/ over __tests__/)
    if (/(?:express\s*\(\)|Fastify\s*\(|new\s+Hono|new\s+Koa)/.test(content)) {
      hasExpressOrFastify = true;
      const isTestFile = /(?:__tests__|\.test\.|\.spec\.|test\/|tests\/)/.test(filePath);
      if (!appFile || (isTestFile === false && /(?:__tests__|\.test\.|\.spec\.)/.test(appFile))) {
        appFile = filePath;
        const match = content.match(/(?:express\s*\(\)|Fastify\s*\(|new\s+Hono|new\s+Koa)/);
        appFileLine = match ? getLineNumber(content, match.index!) : 1;
      }
    }

    // Check for security middleware across all files
    if (/helmet|@fastify\/helmet|secure-headers/i.test(content)) hasHelmet = true;
    if (/rateLimit|rate-limit|@fastify\/rate-limit|express-rate-limit|throttle|RateLimiter/i.test(content)) hasRateLimiting = true;
    if (/cors|@fastify\/cors/i.test(content)) hasCors = true;
  }

  if (hasExpressOrFastify && !hasHelmet) {
    findings.push({
      vulnerability_id: 4,
      severity: "medium",
      category: "web-owasp",
      title: "No Security Headers Middleware (Helmet)",
      description_technical: "No helmet or security headers middleware detected. This leaves the app without security headers like X-Frame-Options, X-Content-Type-Options, CSP, etc.",
      file_path: appFile,
      line_number: appFileLine,
      code_snippet: "// Add: app.use(helmet()) or fastify.register(helmet)",
      owasp_ref: "A05:2021",
      status: "open",
      confidence: "low",
    });
  }

  if (hasExpressOrFastify && !hasRateLimiting) {
    findings.push({
      vulnerability_id: 197,
      severity: "medium",
      category: "api",
      title: "No Rate Limiting Middleware Detected",
      description_technical: "No rate limiting middleware detected in the project. This makes the API vulnerable to brute-force attacks, DDoS, and abuse.",
      file_path: appFile,
      line_number: appFileLine,
      code_snippet: "// Add: app.use(rateLimit({ ... })) or fastify.register(rateLimitPlugin)",
      owasp_ref: "A04:2023",
      status: "open",
      confidence: "low",
    });
  }
}

function isSourceFile(filePath: string): boolean {
  const extensions = [
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sql", ".json",
    ".py", ".go", ".java", ".kt", ".php", ".cs", ".rb", ".rs", ".swift",
    ".properties", ".yml", ".yaml",
  ];
  return extensions.some((ext) => filePath.endsWith(ext));
}

function getLineNumber(content: string, charIndex: number): number {
  return content.substring(0, charIndex).split("\n").length;
}

function getSnippet(content: string, lineNumber: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNumber - 2);
  const end = Math.min(lines.length, lineNumber + 2);
  return lines.slice(start, end).join("\n");
}
