// URL scanner engine - checks deployed app for security headers, SSL, cookies
// Makes HTTP requests to the target URL and analyzes the response

import type { FindingData } from "./types.js";

interface HeaderCheck {
  id: number;
  header: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  expectedPresent: boolean;
  valuePredicate?: (value: string) => boolean;
  category: string;
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    id: 63,
    header: "content-security-policy",
    name: "Missing Content Security Policy",
    severity: "medium",
    expectedPresent: true,
    category: "headers",
  },
  {
    id: 64,
    header: "x-frame-options",
    name: "Missing X-Frame-Options",
    severity: "medium",
    expectedPresent: true,
    category: "headers",
  },
  {
    id: 65,
    header: "x-content-type-options",
    name: "Missing X-Content-Type-Options",
    severity: "low",
    expectedPresent: true,
    category: "headers",
  },
  {
    id: 66,
    header: "strict-transport-security",
    name: "Missing HSTS Header",
    severity: "medium",
    expectedPresent: true,
    category: "headers",
  },
  {
    id: 251,
    header: "referrer-policy",
    name: "Missing Referrer-Policy Header",
    severity: "low",
    expectedPresent: true,
    category: "headers",
  },
];

export async function scanUrl(appUrl: string): Promise<FindingData[]> {
  const findings: FindingData[] = [];

  try {
    // Fetch the URL with a timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(appUrl, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "DataHogo-Scanner/1.0",
      },
    });

    clearTimeout(timeout);

    const body = (await response.text()).substring(0, 512_000);
    const finalUrl = response.url || appUrl;

    // Check security headers
    for (const check of HEADER_CHECKS) {
      const headerValue = response.headers.get(check.header);

      if (check.expectedPresent && !headerValue) {
        findings.push({
          vulnerability_id: check.id,
          severity: check.severity,
          category: check.category,
          title: check.name,
          description_technical: `The ${check.header} header is not set on ${appUrl}`,
          code_snippet: `Response headers missing: ${check.header}`,
          status: "open",
        });
      }

      if (headerValue && check.valuePredicate && !check.valuePredicate(headerValue)) {
        findings.push({
          vulnerability_id: check.id,
          severity: check.severity,
          category: check.category,
          title: check.name,
          description_technical: `The ${check.header} header has a weak value: ${headerValue}`,
          code_snippet: `${check.header}: ${headerValue}`,
          status: "open",
        });
      }
    }

    // Deep CSP analysis (when header IS present)
    const csp = response.headers.get("content-security-policy");
    if (csp) {
      analyzeCspPolicy(csp, findings);
    }

    // Server version disclosure
    const serverHeader = response.headers.get("server");
    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      findings.push({
        vulnerability_id: 4,
        severity: "low",
        category: "headers",
        title: "Server Version Disclosed",
        description_technical: `The Server header reveals version info: ${serverHeader}`,
        code_snippet: `Server: ${serverHeader}`,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }

    // X-Powered-By disclosure
    const poweredBy = response.headers.get("x-powered-by");
    if (poweredBy) {
      findings.push({
        vulnerability_id: 4,
        severity: "low",
        category: "headers",
        title: "X-Powered-By Header Disclosed",
        description_technical: `The X-Powered-By header reveals technology: ${poweredBy}`,
        code_snippet: `X-Powered-By: ${poweredBy}`,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }

    // Check cookies
    const setCookieHeaders = response.headers.getSetCookie?.() ?? [];
    for (const cookie of setCookieHeaders) {
      // Extract just the cookie name (everything before the first '=')
      const cookieName = cookie.split("=")[0].trim();

      // Skip cookies managed by frameworks that intentionally omit HttpOnly because
      // client-side JS must read them (Supabase Auth for session refresh, next-intl
      // for locale sync via <Link>). Flagging these creates noise, not actionable findings.
      const isFrameworkCookie =
        cookieName.startsWith("sb-") ||
        cookieName.startsWith("__supabase") ||
        cookieName === "NEXT_LOCALE";

      if (isFrameworkCookie) continue;

      if (!cookie.toLowerCase().includes("secure")) {
        findings.push({
          vulnerability_id: 67,
          severity: "medium",
          category: "headers",
          title: "Cookie Without Secure Flag",
          code_snippet: maskCookieValue(cookie),
          status: "open",
        });
      }

      if (!cookie.toLowerCase().includes("httponly")) {
        findings.push({
          vulnerability_id: 68,
          severity: "medium",
          category: "headers",
          title: "Cookie Without HttpOnly Flag",
          code_snippet: maskCookieValue(cookie),
          status: "open",
        });
      }
      if (!cookie.toLowerCase().includes("samesite")) {
        findings.push({
          vulnerability_id: 69,
          severity: "medium",
          category: "headers",
          title: "Cookie Without SameSite Attribute",
          code_snippet: maskCookieValue(cookie),
          status: "open",
        });
      }
    }

    // Check if source maps are accessible
    await checkSourceMaps(appUrl, findings);

    // Check for exposed API docs
    await checkExposedEndpoints(appUrl, findings);

    // Check HTTP to HTTPS redirect
    if (appUrl.startsWith("https://")) {
      const httpUrl = appUrl.replace("https://", "http://");
      try {
        const httpResponse = await fetch(httpUrl, {
          method: "HEAD",
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
        });
        const location = httpResponse.headers.get("location");
        if (!location || !location.startsWith("https://")) {
          findings.push({
            vulnerability_id: 66,
            severity: "medium",
            category: "headers",
            title: "HTTP Does Not Redirect to HTTPS",
            description_technical: `${httpUrl} does not redirect to HTTPS`,
            status: "open",
          });
        }
      } catch {
        // HTTP not accessible - that's fine
      }
    }

    // Mixed Content (ID 252) — HTTPS page loading HTTP subresources
    if (finalUrl.startsWith("https://")) {
      const mixedMatches = [...body.matchAll(/(src|href|action)\s*=\s*["']http:\/\/[^"']+["']/gi)]
        .filter((m) => !m[0].includes("http://www.w3.org") && !m[0].includes("http://xmlns"))
        .slice(0, 3);
      if (mixedMatches.length > 0) {
        findings.push({
          vulnerability_id: 252,
          severity: "medium",
          category: "headers",
          title: "Mixed Content Detected",
          description_technical: `HTTPS page loads subresources over HTTP, exposing them to interception`,
          code_snippet: mixedMatches.map((m) => m[0]).join("\n"),
          owasp_ref: "A05:2021",
          status: "open",
        });
      }
    }

    // Form Action Insecure (ID 253) — forms posting over HTTP from an HTTPS page
    if (finalUrl.startsWith("https://")) {
      const formMatches = [...body.matchAll(/<form[^>]*action\s*=\s*["']http:\/\/[^"']+["'][^>]*>/gi)]
        .slice(0, 3);
      if (formMatches.length > 0) {
        findings.push({
          vulnerability_id: 253,
          severity: "medium",
          category: "headers",
          title: "Form Action Uses Insecure HTTP URL",
          description_technical: `One or more HTML forms post data to an HTTP URL, exposing submitted data in transit`,
          code_snippet: formMatches.map((m) => m[0]).join("\n"),
          status: "open",
        });
      }
    }

    // Protocol-Relative Links (ID 254)
    const protoRelativeMatches = [...body.matchAll(/(src|href)\s*=\s*["']\/\/[^"']+["']/gi)]
      .slice(0, 3);
    if (protoRelativeMatches.length > 0) {
      findings.push({
        vulnerability_id: 254,
        severity: "low",
        category: "headers",
        title: "Protocol-Relative Links Detected",
        description_technical: `Page uses protocol-relative URLs (//example.com), which inherit the page protocol and can load resources over HTTP`,
        code_snippet: protoRelativeMatches.map((m) => m[0]).join("\n"),
        status: "open",
      });
    }

    // Bad Content-Type (ID 255)
    const contentType = response.headers.get("content-type");
    const urlPath = (() => {
      try {
        return new URL(finalUrl).pathname;
      } catch {
        return finalUrl;
      }
    })();
    const isLikelyHtmlPage =
      urlPath === "/" ||
      urlPath === "" ||
      urlPath.endsWith(".html") ||
      urlPath.endsWith(".htm") ||
      !urlPath.includes(".");
    if (isLikelyHtmlPage) {
      if (!contentType) {
        findings.push({
          vulnerability_id: 255,
          severity: "low",
          category: "headers",
          title: "Missing Content-Type Header",
          description_technical: `The response does not include a Content-Type header, leaving browsers to sniff the content type`,
          code_snippet: `Content-Type header absent for ${finalUrl}`,
          status: "open",
        });
      } else if (!contentType.includes("text/html")) {
        findings.push({
          vulnerability_id: 255,
          severity: "low",
          category: "headers",
          title: "Unexpected Content-Type for Web Page",
          description_technical: `Expected text/html for this URL but received: ${contentType}`,
          code_snippet: `Content-Type: ${contentType}`,
          status: "open",
        });
      }
    }

  } catch (error) {
    // URL unreachable - not a finding, just means we can't scan
    // The caller should handle this gracefully
  }

  return findings;
}

async function checkSourceMaps(baseUrl: string, findings: FindingData[]): Promise<void> {
  const mapPaths = [
    "/_next/static/chunks/main.js.map",
    "/static/js/main.js.map",
    "/bundle.js.map",
  ];

  for (const path of mapPaths) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok) {
        findings.push({
          vulnerability_id: 49,
          severity: "medium",
          category: "react-nextjs",
          title: "Source Maps Accessible in Production",
          description_technical: `Source map file accessible at ${path}`,
          code_snippet: `GET ${path} → ${response.status}`,
          status: "open",
        });
        break; // One finding is enough
      }
    } catch {
      // Not accessible - good
    }
  }
}

async function checkExposedEndpoints(baseUrl: string, findings: FindingData[]): Promise<void> {
  const endpoints = [
    { path: "/swagger", id: 94, severity: "low" as const },
    { path: "/api-docs", id: 94, severity: "low" as const },
    { path: "/swagger-ui.html", id: 94, severity: "low" as const },
    { path: "/graphql", id: 95, severity: "low" as const },
    { path: "/debug", id: 116, severity: "medium" as const },
    { path: "/_debug", id: 116, severity: "medium" as const },
    { path: "/.env", id: 62, severity: "critical" as const },
    { path: "/.git/HEAD", id: 62, severity: "critical" as const },
    { path: "/.git/config", id: 62, severity: "critical" as const },
    { path: "/server-status", id: 116, severity: "medium" as const },
    { path: "/server-info", id: 116, severity: "medium" as const },
    { path: "/actuator", id: 116, severity: "medium" as const },
    { path: "/actuator/health", id: 116, severity: "low" as const },
    { path: "/phpinfo.php", id: 116, severity: "medium" as const },
    { path: "/wp-admin", id: 116, severity: "low" as const },
    { path: "/wp-login.php", id: 116, severity: "low" as const },
    { path: "/.DS_Store", id: 99, severity: "low" as const },
    { path: "/robots.txt", id: 99, severity: "info" as const },
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(`${baseUrl}${endpoint.path}`, {
        method: "GET",
        signal: AbortSignal.timeout(5000),
        headers: { "User-Agent": "DataHogo-Scanner/1.0" },
      });
      if (response.ok) {
        findings.push({
          vulnerability_id: endpoint.id,
          severity: endpoint.severity,
          category: endpoint.id === 62 ? "vibecoding" : endpoint.id === 95 ? "api" : "config",
          title: `Exposed Endpoint: ${endpoint.path}`,
          description_technical: `${endpoint.path} is publicly accessible and returned HTTP ${response.status}`,
          code_snippet: `GET ${endpoint.path} → ${response.status} OK`,
          owasp_ref: endpoint.id === 62 ? "A07:2021" : "A05:2021",
          status: "open",
        });
      }
    } catch {
      // Not accessible - fine
    }
  }

  // CORS preflight test — check if server reflects arbitrary origins
  await checkCorsPreflight(baseUrl, findings);
}

function maskCookieValue(cookie: string): string {
  // Mask the cookie value, keep the name and attributes
  return cookie.replace(/=([^;]{10,})/, "=***REDACTED***");
}

function analyzeCspPolicy(csp: string, findings: FindingData[]): void {
  const directives = csp.split(";").map((d) => d.trim().toLowerCase());

  for (const directive of directives) {
    // Check for unsafe-inline in script-src
    if (directive.startsWith("script-src") && directive.includes("'unsafe-inline'")) {
      findings.push({
        vulnerability_id: 63,
        severity: "medium",
        category: "headers",
        title: "CSP Allows unsafe-inline Scripts",
        description_technical: "Content-Security-Policy script-src includes 'unsafe-inline', enabling inline script execution",
        code_snippet: directive,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }

    // Check for unsafe-eval in script-src
    if (directive.startsWith("script-src") && directive.includes("'unsafe-eval'")) {
      findings.push({
        vulnerability_id: 63,
        severity: "high",
        category: "headers",
        title: "CSP Allows unsafe-eval Scripts",
        description_technical: "Content-Security-Policy script-src includes 'unsafe-eval', enabling eval() execution",
        code_snippet: directive,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }

    // Check for wildcard in any source directive
    if (directive.includes(" *") && !directive.includes("*.")) {
      findings.push({
        vulnerability_id: 63,
        severity: "medium",
        category: "headers",
        title: "CSP Contains Wildcard Source",
        description_technical: "Content-Security-Policy contains a wildcard (*) source, allowing resources from any origin",
        code_snippet: directive,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }
  }

  // Check for missing frame-ancestors (clickjacking protection)
  const hasFrameAncestors = directives.some((d) => d.startsWith("frame-ancestors"));
  if (!hasFrameAncestors) {
    findings.push({
      vulnerability_id: 64,
      severity: "low",
      category: "headers",
      title: "CSP Missing frame-ancestors Directive",
      description_technical: "Content-Security-Policy does not include frame-ancestors, relying on X-Frame-Options for clickjacking protection",
      code_snippet: `CSP: ${csp.substring(0, 200)}${csp.length > 200 ? "..." : ""}`,
      status: "open",
    });
  }
}

async function checkCorsPreflight(baseUrl: string, findings: FindingData[]): Promise<void> {
  try {
    const response = await fetch(baseUrl, {
      method: "OPTIONS",
      signal: AbortSignal.timeout(5000),
      headers: {
        "User-Agent": "DataHogo-Scanner/1.0",
        Origin: "https://evil-attacker.com",
        "Access-Control-Request-Method": "GET",
      },
    });

    const allowOrigin = response.headers.get("access-control-allow-origin");
    if (allowOrigin === "*" || allowOrigin === "https://evil-attacker.com") {
      findings.push({
        vulnerability_id: 4,
        severity: "medium",
        category: "headers",
        title: "CORS Reflects Arbitrary Origins",
        description_technical: `Server reflects arbitrary Origin in Access-Control-Allow-Origin: ${allowOrigin}`,
        code_snippet: `OPTIONS ${baseUrl}\nOrigin: https://evil-attacker.com\n→ Access-Control-Allow-Origin: ${allowOrigin}`,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }

    const allowCredentials = response.headers.get("access-control-allow-credentials");
    if (allowCredentials === "true" && (allowOrigin === "*" || allowOrigin === "https://evil-attacker.com")) {
      findings.push({
        vulnerability_id: 4,
        severity: "high",
        category: "headers",
        title: "CORS Allows Credentials from Any Origin",
        description_technical: "Server allows credentials (cookies) from arbitrary origins — critical cross-origin data theft risk",
        code_snippet: `Access-Control-Allow-Origin: ${allowOrigin}\nAccess-Control-Allow-Credentials: true`,
        owasp_ref: "A05:2021",
        status: "open",
      });
    }
  } catch {
    // CORS preflight not supported or request failed — fine
  }
}
