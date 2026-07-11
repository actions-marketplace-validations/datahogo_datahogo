import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { scanUrl } from "./url-scanner.js";

describe("scanUrl", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("when all security headers are absent", () => {
    it("returns missing header findings for CSP, X-Frame-Options, X-Content-Type-Options, HSTS, and Referrer-Policy", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string, options?: any) => {
        const urlStr = url.toString();
        // Main HTTPS request - return response with no headers
        if (urlStr === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        // HTTP redirect check - fail (not accessible)
        if (urlStr === "http://example.com") {
          return Promise.reject(new Error("Not found"));
        }
        // Source maps, exposed endpoints - all fail (not accessible)
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - should have the 5 missing header findings (4 original + Referrer-Policy)
      // Plus Missing Content-Type (ID 255) since no content-type header is set
      const missingHeaderFindings = findings.filter(
        (f) => [63, 64, 65, 66, 251].includes(f.vulnerability_id) && f.title.startsWith("Missing")
      );
      expect(missingHeaderFindings).toHaveLength(5);
      expect(findings.some((f) => f.vulnerability_id === 63)).toBe(true); // CSP
      expect(findings.some((f) => f.vulnerability_id === 64)).toBe(true); // X-Frame-Options
      expect(findings.some((f) => f.vulnerability_id === 65)).toBe(true); // X-Content-Type-Options
      expect(findings.some((f) => f.vulnerability_id === 66)).toBe(true); // HSTS
      expect(findings.some((f) => f.vulnerability_id === 251)).toBe(true); // Referrer-Policy

      const cspFinding = findings.find((f) => f.vulnerability_id === 63);
      expect(cspFinding?.severity).toBe("medium");
      expect(cspFinding?.category).toBe("headers");
      expect(cspFinding?.title).toBe("Missing Content Security Policy");
      expect(cspFinding?.status).toBe("open");
    });
  });

  describe("when all security headers are present", () => {
    it("returns no header findings", async () => {
      // Arrange
      const mockHeaders = new Map([
        ["content-security-policy", "default-src 'self'; frame-ancestors 'self'"],
        ["x-frame-options", "DENY"],
        ["x-content-type-options", "nosniff"],
        ["strict-transport-security", "max-age=31536000; includeSubDomains"],
        ["referrer-policy", "strict-origin-when-cross-origin"],
        ["content-type", "text/html; charset=utf-8"],
      ]);

      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn((header: string) => mockHeaders.get(header.toLowerCase()) || null),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - no header findings (ids 63-66)
      const headerFindings = findings.filter(
        (f) => f.vulnerability_id >= 63 && f.vulnerability_id <= 66 && f.title.includes("Missing")
      );
      expect(headerFindings).toHaveLength(0);
    });
  });

  describe("cookie security", () => {
    it("detects cookies without Secure flag", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue(["session=abc123; HttpOnly; SameSite=Strict"]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const secureFinding = findings.find((f) => f.vulnerability_id === 67);
      expect(secureFinding).toBeDefined();
      expect(secureFinding?.severity).toBe("medium");
      expect(secureFinding?.category).toBe("headers");
      expect(secureFinding?.title).toBe("Cookie Without Secure Flag");
      expect(secureFinding?.status).toBe("open");
    });

    it("detects cookies without HttpOnly flag", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue(["session=abc123; Secure; SameSite=Strict"]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const httpOnlyFinding = findings.find((f) => f.vulnerability_id === 68);
      expect(httpOnlyFinding).toBeDefined();
      expect(httpOnlyFinding?.severity).toBe("medium");
      expect(httpOnlyFinding?.category).toBe("headers");
      expect(httpOnlyFinding?.title).toBe("Cookie Without HttpOnly Flag");
      expect(httpOnlyFinding?.status).toBe("open");
    });

    it("detects cookies without SameSite attribute", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue(["session=abc123; Secure; HttpOnly"]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const sameSiteFinding = findings.find((f) => f.vulnerability_id === 69);
      expect(sameSiteFinding).toBeDefined();
      expect(sameSiteFinding?.severity).toBe("medium");
      expect(sameSiteFinding?.category).toBe("headers");
      expect(sameSiteFinding?.title).toBe("Cookie Without SameSite Attribute");
      expect(sameSiteFinding?.status).toBe("open");
    });

    it("detects multiple cookie issues on single cookie", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue(["session=abc123"]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - should have all 3 cookie vulnerabilities
      const cookieFindings = findings.filter(
        (f) => f.vulnerability_id >= 67 && f.vulnerability_id <= 69
      );
      expect(cookieFindings).toHaveLength(3);
    });

    it("does not flag cookies with all security attributes", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi
            .fn()
            .mockReturnValue(["session=abc123; Secure; HttpOnly; SameSite=Strict"]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - no cookie findings
      const cookieFindings = findings.filter(
        (f) => f.vulnerability_id >= 67 && f.vulnerability_id <= 69
      );
      expect(cookieFindings).toHaveLength(0);
    });
  });

  describe("source map accessibility", () => {
    it("detects accessible source maps", async () => {
      // Arrange
      fetchMock
        .mockResolvedValueOnce({
          // Main URL
          ok: true,
          url: "https://example.com",
          text: vi.fn().mockResolvedValue(""),
          headers: {
            get: vi.fn().mockReturnValue(null),
            getSetCookie: vi.fn().mockReturnValue([]),
          },
        })
        .mockResolvedValueOnce({
          // Source map check
          ok: true,
          status: 200,
        });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const sourceMapFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(sourceMapFinding).toBeDefined();
      expect(sourceMapFinding?.severity).toBe("medium");
      expect(sourceMapFinding?.category).toBe("react-nextjs");
      expect(sourceMapFinding?.title).toBe("Source Maps Accessible in Production");
      expect(sourceMapFinding?.status).toBe("open");
      expect(sourceMapFinding?.code_snippet).toContain("200");
    });

    it("does not report source map finding when source maps are not accessible", async () => {
      // Arrange
      fetchMock
        .mockResolvedValueOnce({
          // Main URL
          ok: true,
          url: "https://example.com",
          text: vi.fn().mockResolvedValue(""),
          headers: {
            get: vi.fn().mockReturnValue(null),
            getSetCookie: vi.fn().mockReturnValue([]),
          },
        })
        .mockRejectedValueOnce(new Error("Not found")) // First source map check fails
        .mockRejectedValueOnce(new Error("Not found")) // Second source map check fails
        .mockRejectedValueOnce(new Error("Not found")); // Third source map check fails

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const sourceMapFinding = findings.find((f) => f.vulnerability_id === 49);
      expect(sourceMapFinding).toBeUndefined();
    });

    it("only reports one source map finding even if multiple paths are accessible", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - only one finding even though multiple source maps exist
      const sourceMapFindings = findings.filter((f) => f.vulnerability_id === 49);
      expect(sourceMapFindings).toHaveLength(1);
    });
  });

  describe("exposed debug endpoints", () => {
    it("detects exposed debug endpoint", async () => {
      // Arrange - use URL-based matching to avoid position-dependent mocks
      fetchMock.mockImplementation((url: string) => {
        const u = url.toString();
        if (u === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        if (u.endsWith("/debug")) {
          return Promise.resolve({ ok: true, status: 200 });
        }
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const debugFinding = findings.find((f) => f.vulnerability_id === 116);
      expect(debugFinding).toBeDefined();
      expect(debugFinding?.severity).toBe("medium");
      expect(debugFinding?.category).toBe("config");
      expect(debugFinding?.title).toContain("/debug");
      expect(debugFinding?.status).toBe("open");
    });

    it("detects exposed API documentation endpoints", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string) => {
        const u = url.toString();
        if (u === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        if (u.endsWith("/swagger")) {
          return Promise.resolve({ ok: true, status: 200 });
        }
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const apiDocsFinding = findings.find((f) => f.vulnerability_id === 94);
      expect(apiDocsFinding).toBeDefined();
      expect(apiDocsFinding?.severity).toBe("low");
      expect(apiDocsFinding?.category).toBe("config");
      expect(apiDocsFinding?.title).toContain("/swagger");
      expect(apiDocsFinding?.status).toBe("open");
    });

    it("detects exposed GraphQL endpoint", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string) => {
        const u = url.toString();
        if (u === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        if (u.endsWith("/graphql")) {
          return Promise.resolve({ ok: true, status: 200 });
        }
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const graphqlFinding = findings.find((f) => f.vulnerability_id === 95);
      expect(graphqlFinding).toBeDefined();
      expect(graphqlFinding?.severity).toBe("low");
      expect(graphqlFinding?.category).toBe("api");
      expect(graphqlFinding?.title).toContain("/graphql");
      expect(graphqlFinding?.status).toBe("open");
    });

    it("does not report endpoint findings when all endpoints return 404", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string) => {
        const u = url.toString();
        if (u === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const endpointFindings = findings.filter(
        (f) => f.vulnerability_id === 94 || f.vulnerability_id === 95 || f.vulnerability_id === 116
      );
      expect(endpointFindings).toHaveLength(0);
    });
  });

  describe("HTTP to HTTPS redirect", () => {
    it("detects missing HTTP to HTTPS redirect", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string, options?: any) => {
        const urlStr = url.toString();
        // Main HTTPS request
        if (urlStr === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        // HTTP URL check - no redirect (location header missing or not HTTPS)
        if (urlStr === "http://example.com" && options?.method === "HEAD") {
          return Promise.resolve({
            ok: true,
            headers: {
              get: vi.fn((header: string) => {
                if (header === "location") return null;
                return null;
              }),
            },
          });
        }
        // Source maps and endpoints - all fail
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const redirectFinding = findings.find(
        (f) =>
          f.vulnerability_id === 66 && f.title === "HTTP Does Not Redirect to HTTPS"
      );
      expect(redirectFinding).toBeDefined();
      expect(redirectFinding?.severity).toBe("medium");
      expect(redirectFinding?.category).toBe("headers");
      expect(redirectFinding?.description_technical).toContain("http://example.com");
      expect(redirectFinding?.status).toBe("open");
    });

    it("does not flag when HTTP redirects to HTTPS", async () => {
      // Arrange
      fetchMock.mockImplementation((url: string, options?: any) => {
        const urlStr = url.toString();
        // Main HTTPS request
        if (urlStr === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        // HTTP URL check - redirects to HTTPS
        if (urlStr === "http://example.com" && options?.method === "HEAD") {
          return Promise.resolve({
            ok: false,
            status: 301,
            headers: {
              get: vi.fn((header: string) => {
                if (header === "location") return "https://example.com/";
                return null;
              }),
            },
          });
        }
        // Source maps and endpoints - all fail
        return Promise.reject(new Error("Not found"));
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const redirectFinding = findings.find(
        (f) =>
          f.vulnerability_id === 66 && f.title === "HTTP Does Not Redirect to HTTPS"
      );
      expect(redirectFinding).toBeUndefined();
    });

    it("does not check HTTP redirect for non-HTTPS URLs", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "http://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      // Act
      const findings = await scanUrl("http://example.com");

      // Assert - should not check for HTTP redirect
      const redirectFinding = findings.find(
        (f) =>
          f.vulnerability_id === 66 && f.title === "HTTP Does Not Redirect to HTTPS"
      );
      expect(redirectFinding).toBeUndefined();
    });

    it("does not flag when HTTP endpoint is not accessible", async () => {
      // Arrange
      fetchMock
        .mockResolvedValueOnce({
          // HTTPS URL (main)
          ok: true,
          url: "https://example.com",
          text: vi.fn().mockResolvedValue(""),
          headers: {
            get: vi.fn().mockReturnValue(null),
            getSetCookie: vi.fn().mockReturnValue([]),
          },
        })
        .mockRejectedValue(new Error("Connection failed")); // All subsequent requests fail

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      const redirectFinding = findings.find(
        (f) =>
          f.vulnerability_id === 66 && f.title === "HTTP Does Not Redirect to HTTPS"
      );
      expect(redirectFinding).toBeUndefined();
    });
  });

  describe("error handling", () => {
    it("returns empty array when URL is unreachable", async () => {
      // Arrange
      fetchMock.mockRejectedValue(new Error("Network error"));

      // Act
      const findings = await scanUrl("https://unreachable.example.com");

      // Assert
      expect(findings).toEqual([]);
    });

    it("returns empty array when request times out", async () => {
      // Arrange
      fetchMock.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Timeout")), 100);
        });
      });

      // Act
      const findings = await scanUrl("https://slow.example.com");

      // Assert
      expect(findings).toEqual([]);
    });

    it("handles fetch abort gracefully", async () => {
      // Arrange
      fetchMock.mockImplementation(() => {
        const error = new Error("Aborted");
        error.name = "AbortError";
        return Promise.reject(error);
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert
      expect(findings).toEqual([]);
    });
  });

  describe("edge cases", () => {
    it("handles response with no set-cookie headers", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: undefined, // No getSetCookie method
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - should not crash
      expect(Array.isArray(findings)).toBe(true);
    });

    it("masks cookie values in findings", async () => {
      // Arrange
      const longCookieValue = "verylongsessio" + "n".repeat(50);
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([`session=${longCookieValue}`]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - cookie value should be masked
      const cookieFinding = findings.find((f) => f.vulnerability_id === 67);
      expect(cookieFinding?.code_snippet).toContain("***REDACTED***");
      expect(cookieFinding?.code_snippet).not.toContain(longCookieValue);
    });

    it("handles multiple cookies in response", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            "session=abc123",
            "tracking=xyz789; Secure; HttpOnly; SameSite=Lax",
            "preference=dark-mode",
          ]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - should detect issues with first and third cookies
      const cookieFindings = findings.filter(
        (f) => f.vulnerability_id >= 67 && f.vulnerability_id <= 69
      );
      // First cookie: missing all 3 attributes = 3 findings
      // Second cookie: has all attributes = 0 findings
      // Third cookie: missing all 3 attributes = 3 findings
      // Total = 6 findings
      expect(cookieFindings.length).toBeGreaterThanOrEqual(3);
    });

    it("does not flag HttpOnly on sb- prefixed Supabase Auth cookies", async () => {
      // Supabase Auth cookies omit HttpOnly by design — the JS client reads them
      // from document.cookie to perform session refreshes. Flagging these would
      // be a false positive.
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            "sb-abcdef-auth-token=sometoken; Secure; SameSite=Lax",
          ]),
        },
      });

      const findings = await scanUrl("https://example.com");

      // HttpOnly finding must NOT be present for Supabase cookies
      const httpOnlyFinding = findings.find((f) => f.vulnerability_id === 68);
      expect(httpOnlyFinding).toBeUndefined();

      // Secure and SameSite checks still apply (both attributes ARE present here)
      const secureFinding = findings.find((f) => f.vulnerability_id === 67);
      expect(secureFinding).toBeUndefined();
    });

    it("does not flag any cookie issue on __supabase prefixed cookies", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            "__supabase_session=sometoken; Secure; SameSite=Lax",
          ]),
        },
      });

      const findings = await scanUrl("https://example.com");

      // All cookie checks are skipped for Supabase cookies
      const cookieFindings = findings.filter((f) => [67, 68, 69].includes(f.vulnerability_id));
      expect(cookieFindings).toHaveLength(0);
    });

    it("skips all cookie checks on sb- cookies but still flags non-Supabase cookies", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            // Supabase cookie — entirely skipped (no findings)
            "sb-xyz-auth-token=tok; SameSite=Lax",
            // Regular session cookie — missing HttpOnly → should trigger vuln 68
            "session=abc; Secure; SameSite=Strict",
          ]),
        },
      });

      const findings = await scanUrl("https://example.com");

      // No Secure finding on Supabase cookie (skipped entirely)
      const secureFindings = findings.filter((f) => f.vulnerability_id === 67);
      expect(secureFindings).toHaveLength(0);

      // HttpOnly finding only on the regular cookie
      const httpOnlyFindings = findings.filter((f) => f.vulnerability_id === 68);
      expect(httpOnlyFindings).toHaveLength(1);
      expect(httpOnlyFindings[0].code_snippet).toContain("session=");
    });

    it("does not flag any cookie issue on NEXT_LOCALE cookie", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            "NEXT_LOCALE=en; Path=/; SameSite=lax",
          ]),
        },
      });

      const findings = await scanUrl("https://example.com");

      const cookieFindings = findings.filter((f) => [67, 68, 69].includes(f.vulnerability_id));
      expect(cookieFindings).toHaveLength(0);
    });

    it("is case-insensitive when checking cookie attributes", async () => {
      // Arrange
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn().mockReturnValue(null),
          getSetCookie: vi.fn().mockReturnValue([
            "session=abc123; SECURE; HTTPONLY; SAMESITE=Strict",
          ]),
        },
      });

      // Act
      const findings = await scanUrl("https://example.com");

      // Assert - should not flag cookies (case-insensitive check)
      const cookieFindings = findings.filter(
        (f) => f.vulnerability_id >= 67 && f.vulnerability_id <= 69
      );
      expect(cookieFindings).toHaveLength(0);
    });
  });

  describe("Referrer-Policy header (ID 251)", () => {
    it("detects missing Referrer-Policy header", async () => {
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 251);
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("low");
      expect(finding?.category).toBe("headers");
      expect(finding?.title).toBe("Missing Referrer-Policy Header");
      expect(finding?.status).toBe("open");
    });

    it("does not flag when Referrer-Policy header is present", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        url: "https://example.com",
        text: vi.fn().mockResolvedValue(""),
        headers: {
          get: vi.fn((header: string) => {
            if (header === "referrer-policy") return "strict-origin-when-cross-origin";
            if (header === "content-type") return "text/html; charset=utf-8";
            return null;
          }),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 251);
      expect(finding).toBeUndefined();
    });
  });

  describe("mixed content (ID 252)", () => {
    it("detects HTTP subresource references on an HTTPS page", async () => {
      const bodyWithMixedContent = `
        <html>
          <head><script src="http://cdn.example.com/lib.js"></script></head>
          <body>
            <img src="http://images.example.com/photo.jpg" />
            <link href="http://fonts.example.com/font.css" rel="stylesheet" />
          </body>
        </html>
      `;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(bodyWithMixedContent),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 252);
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
      expect(finding?.category).toBe("headers");
      expect(finding?.owasp_ref).toBe("A05:2021");
      expect(finding?.status).toBe("open");
    });

    it("does not flag on HTTP pages (mixed content only applies to HTTPS)", async () => {
      const bodyWithHttpRefs = `<img src="http://images.example.com/photo.jpg" />`;
      fetchMock.mockResolvedValue({
        ok: true,
        url: "http://example.com",
        text: vi.fn().mockResolvedValue(bodyWithHttpRefs),
        headers: {
          get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      const findings = await scanUrl("http://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 252);
      expect(finding).toBeUndefined();
    });

    it("does not flag XML namespace http:// references", async () => {
      const bodyWithXmlNs = `
        <html xmlns="http://www.w3.org/1999/xhtml"
              xmlns:og="http://xmlns.com/foaf/0.1/">
        </html>
      `;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(bodyWithXmlNs),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 252);
      expect(finding).toBeUndefined();
    });

    it("does not flag when body has no HTTP subresource references", async () => {
      const cleanBody = `<img src="https://cdn.example.com/photo.jpg" /><script src="/static/app.js"></script>`;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(cleanBody),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 252);
      expect(finding).toBeUndefined();
    });
  });

  describe("form action insecure (ID 253)", () => {
    it("detects form with HTTP action URL on an HTTPS page", async () => {
      const bodyWithInsecureForm = `
        <form action="http://api.example.com/login" method="POST">
          <input type="password" name="pass" />
        </form>
      `;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(bodyWithInsecureForm),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 253);
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("medium");
      expect(finding?.category).toBe("headers");
      expect(finding?.status).toBe("open");
    });

    it("does not flag forms with HTTPS action URLs", async () => {
      const cleanForm = `<form action="https://api.example.com/login" method="POST"></form>`;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(cleanForm),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 253);
      expect(finding).toBeUndefined();
    });

    it("does not flag form action insecure on HTTP pages", async () => {
      const bodyWithForm = `<form action="http://api.example.com/login" method="POST"></form>`;
      fetchMock.mockResolvedValue({
        ok: true,
        url: "http://example.com",
        text: vi.fn().mockResolvedValue(bodyWithForm),
        headers: {
          get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      const findings = await scanUrl("http://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 253);
      expect(finding).toBeUndefined();
    });
  });

  describe("protocol-relative links (ID 254)", () => {
    it("detects protocol-relative src and href attributes", async () => {
      const bodyWithProtoRelative = `
        <script src="//cdn.example.com/lib.js"></script>
        <link href="//fonts.example.com/font.css" rel="stylesheet" />
      `;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(bodyWithProtoRelative),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 254);
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("low");
      expect(finding?.category).toBe("headers");
      expect(finding?.status).toBe("open");
    });

    it("does not flag when no protocol-relative links are present", async () => {
      const cleanBody = `<script src="https://cdn.example.com/lib.js"></script>`;
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(cleanBody),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 254);
      expect(finding).toBeUndefined();
    });

    it("detects protocol-relative links on HTTP pages too", async () => {
      const bodyWithProtoRelative = `<img src="//cdn.example.com/img.png" />`;
      fetchMock.mockResolvedValue({
        ok: true,
        url: "http://example.com",
        text: vi.fn().mockResolvedValue(bodyWithProtoRelative),
        headers: {
          get: vi.fn((h: string) => (h === "content-type" ? "text/html" : null)),
          getSetCookie: vi.fn().mockReturnValue([]),
        },
      });

      const findings = await scanUrl("http://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 254);
      expect(finding).toBeDefined();
    });
  });

  describe("content-type check (ID 255)", () => {
    it("detects missing Content-Type header for root URL", async () => {
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn().mockReturnValue(null), // no content-type
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 255);
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("low");
      expect(finding?.category).toBe("headers");
      expect(finding?.title).toBe("Missing Content-Type Header");
      expect(finding?.status).toBe("open");
    });

    it("detects wrong content-type for an HTML page URL", async () => {
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn((h: string) => (h === "content-type" ? "application/octet-stream" : null)),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 255);
      expect(finding).toBeDefined();
      expect(finding?.title).toBe("Unexpected Content-Type for Web Page");
      expect(finding?.code_snippet).toContain("application/octet-stream");
    });

    it("does not flag when Content-Type is text/html", async () => {
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn((h: string) =>
                h === "content-type" ? "text/html; charset=utf-8" : null
              ),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com");

      const finding = findings.find((f) => f.vulnerability_id === 255);
      expect(finding).toBeUndefined();
    });

    it("does not flag Content-Type for URLs with file extensions like .js or .png", async () => {
      // Non-HTML resource URLs are not expected to serve text/html
      fetchMock.mockImplementation((url: string) => {
        if (url.toString() === "https://example.com/static/app.js") {
          return Promise.resolve({
            ok: true,
            url: "https://example.com/static/app.js",
            text: vi.fn().mockResolvedValue(""),
            headers: {
              get: vi.fn((h: string) =>
                h === "content-type" ? "application/javascript" : null
              ),
              getSetCookie: vi.fn().mockReturnValue([]),
            },
          });
        }
        return Promise.reject(new Error("Not found"));
      });

      const findings = await scanUrl("https://example.com/static/app.js");

      const finding = findings.find((f) => f.vulnerability_id === 255);
      expect(finding).toBeUndefined();
    });
  });
});
