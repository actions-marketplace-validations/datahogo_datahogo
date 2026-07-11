import { describe, it, expect } from "vitest";
import { PHPScanAgent } from "./php-agent.js";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

const agent = new PHPScanAgent();

// ===========================================================================
// getMetadata
// ===========================================================================

describe("PHPScanAgent.getMetadata()", () => {
  it("returns correct name, version, and technologies", () => {
    const meta = agent.getMetadata();
    expect(meta.name).toBe("php-agent");
    expect(meta.version).toBe("1.0.0");
    expect(meta.technologies).toEqual(["php", "laravel"]);
  });
});

// ===========================================================================
// detect()
// ===========================================================================

describe("PHPScanAgent.detect()", () => {
  it("detects composer.json at root", async () => {
    const files = makeFiles({ "composer.json": '{ "require": { "laravel/framework": "^10.0" } }' });
    expect(await agent.detect(files)).toBe(true);
  });

  it("detects composer.json in a subdirectory", async () => {
    const files = makeFiles({ "backend/composer.json": '{ "require": {} }' });
    expect(await agent.detect(files)).toBe(true);
  });

  it("returns false when no composer.json is present", async () => {
    const files = makeFiles({
      "package.json": '{ "dependencies": { "next": "14.0" } }',
      "src/index.ts": "console.log('hello')",
    });
    expect(await agent.detect(files)).toBe(false);
  });

  it("returns false for empty file map", async () => {
    expect(await agent.detect(new Map())).toBe(false);
  });

  it("does not trigger on composer.lock (without composer.json)", async () => {
    const files = makeFiles({ "composer.lock": '{ "packages": [] }' });
    expect(await agent.detect(files)).toBe(false);
  });
});

// ===========================================================================
// Check 1 — Mass assignment without $fillable/$guarded
// ===========================================================================

describe("PHPScanAgent.scan() — check 1: mass assignment", () => {
  it("flags Eloquent model missing both $fillable and $guarded", async () => {
    const vuln = `<?php
namespace App\\Models;
use Illuminate\\Database\\Eloquent\\Model;
class User extends Model
{
    // no $fillable or $guarded defined
}
`;
    const files = makeFiles({ "composer.json": "{}", "app/Models/User.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("Mass assignment"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-915");
  });

  it("flags second model missing protection in same repo", async () => {
    const model1 = `<?php class Post extends Model { }`;
    const model2 = `<?php class Comment extends Model { }`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Models/Post.php": model1,
      "app/Models/Comment.php": model2,
    });
    const results = await agent.scan(files);
    const findings = results.filter((r) => r.title.includes("Mass assignment"));
    expect(findings.length).toBe(2);
  });

  it("does not flag model with $fillable", async () => {
    const safe = `<?php
class User extends Model {
    protected $fillable = ['name', 'email'];
}`;
    const files = makeFiles({ "composer.json": "{}", "app/Models/User.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Mass assignment"))).toHaveLength(0);
  });

  it("does not flag model with $guarded", async () => {
    const safe = `<?php
class User extends Model {
    protected $guarded = [];
}`;
    const files = makeFiles({ "composer.json": "{}", "app/Models/User.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Mass assignment"))).toHaveLength(0);
  });

  it("does not flag PHP files that do not extend Model", async () => {
    const notModel = `<?php
class UserRepository {
    public function save(array $data) {}
}`;
    const files = makeFiles({ "composer.json": "{}", "app/Repositories/UserRepository.php": notModel });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Mass assignment"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 2 — SQL injection via DB::raw()
// ===========================================================================

describe("PHPScanAgent.scan() — check 2: SQL injection via DB::raw()", () => {
  it("flags DB::raw() with a variable inside", async () => {
    const vuln = `<?php
$results = DB::select(DB::raw("SELECT * FROM users WHERE id = $id"));
`;
    const files = makeFiles({ "composer.json": "{}", "app/Http/Controllers/UserController.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("DB::raw()"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.cwe).toBe("CWE-89");
  });

  it("flags inline DB::raw() with interpolated variable", async () => {
    const vuln = `<?php
$rows = DB::table('orders')->whereRaw(DB::raw("amount > $minAmount"))->get();
`;
    const files = makeFiles({ "composer.json": "{}", "app/Services/OrderService.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("DB::raw()"));
    expect(finding).toBeDefined();
  });

  it("does not flag DB::raw() with only a literal string", async () => {
    const safe = `<?php
$results = DB::select(DB::raw("SELECT COUNT(*) FROM users"));
`;
    const files = makeFiles({ "composer.json": "{}", "app/Http/Controllers/StatsController.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("DB::raw()"))).toHaveLength(0);
  });

  it("does not flag query builder bindings", async () => {
    const safe = `<?php
$results = DB::select('SELECT * FROM users WHERE id = ?', [$id]);
`;
    const files = makeFiles({ "composer.json": "{}", "app/Http/Controllers/UserController.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("DB::raw()"))).toHaveLength(0);
  });

  it("does not flag DB::raw() that contains a ? placeholder", async () => {
    const safe = `<?php
$results = DB::select(DB::raw("SELECT * FROM users WHERE id = ?"), [$id]);
`;
    const files = makeFiles({ "composer.json": "{}", "app/Http/Controllers/UserController.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("DB::raw()"))).toHaveLength(0);
  });

  it("does not flag DB::raw() with a binding array as second argument", async () => {
    const safe = `<?php
$results = DB::raw("SELECT * FROM t WHERE x = $x", [$x]);
`;
    // Note: the second-argument pattern '...', [$x] should make this safe
    const files = makeFiles({ "composer.json": "{}", "app/Repos/UserRepo.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("DB::raw()"))).toHaveLength(0);
  });

  it("finding has confidence: high when flagged", async () => {
    const vuln = `<?php $r = DB::raw("SELECT * FROM t WHERE x = $x");`;
    const files = makeFiles({ "composer.json": "{}", "app/Repos/UserRepo.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("DB::raw()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("high");
  });
});

// ===========================================================================
// Check 3 — APP_DEBUG=true
// ===========================================================================

describe("PHPScanAgent.scan() — check 3: APP_DEBUG=true", () => {
  it("flags APP_DEBUG=true in .env", async () => {
    const files = makeFiles({ "composer.json": "{}", ".env": "APP_DEBUG=true\nAPP_ENV=production\n" });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("APP_DEBUG"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-215");
  });

  it("flags APP_DEBUG=True (mixed case)", async () => {
    const files = makeFiles({ "composer.json": "{}", ".env": "APP_DEBUG=True\n" });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("APP_DEBUG"))).toBeDefined();
  });

  it("does not flag APP_DEBUG=false", async () => {
    const files = makeFiles({ "composer.json": "{}", ".env": "APP_DEBUG=false\nAPP_ENV=production\n" });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("APP_DEBUG"))).toHaveLength(0);
  });

  it("does not flag APP_DEBUG in .env.example", async () => {
    const files = makeFiles({ "composer.json": "{}", ".env.example": "APP_DEBUG=true\n" });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("APP_DEBUG"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 4 — Dangerous functions
// ===========================================================================

describe("PHPScanAgent.scan() — check 4: dangerous functions", () => {
  it("flags eval()", async () => {
    const vuln = `<?php eval($userInput);`;
    const files = makeFiles({ "composer.json": "{}", "app/Helper.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("eval()"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.cwe).toBe("CWE-78");
  });

  it("flags exec()", async () => {
    const vuln = `<?php exec($command, $output);`;
    const files = makeFiles({ "composer.json": "{}", "app/Shell.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("exec()"))).toBeDefined();
  });

  it("flags system()", async () => {
    const vuln = `<?php system($cmd);`;
    const files = makeFiles({ "composer.json": "{}", "app/Run.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("system()"))).toBeDefined();
  });

  it("flags shell_exec()", async () => {
    const vuln = `<?php $out = shell_exec($input);`;
    const files = makeFiles({ "composer.json": "{}", "app/Run.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("shell_exec()"))).toBeDefined();
  });

  it("flags passthru()", async () => {
    const vuln = `<?php passthru($cmd);`;
    const files = makeFiles({ "composer.json": "{}", "app/Run.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("passthru()"))).toBeDefined();
  });

  it("flags popen()", async () => {
    const vuln = `<?php $handle = popen($cmd, 'r');`;
    const files = makeFiles({ "composer.json": "{}", "app/Run.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("popen()"))).toBeDefined();
  });

  it("does not flag functions mentioned in comments", async () => {
    const safe = `<?php
// Never use eval($input) in production
// exec() is dangerous
# system() calls should be avoided
`;
    const files = makeFiles({ "composer.json": "{}", "docs/Security.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Dangerous function"))).toHaveLength(0);
  });

  it("does not flag doc block comments", async () => {
    const safe = `<?php
/**
 * Avoid using exec() or system() calls directly.
 */
function runCommand(string $cmd): void {
    // implementation uses a safe wrapper
}
`;
    const files = makeFiles({ "composer.json": "{}", "app/Utils/Command.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Dangerous function"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 5 — Unsafe unserialize
// ===========================================================================

describe("PHPScanAgent.scan() — check 5: unsafe unserialize", () => {
  it("flags unserialize() with a variable", async () => {
    const vuln = `<?php $obj = unserialize($data);`;
    const files = makeFiles({ "composer.json": "{}", "app/Cache.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("unserialize()"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.cwe).toBe("CWE-502");
  });

  it("flags unserialize() with user superglobal", async () => {
    const vuln = `<?php $obj = unserialize($_POST['data']);`;
    // $_POST['data'] ultimately becomes a variable reference; let's check
    // the pattern matches nested calls too. Our regex matches `unserialize($` so
    // $_POST starts with $ which satisfies the pattern.
    const files = makeFiles({ "composer.json": "{}", "app/Handler.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("unserialize()"))).toBeDefined();
  });

  it("does not flag unserialize with a literal string", async () => {
    const safe = `<?php $obj = unserialize('a:1:{i:0;s:5:"hello";}');`;
    const files = makeFiles({ "composer.json": "{}", "app/Cache.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("unserialize()"))).toHaveLength(0);
  });

  it("does not flag json_decode", async () => {
    const safe = `<?php $obj = json_decode($data, true);`;
    const files = makeFiles({ "composer.json": "{}", "app/Cache.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("unserialize()"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 6 — XSS via echo without escaping
// ===========================================================================

describe("PHPScanAgent.scan() — check 6: XSS via echo without escaping", () => {
  it("flags echo $var in plain PHP without escaping", async () => {
    const vuln = `<?php echo $username; ?>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/profile.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("XSS via echo"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-79");
  });

  it("flags multiple unescaped echo calls", async () => {
    const vuln = `<?php
echo $firstName;
echo $lastName;
`;
    const files = makeFiles({ "composer.json": "{}", "template.php": vuln });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS via echo"))).toHaveLength(2);
  });

  it("flags {!! $var !!} in Blade templates", async () => {
    const vuln = `<p>{!! $bio !!}</p>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/user.blade.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("unescaped Blade output"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-79");
  });

  it("does not flag echo with htmlspecialchars()", async () => {
    const safe = `<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>`;
    const files = makeFiles({ "composer.json": "{}", "template.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS via echo"))).toHaveLength(0);
  });

  it("does not flag safe {{ }} Blade syntax", async () => {
    const safe = `<p>{{ $username }}</p>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/user.blade.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS"))).toHaveLength(0);
  });

  it("does not flag echo with e() helper", async () => {
    const safe = `<?php echo e($username); ?>`;
    const files = makeFiles({ "composer.json": "{}", "template.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS via echo"))).toHaveLength(0);
  });

  it("does not flag echo with strip_tags()", async () => {
    const safe = `<?php echo strip_tags($bio); ?>`;
    const files = makeFiles({ "composer.json": "{}", "template.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS via echo"))).toHaveLength(0);
  });

  it("does not flag echo with nl2br(e($var))", async () => {
    const safe = `<?php echo nl2br(e($comment)); ?>`;
    const files = makeFiles({ "composer.json": "{}", "template.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("XSS via echo"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 7 — Routes without auth middleware
// ===========================================================================

describe("PHPScanAgent.scan() — check 7: routes without auth middleware", () => {
  it("flags Route::post() without middleware in routes/web.php", async () => {
    const vuln = `<?php
Route::post('/admin/users', [UserController::class, 'store']);
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("without auth middleware"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.cwe).toBe("CWE-306");
  });

  it("flags Route::delete() without middleware in routes/api.php", async () => {
    const vuln = `<?php
Route::delete('/posts/{id}', [PostController::class, 'destroy']);
`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("without auth middleware"))).toBeDefined();
  });

  it("does not flag routes with ->middleware('auth')", async () => {
    const safe = `<?php
Route::post('/admin/users', [UserController::class, 'store'])->middleware('auth');
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /login and /register routes", async () => {
    const safe = `<?php
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /webhook route", async () => {
    const safe = `<?php Route::post('/webhook', [WebhookController::class, 'handle']);`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not scan non-route files", async () => {
    const vuln = `<?php Route::post('/data', [DataController::class, 'store']);`;
    const files = makeFiles({ "composer.json": "{}", "app/Http/Controllers/DataController.php": vuln });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag routes with ->middleware('auth:api')", async () => {
    const safe = `<?php
Route::post('/api/data', [DataController::class, 'store'])->middleware('auth:api');
`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag routes with ->middleware('auth:sanctum')", async () => {
    const safe = `<?php
Route::post('/api/profile', [ProfileController::class, 'update'])->middleware('auth:sanctum');
`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag routes with middleware array syntax containing auth", async () => {
    const safe = `<?php
Route::post('/settings', [SettingsController::class, 'update'])->middleware(['auth', 'verified']);
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /callback route", async () => {
    const safe = `<?php Route::post('/callback', [OAuthController::class, 'handle']);`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /oauth route", async () => {
    const safe = `<?php Route::post('/oauth/token', [TokenController::class, 'issue']);`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /stripe route", async () => {
    const safe = `<?php Route::post('/stripe/webhook', [StripeController::class, 'handle']);`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag /api/public route", async () => {
    const safe = `<?php Route::post('/api/public/search', [SearchController::class, 'index']);`;
    const files = makeFiles({ "composer.json": "{}", "routes/api.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag routes inside Route::middleware('auth')->group(", async () => {
    const safe = `<?php
Route::middleware('auth')->group(function () {
    Route::post('/admin/users', [UserController::class, 'store']);
    Route::delete('/admin/users/{id}', [UserController::class, 'destroy']);
});
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("does not flag routes when Kernel.php defines global Authenticate middleware", async () => {
    const kernel = `<?php
namespace App\\Http;
class Kernel extends HttpKernel {
    protected $middleware = [
        \\Illuminate\\Auth\\Middleware\\Authenticate::class,
    ];
}
`;
    const routes = `<?php
Route::post('/admin/data', [DataController::class, 'store']);
`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Http/Kernel.php": kernel,
      "routes/web.php": routes,
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("finding has confidence: low", async () => {
    const vuln = `<?php
Route::post('/admin/users', [UserController::class, 'store']);
`;
    const files = makeFiles({ "composer.json": "{}", "routes/web.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("without auth middleware"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });
});

// ===========================================================================
// Check 8 — SQL injection via raw $_GET/$_POST in query()
// ===========================================================================

describe("PHPScanAgent.scan() — check 8: SQL injection via raw user input", () => {
  it("flags $_GET used directly in query()", async () => {
    const vuln = `<?php $result = $db->query("SELECT * FROM users WHERE id = " . $_GET['id']);`;
    const files = makeFiles({ "composer.json": "{}", "search.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("raw user input"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.cwe).toBe("CWE-89");
  });

  it("flags $_POST used directly in query()", async () => {
    const vuln = `<?php mysqli_query($conn, "DELETE FROM users WHERE id = " . $_POST['id']);`;
    const files = makeFiles({ "composer.json": "{}", "delete.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("raw user input"))).toBeDefined();
  });

  it("does not flag $_GET assignment without query()", async () => {
    const safe = `<?php $id = $_GET['id'];`;
    const files = makeFiles({ "composer.json": "{}", "handler.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("raw user input"))).toHaveLength(0);
  });

  it("does not flag safe prepared statements", async () => {
    const safe = `<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_GET['id']]);
`;
    const files = makeFiles({ "composer.json": "{}", "handler.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("raw user input"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 9 — SSRF via file_get_contents / curl
// ===========================================================================

describe("PHPScanAgent.scan() — check 9: SSRF", () => {
  it("flags file_get_contents() with a variable URL", async () => {
    const vuln = `<?php $content = file_get_contents($url);`;
    const files = makeFiles({ "composer.json": "{}", "app/Fetcher.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("SSRF"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-918");
  });

  it("flags file_get_contents() with a user-supplied URL", async () => {
    const vuln = `<?php $content = file_get_contents($_GET['url']);`;
    const files = makeFiles({ "composer.json": "{}", "proxy.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("SSRF"))).toBeDefined();
  });

  it("does not flag file_get_contents() with a literal URL", async () => {
    const safe = `<?php $content = file_get_contents('https://api.example.com/data.json');`;
    const files = makeFiles({ "composer.json": "{}", "fetcher.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("SSRF"))).toHaveLength(0);
  });

  it("does not flag file_get_contents() on a local path literal", async () => {
    const safe = `<?php $content = file_get_contents('/var/data/config.json');`;
    const files = makeFiles({ "composer.json": "{}", "loader.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("SSRF"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 10 — Weak password hashing
// ===========================================================================

describe("PHPScanAgent.scan() — check 10: weak hashing", () => {
  it("flags md5() with a variable", async () => {
    const vuln = `<?php $hash = md5($password);`;
    const files = makeFiles({ "composer.json": "{}", "app/Auth.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("md5()"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.cwe).toBe("CWE-328");
  });

  it("flags sha1() with a variable", async () => {
    const vuln = `<?php $hash = sha1($password);`;
    const files = makeFiles({ "composer.json": "{}", "app/Auth.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("sha1()") || r.title.includes("md5() or sha1()"))).toBeDefined();
  });

  it("flags md5() used on any variable (not just password context)", async () => {
    const vuln = `<?php $checksum = md5($fileContents);`;
    const files = makeFiles({ "composer.json": "{}", "app/Util.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("Weak hashing"))).toBeDefined();
  });

  it("does not flag password_hash()", async () => {
    const safe = `<?php $hash = password_hash($password, PASSWORD_BCRYPT);`;
    const files = makeFiles({ "composer.json": "{}", "app/Auth.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Weak hashing"))).toHaveLength(0);
  });

  it("does not flag md5 mentioned only in a comment", async () => {
    const safe = `<?php
// md5($value) is insecure — use password_hash() instead
$hash = password_hash($password, PASSWORD_BCRYPT);
`;
    const files = makeFiles({ "composer.json": "{}", "app/Auth.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Weak hashing"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 11 — Committed .env with secrets
// ===========================================================================

describe("PHPScanAgent.scan() — check 11: committed .env file", () => {
  it("flags .env containing DB_PASSWORD", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env": "APP_NAME=Laravel\nDB_PASSWORD=supersecret\nAPP_ENV=production\n",
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("Secret credentials"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("CRITICAL");
    expect(finding!.cwe).toBe("CWE-540");
  });

  it("flags .env containing APP_KEY", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env": "APP_KEY=base64:abcdefghijklmnopqrstuvwxyz123456789=\n",
    });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("Secret credentials"))).toBeDefined();
  });

  it("flags .env containing API_SECRET", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env": "STRIPE_API_SECRET=sk_live_abc123\n",
    });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("Secret credentials"))).toBeDefined();
  });

  it("does not flag .env.example", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env.example": "DB_PASSWORD=your_password_here\nAPP_KEY=\n",
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Secret credentials"))).toHaveLength(0);
  });

  it("does not flag .env.template", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env.template": "APP_KEY=changeme\n",
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Secret credentials"))).toHaveLength(0);
  });

  it("does not flag .env with only non-sensitive keys", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env": "APP_NAME=MyApp\nAPP_URL=http://localhost\nPORT=8080\n",
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("Secret credentials"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 12 — CORS wildcard
// ===========================================================================

describe("PHPScanAgent.scan() — check 12: CORS wildcard", () => {
  it("flags CORS_ALLOWED_ORIGINS with * in config file", async () => {
    const vuln = `<?php
return [
    'allowedOrigins' => ['*'],
    'allowedMethods' => ['GET', 'POST'],
];
`;
    const files = makeFiles({ "composer.json": "{}", "config/cors.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("CORS"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.cwe).toBe("CWE-942");
  });

  it("flags CORS_ALLOWED_ORIGINS=* in .env", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      ".env": "CORS_ALLOWED_ORIGINS=*\nAPP_ENV=production\n",
    });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("CORS"))).toBeDefined();
  });

  it("flags Access-Control-Allow-Origin: * in PHP response header", async () => {
    const vuln = `<?php header('Access-Control-Allow-Origin: *');`;
    const files = makeFiles({ "composer.json": "{}", "api.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("CORS"))).toBeDefined();
  });

  it("does not flag specific origin in CORS config", async () => {
    const safe = `<?php
return [
    'allowedOrigins' => ['https://myapp.com'],
];
`;
    const files = makeFiles({ "composer.json": "{}", "config/cors.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CORS"))).toHaveLength(0);
  });
});

// ===========================================================================
// Check 13 — Missing CSRF in Blade forms
// ===========================================================================

describe("PHPScanAgent.scan() — check 13: missing CSRF in Blade forms", () => {
  it("flags a POST form without @csrf", async () => {
    const vuln = `<form method="POST" action="/admin/users">
    <input name="name" type="text" />
    <button>Submit</button>
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/admin.blade.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("CSRF"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.cwe).toBe("CWE-352");
  });

  it("flags a form with method=POST (uppercase) without @csrf", async () => {
    const vuln = `<form method="POST" action="/settings">
    <input name="email" />
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/settings.blade.php": vuln });
    const results = await agent.scan(files);
    expect(results.find((r) => r.title.includes("CSRF"))).toBeDefined();
  });

  it("does not flag a form with @csrf", async () => {
    const safe = `<form method="POST" action="/admin/users">
    @csrf
    <input name="name" type="text" />
    <button>Submit</button>
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/admin.blade.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CSRF"))).toHaveLength(0);
  });

  it("does not flag a form with csrf_field()", async () => {
    const safe = `<form method="POST" action="/profile">
    {{ csrf_field() }}
    <input name="bio" />
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/profile.blade.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CSRF"))).toHaveLength(0);
  });

  it("does not flag a GET form (no CSRF needed)", async () => {
    const safe = `<form method="get" action="/search">
    <input name="q" />
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/search.blade.php": safe });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CSRF"))).toHaveLength(0);
  });

  it("does not flag non-Blade PHP files", async () => {
    const vuln = `<form method="POST" action="/delete">
    <button>Delete</button>
</form>`;
    const files = makeFiles({ "composer.json": "{}", "resources/views/delete.php": vuln });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CSRF"))).toHaveLength(0);
  });
});

// ===========================================================================
// Clean project — zero findings
// ===========================================================================

describe("PHPScanAgent.scan() — clean Laravel project", () => {
  it("reports zero security findings for a well-written project", async () => {
    const cleanModel = `<?php
namespace App\\Models;
use Illuminate\\Database\\Eloquent\\Model;

class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
    protected $hidden = ['password', 'remember_token'];
}
`;
    const cleanController = `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;

class UserController extends Controller
{
    public function show(Request $request)
    {
        $users = \\DB::table('users')
            ->where('id', '?')
            ->setBindings([$request->id])
            ->get();
        return response()->json($users);
    }

    public function profile(Request $request)
    {
        $name = htmlspecialchars($request->input('name'), ENT_QUOTES, 'UTF-8');
        return view('profile', compact('name'));
    }
}
`;
    const cleanRoutes = `<?php
use App\\Http\\Controllers\\UserController;
use Illuminate\\Support\\Facades\\Route;

Route::middleware('auth')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::post('/users', [UserController::class, 'store'])->middleware('auth');
    Route::delete('/users/{id}', [UserController::class, 'destroy'])->middleware('auth');
});

Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
`;
    const cleanBlade = `<form method="POST" action="/profile">
    @csrf
    <input name="name" type="text" />
    <button type="submit">Save</button>
</form>
<p>Hello, {{ $username }}</p>
`;
    const cleanEnv = `APP_NAME=Laravel
APP_ENV=production
APP_DEBUG=false
APP_URL=https://myapp.com
`;
    const cleanCors = `<?php
return [
    'allowedOrigins' => ['https://myapp.com'],
    'allowedMethods' => ['GET', 'POST', 'PUT', 'DELETE'],
    'allowedHeaders' => ['*'],
];
`;
    const files = makeFiles({
      "composer.json": '{ "require": { "laravel/framework": "^10.0" } }',
      "app/Models/User.php": cleanModel,
      "app/Http/Controllers/UserController.php": cleanController,
      "routes/web.php": cleanRoutes,
      "resources/views/profile.blade.php": cleanBlade,
      ".env": cleanEnv,
      "config/cors.php": cleanCors,
    });

    const results = await agent.scan(files);
    expect(results).toHaveLength(0);
  });
});

// ===========================================================================
// getChecks()
// ===========================================================================

describe("PHPScanAgent.getChecks()", () => {
  const agentForChecks = new PHPScanAgent();
  const checks = agentForChecks.getChecks();

  it("returns non-empty array of check definitions", () => {
    expect(checks.length).toBeGreaterThan(0);
  });

  it("every check has required fields", () => {
    const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
    for (const check of checks) {
      expect(check.id).toBeTruthy();
      expect(check.name).toBeTruthy();
      expect(validSeverities.has(check.severity)).toBe(true);
    }
  });

  it("check IDs are unique", () => {
    const ids = checks.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("check IDs follow php: prefix convention", () => {
    for (const check of checks) {
      expect(check.id).toMatch(/^php:/);
    }
  });

  it("scan findings have checkIds matching declared checks", async () => {
    // Combine several vulnerable snippets that cover multiple checks
    const files = makeFiles({
      "composer.json": "{}",
      "app/Models/User.php": `<?php class User extends Model { }`,
      ".env": "APP_DEBUG=true\nDB_PASSWORD=secret123\n",
      "app/Helper.php": `<?php exec($command, $output);`,
      "app/Cache.php": `<?php $obj = unserialize($data);`,
      "routes/web.php": `<?php Route::post('/admin/data', [C::class, 'store']);`,
    });

    const results = await agentForChecks.scan(files);
    expect(results.length).toBeGreaterThan(0);

    const declaredIds = new Set(checks.map((c) => c.id));
    for (const result of results) {
      if (result.checkId !== undefined) {
        expect(declaredIds.has(result.checkId)).toBe(true);
      }
    }
  });
});

// ===========================================================================
// ScanResult shape
// ===========================================================================

describe("PHPScanAgent.scan() — result structure", () => {
  it("every finding has all required fields with correct types", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      "app/Models/User.php": `<?php class User extends Model {}`,
      ".env": "APP_DEBUG=true\nDB_PASSWORD=secret123\n",
      "app/Helper.php": `<?php exec($cmd);`,
      "app/Cache.php": `<?php unserialize($data);`,
      "routes/web.php": `<?php Route::post('/data', [C::class, 'store']);`,
    });

    const results = await agent.scan(files);
    expect(results.length).toBeGreaterThan(0);

    for (const result of results) {
      expect(typeof result.title).toBe("string");
      expect(result.title.length).toBeGreaterThan(0);
      expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(result.severity);
      expect(typeof result.file).toBe("string");
      expect(result.file.length).toBeGreaterThan(0);
      expect(typeof result.line).toBe("number");
      expect(result.line).toBeGreaterThanOrEqual(1);
      expect(typeof result.description).toBe("string");
      expect(result.description.length).toBeGreaterThan(0);
      expect(typeof result.fix).toBe("string");
      expect(result.fix.length).toBeGreaterThan(0);
      if (result.cwe !== undefined) {
        expect(result.cwe).toMatch(/^CWE-\d+$/);
      }
    }
  });
});

// ===========================================================================
// Confidence levels
// ===========================================================================

describe("PHPScanAgent.scan() — confidence levels", () => {
  it("eval() with $_POST gets confidence: high", async () => {
    const vuln = `<?php eval($_POST['code']);`;
    const files = makeFiles({ "composer.json": "{}", "app/Handler.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("eval()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("high");
  });

  it("eval() with a plain variable gets confidence: medium", async () => {
    const vuln = `<?php eval($template);`;
    const files = makeFiles({ "composer.json": "{}", "app/Template.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("eval()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("medium");
  });

  it("exec() in Artisan command gets confidence: low", async () => {
    const vuln = `<?php exec($cmd, $output);`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Console/Commands/DeployCommand.php": vuln,
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("exec()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });

  it("shell_exec() in Artisan command gets confidence: low", async () => {
    const vuln = `<?php $out = shell_exec($command);`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Console/Commands/BuildAssets.php": vuln,
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("shell_exec()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });

  it("unserialize() with $_POST gets confidence: high", async () => {
    const vuln = `<?php $obj = unserialize($_POST['data']);`;
    const files = makeFiles({ "composer.json": "{}", "app/Handler.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("unserialize()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("high");
  });

  it("unserialize() with plain variable gets confidence: medium", async () => {
    const vuln = `<?php $obj = unserialize($cached);`;
    const files = makeFiles({ "composer.json": "{}", "app/Cache.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("unserialize()"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("medium");
  });

  it("APP_DEBUG=true gets confidence: high", async () => {
    const files = makeFiles({ "composer.json": "{}", ".env": "APP_DEBUG=true\n" });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("APP_DEBUG"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("high");
  });

  it("mass assignment gets confidence: medium", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      "app/Models/Order.php": `<?php class Order extends Model {}`,
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("Mass assignment"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("medium");
  });

  it("XSS echo gets confidence: medium", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      "template.php": `<?php echo $name; ?>`,
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("XSS via echo"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("medium");
  });

  it("missing CSRF gets confidence: low", async () => {
    const files = makeFiles({
      "composer.json": "{}",
      "resources/views/form.blade.php": `<form method="POST" action="/submit"><button>Go</button></form>`,
    });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("CSRF"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });
});

// ===========================================================================
// SSRF — URL validation context
// ===========================================================================

describe("PHPScanAgent.scan() — check 9: SSRF with URL validation context", () => {
  it("finding has confidence: high when no validation is present", async () => {
    const vuln = `<?php $content = file_get_contents($url);`;
    const files = makeFiles({ "composer.json": "{}", "app/Fetcher.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("SSRF"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("high");
  });

  it("finding has confidence: low when filter_var FILTER_VALIDATE_URL appears within 5 lines before", async () => {
    const vuln = `<?php
$url = $_GET['url'];
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    abort(400);
}
$content = file_get_contents($url);
`;
    const files = makeFiles({ "composer.json": "{}", "app/Proxy.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("SSRF"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });

  it("finding has confidence: low when parse_url + host check appears within 5 lines before", async () => {
    const vuln = `<?php
$parsed = parse_url($url);
$host = $parsed['host'];
if (!in_array($host, $allowedDomains)) { abort(403); }
$content = file_get_contents($url);
`;
    const files = makeFiles({ "composer.json": "{}", "app/Fetcher.php": vuln });
    const results = await agent.scan(files);
    const finding = results.find((r) => r.title.includes("SSRF"));
    expect(finding).toBeDefined();
    expect(finding!.confidence).toBe("low");
  });
});

// ===========================================================================
// Global middleware suppression (Kernel.php / bootstrap/app.php)
// ===========================================================================

describe("PHPScanAgent.scan() — global middleware suppression", () => {
  it("suppresses route auth findings when Kernel.php has Authenticate middleware", async () => {
    const kernel = `<?php
namespace App\\Http;
class Kernel extends HttpKernel {
    protected $middleware = [
        \\Illuminate\\Auth\\Middleware\\Authenticate::class,
    ];
    protected $middlewareAliases = [
        'auth' => \\Illuminate\\Auth\\Middleware\\Authenticate::class,
    ];
}
`;
    const routes = `<?php
Route::post('/orders', [OrderController::class, 'store']);
Route::delete('/orders/{id}', [OrderController::class, 'destroy']);
`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Http/Kernel.php": kernel,
      "routes/api.php": routes,
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("without auth middleware"))).toHaveLength(0);
  });

  it("suppresses CSRF findings when Kernel.php has throttle (mature middleware setup)", async () => {
    const kernel = `<?php
class Kernel {
    protected $middlewareGroups = [
        'web' => [
            \\App\\Http\\Middleware\\VerifyCsrfToken::class,
            'throttle:web',
        ],
    ];
}
`;
    const blade = `<form method="POST" action="/submit"><button>Go</button></form>`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Http/Kernel.php": kernel,
      "resources/views/form.blade.php": blade,
    });
    const results = await agent.scan(files);
    expect(results.filter((r) => r.title.includes("CSRF"))).toHaveLength(0);
  });

  it("still reports other findings (non-absence-based) when global auth is present", async () => {
    const kernel = `<?php
class Kernel {
    protected $middlewareAliases = ['auth' => \\Illuminate\\Auth\\Middleware\\Authenticate::class];
}
`;
    const files = makeFiles({
      "composer.json": "{}",
      "app/Http/Kernel.php": kernel,
      ".env": "APP_DEBUG=true\n",
      "app/Models/User.php": `<?php class User extends Model {}`,
    });
    const results = await agent.scan(files);
    // APP_DEBUG and mass assignment should still fire
    expect(results.find((r) => r.title.includes("APP_DEBUG"))).toBeDefined();
    expect(results.find((r) => r.title.includes("Mass assignment"))).toBeDefined();
  });
});
