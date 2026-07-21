/**
 * AegisLab - remediation.js
 * ===========================
 * Turns raw findings into a prioritized "what to fix first" action list with
 * concrete, copy-pasteable code snippets — not just prose recommendations.
 *
 * This is intentionally a static, hand-curated mapping (keyed by stable
 * substrings of each test module's `issue` text) rather than an AI call:
 * it's fast, free, works fully offline, and never invents wrong advice.
 * Findings that don't match a known snippet still get a priority ranking
 * and the original recommendation text, just without a code block.
 */

const SEVERITY_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// Each entry: an array of [matcher, snippet-builder]. The matcher tests
// against the finding's `issue` string (lowercased). First match wins.
const SNIPPET_RULES = [
  [
    /alg.*none/,
    () => ({
      lang: "javascript",
      title: "Reject alg:none JWTs",
      code:
`// When verifying, pin the expected algorithm explicitly —
// never let the token's own header decide how it's checked.
jwt.verify(token, SECRET, { algorithms: ["HS256"] });`,
    }),
  ],
  [
    /no expiry|missing.*exp/,
    () => ({
      lang: "javascript",
      title: "Issue short-lived tokens",
      code:
`jwt.sign(payload, SECRET, { expiresIn: "15m" }); // + refresh token flow`,
    }),
  ],
  [
    /invalid.*bearer token|malformed.*token/,
    () => ({
      lang: "javascript",
      title: "Fail closed on token verification errors",
      code:
`try {
  req.user = jwt.verify(token, SECRET);
} catch {
  return res.status(401).json({ error: "Invalid or expired token" });
}`,
    }),
  ],
  [
    /accessible without authentication|missing without auth/,
    () => ({
      lang: "javascript",
      title: "Add an auth guard before the handler",
      code:
`// Express
router.get("/protected", requireAuth, handler);

// NestJS
@UseGuards(AuthGuard("jwt"))
@Get("protected")
handler() { ... }`,
    }),
  ],
  [
    /account existence|enumeration/,
    () => ({
      lang: "javascript",
      title: "Return an identical error for both cases",
      code:
`// Don't distinguish "no such user" from "wrong password"
if (!user || !(await bcrypt.compare(password, user.hash))) {
  return res.status(401).json({ error: "Invalid email or password" });
}`,
    }),
  ],
  [
    /broken object level authorization|idor|bola/,
    () => ({
      lang: "javascript",
      title: "Scope the query to the authenticated user",
      code:
`// Don't trust the :id alone — constrain by ownership too
const record = await db.orders.findOne({
  id: req.params.id,
  ownerId: req.user.id, // <-- the missing piece
});
if (!record) return res.status(404).end();`,
    }),
  ],
  [
    /privileged.*administrative endpoint|function level authorization/,
    () => ({
      lang: "javascript",
      title: "Add a role check, separate from auth",
      code:
`// Express
router.get("/admin/dashboard", requireAuth, requireRole("admin"), handler);

// NestJS
@UseGuards(AuthGuard("jwt"), RolesGuard)
@Roles("admin")
@Get("admin/dashboard")
handler() { ... }`,
    }),
  ],
  [
    /sql injection/,
    () => ({
      lang: "javascript",
      title: "Use parameterized queries — never concatenate",
      code:
`// Bad:  db.query(\`SELECT * FROM users WHERE email = '\${email}'\`)
// Good:
db.query("SELECT * FROM users WHERE email = $1", [email]);`,
    }),
  ],
  [
    /nosql operator injection/,
    () => ({
      lang: "javascript",
      title: "Reject non-string values where a string is expected",
      code:
`if (typeof req.body.email !== "string") {
  return res.status(400).json({ error: "Invalid input" });
}`,
    }),
  ],
  [
    /reflected.*xss|not html-escaped/,
    () => ({
      lang: "javascript",
      title: "Escape output, or use a templating engine that auto-escapes",
      code:
`const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));
res.send(\`Results for: \${escapeHtml(query)}\`);`,
    }),
  ],
  [
    /no rate limiting/,
    () => ({
      lang: "javascript",
      title: "Add rate limiting to this route",
      code:
`// Express
const rateLimit = require("express-rate-limit");
app.use("/auth/login", rateLimit({ windowMs: 60_000, max: 10 }));

// NestJS — register ThrottlerModule in AppModule, then:
@UseGuards(ThrottlerGuard)
@Post("auth/login")
login() { ... }`,
    }),
  ],
  [
    /sensitive.*credential-like fields|excessive data exposure/,
    () => ({
      lang: "javascript",
      title: "Use a response DTO, don't return the raw row",
      code:
`// Bad:  return res.json(userRow);
// Good:
return res.json({
  id: userRow.id,
  email: userRow.email,
  // password_hash, __v, internal_notes deliberately omitted
});`,
    }),
  ],
  [
    /x-powered-by/,
    () => ({
      lang: "javascript",
      title: "Disable the X-Powered-By header",
      code: `app.disable("x-powered-by"); // Express\n// or: app.use(helmet.hidePoweredBy());`,
    }),
  ],
  [
    /wildcard origin and credentials|dangerous cors/,
    () => ({
      lang: "javascript",
      title: "Never combine wildcard origin with credentials",
      code:
`app.use(cors({
  origin: ["https://app.yourdomain.com"], // explicit allow-list, not "*"
  credentials: true,
}));`,
    }),
  ],
  [
    /cors allows requests from any origin/,
    () => ({
      lang: "javascript",
      title: "Restrict CORS to known origins",
      code: `app.use(cors({ origin: ["https://app.yourdomain.com"] }));`,
    }),
  ],
  [
    /unencrypted http/,
    () => ({
      lang: "nginx",
      title: "Redirect all HTTP to HTTPS",
      code:
`server {
  listen 80;
  return 301 https://$host$request_uri;
}`,
    }),
  ],
  [
    /strict-transport-security|hsts/,
    () => ({
      lang: "javascript",
      title: "Add HSTS via helmet",
      code:
`const helmet = require("helmet");
app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));`,
    }),
  ],
  [
    /missing recommended security headers/,
    () => ({
      lang: "javascript",
      title: "Add helmet for baseline security headers",
      code: `npm install helmet\n// then:\napp.use(require("helmet")());`,
    }),
  ],
  [
    /cookie missing/,
    () => ({
      lang: "javascript",
      title: "Set secure cookie flags",
      code: `res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "strict" });`,
    }),
  ],
  [
    /legacy.*tls|weak tls/,
    () => ({
      lang: "nginx",
      title: "Disable TLS versions below 1.2",
      code: `ssl_protocols TLSv1.2 TLSv1.3;`,
    }),
  ],
  // ---- static scanner findings ----
  [
    /hardcoded aws access key/,
    () => ({
      lang: "bash",
      title: "Rotate immediately, then move to env vars",
      code:
`# 1. Revoke the key in AWS IAM console right now.
# 2. Move the new one to an env var:
export AWS_ACCESS_KEY_ID="..."   # never hardcode in source`,
    }),
  ],
  [
    /stripe live secret key/,
    () => ({
      lang: "bash",
      title: "Roll the key in the Stripe dashboard, then use env vars",
      code: `// In code:\nconst stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);`,
    }),
  ],
  [
    /google api key/,
    () => ({
      lang: "javascript",
      title: "Restrict the key, then load from env",
      code: `const key = process.env.GOOGLE_MAPS_API_KEY;`,
    }),
  ],
  [
    /private key material/,
    () => ({
      lang: "bash",
      title: "Rotate the key pair, never commit private keys",
      code: `# Load from a mounted secret file or secrets manager at runtime,\n# and add the filename to .gitignore.`,
    }),
  ],
  [
    /service_role key/,
    () => ({
      lang: "javascript",
      title: "Use the anon key client-side, service_role only on trusted servers",
      code:
`// Client-side / anywhere browser-reachable:
const supabase = createClient(URL, process.env.SUPABASE_ANON_KEY);

// Server-side only, never shipped to a client:
const supabaseAdmin = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    }),
  ],
  [
    /environment file committed/,
    () => ({
      lang: "bash",
      title: "Untrack it and ignore it going forward",
      code: `echo ".env" >> .gitignore\ngit rm --cached .env`,
    }),
  ],
  [
    /possible hardcoded credential/,
    () => ({
      lang: "javascript",
      title: "Move it to an environment variable",
      code: `const value = process.env.YOUR_VARIABLE_NAME;`,
    }),
  ],
  [
    /no helmet\(\) security-headers/,
    () => ({
      lang: "bash",
      title: "Install and wire up helmet",
      code: `npm install helmet\n// then: app.use(require("helmet")());`,
    }),
  ],
  [
    /no rate-limiting middleware detected/,
    () => ({
      lang: "bash",
      title: "Install express-rate-limit",
      code:
`npm install express-rate-limit
// app.use("/auth", require("express-rate-limit")({ windowMs: 60000, max: 10 }));`,
    }),
  ],
  [
    /no global validationpipe/,
    () => ({
      lang: "typescript",
      title: "Add a global ValidationPipe",
      code: `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));`,
    }),
  ],
  [
    /no @nestjs\/throttler/,
    () => ({
      lang: "bash",
      title: "Install and register ThrottlerModule",
      code: `npm install @nestjs/throttler\n// register ThrottlerModule.forRoot([...]) in AppModule`,
    }),
  ],
  [
    /mass assignment/,
    () => ({
      lang: "javascript",
      title: "Allowlist writable fields explicitly (DTO pattern)",
      code:
`// Express — never do this:
//   const user = await User.create(req.body);
// Instead, pick only the fields the client is allowed to set:
const { name, email } = req.body; // role/isAdmin/price etc simply don't exist here
const user = await User.create({ name, email });

// NestJS — same idea via a DTO + whitelist validation:
// class CreateUserDto { name: string; email: string; }  // no "role" field at all
// app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));`,
    }),
  ],
  [
    /server[- ]side request forgery|\bssrf\b/,
    () => ({
      lang: "javascript",
      title: "Allowlist destinations before fetching a user-supplied URL",
      code:
`const { URL } = require("url");
const ALLOWED_HOSTS = new Set(["images.trusted-cdn.com"]);
const PRIVATE_RANGES = [/^10\\./, /^127\\./, /^169\\.254\\./, /^172\\.(1[6-9]|2\\d|3[0-1])\\./, /^192\\.168\\./];

function assertSafeFetchTarget(rawUrl) {
  const u = new URL(rawUrl);
  if (u.protocol !== "https:") throw new Error("only https allowed");
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error("host not allowlisted");
  if (PRIVATE_RANGES.some((re) => re.test(u.hostname))) throw new Error("private/internal address blocked");
  return u;
}
// then: fetch(assertSafeFetchTarget(userSuppliedUrl).toString(), { redirect: "error" });`,
    }),
  ],
];

function findSnippet(issueLower) {
  for (const [matcher, build] of SNIPPET_RULES) {
    if (matcher.test(issueLower)) return build();
  }
  return null;
}

/**
 * Ranks findings by severity (CRITICAL first), then attaches a code snippet
 * where one is known. Returns the top N for the "Top Priority Fixes" panel.
 */
function buildPriorityFixes(vulnerabilities, limit = 5) {
  const ranked = [...vulnerabilities].sort(
    (a, b) => (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0)
  );
  return ranked.slice(0, limit).map((v) => ({
    ...v,
    snippet: findSnippet(v.issue.toLowerCase()),
  }));
}
