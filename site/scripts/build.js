const fs = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const repoRoot = path.resolve(root, "..");
const dist = path.join(root, "dist");

function projectVersion() {
  const pyproject = fs.readFileSync(path.join(repoRoot, "pyproject.toml"), "utf8");
  const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("Could not read project version from pyproject.toml");
  return match[1];
}

console.log("Generating browser security artifacts...");
const python = process.platform === "win32" ? "python" : "python3";
try {
  execSync(`${python} site/scripts/build-classifier-risk-floors.py`, { cwd: repoRoot, stdio: "inherit" });
  execSync(`${python} site/scripts/build-compliance-json.py`, { cwd: repoRoot, stdio: "inherit" });
  execSync(`${python} site/scripts/convert_data.py`, { cwd: repoRoot, stdio: "inherit" });
} catch (_error) {
  console.error("ERROR: browser security artifact generation failed; refusing to build with stale data");
  process.exit(1);
}

fs.rmSync(dist, { recursive: true, force: true });
console.log("Compiling static routes with Eleventy...");
execSync("npx eleventy --config=eleventy.config.cjs", { cwd: root, stdio: "inherit" });

// Eleventy emits non-index HTML inputs as directory indexes by default. Keep
// the two historical flat URLs stable for existing links and the sitemap.
for (const [generated, stable] of [
  [path.join(dist, "404", "index.html"), path.join(dist, "404.html")],
  [path.join(dist, "docs", "faq", "index.html"), path.join(dist, "docs", "faq.html")],
]) {
  fs.renameSync(generated, stable);
  fs.rmSync(path.dirname(generated), { recursive: true, force: true });
}

const demoSource = path.join(repoRoot, "examples", "02-dangerous-replacement", "evidence.json");
fs.copyFileSync(demoSource, path.join(dist, "demo-evidence.json"));

// Cloudflare Pages compiles Functions from the PROJECT-ROOT functions/
// directory, not from the build output — so source functions must carry a
// real version literal (build-time substitution in dist/functions would
// never reach production). Enforce that the literal matches pyproject here
// and in the contract tests; a release bump fails the build until the
// functions are updated.
const version = projectVersion();
for (const fn of ["api/chat.js", "openapi.json.js"]) {
  const source = fs.readFileSync(path.join(root, "functions", fn), "utf8");
  if (source.includes("__READTHEPLAN_VERSION__")) {
    throw new Error(`functions/${fn} must not use the version placeholder — Pages deploys source functions verbatim.`);
  }
  if (!source.includes(version)) {
    throw new Error(`functions/${fn} version literal is stale (expected ${version}).`);
  }
}

// Generate _routes.json — only API/health routes go to Functions
fs.writeFileSync(
  path.join(dist, "_routes.json"),
  JSON.stringify({ version: 1, include: ["/api/*", "/health", "/openapi.json"], exclude: [] }, null, 2),
  "utf8",
);

// Single source of truth for the shipped security headers. Inline event
// handlers and <script> blocks were removed site-wide, so scripts execute
// only from same-origin files. Plausible is an API destination, not a
// script source; there is no inline allowance for scripts.
fs.writeFileSync(
  path.join(dist, "_headers"),
  [
    "/*",
    "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://plausible.io; font-src 'self'; img-src 'self' data:; media-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests",
    "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "  Access-Control-Allow-Origin: https://readtheplan.dev",
    "  Cross-Origin-Opener-Policy: same-origin",
    "  Cross-Origin-Resource-Policy: same-origin",
    "  X-Content-Type-Options: nosniff",
    "  X-DNS-Prefetch-Control: off",
    "  X-Frame-Options: DENY",
    "  Referrer-Policy: strict-origin-when-cross-origin",
    "  Permissions-Policy: accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()",
    "",
  ].join("\n"),
  "utf8",
);

const htmlFiles = [];
function collectHtml(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectHtml(full);
    else if (entry.name.endsWith(".html")) htmlFiles.push(full);
  }
}
collectHtml(dist);

for (const file of htmlFiles) {
  const content = fs.readFileSync(file, "utf8");
  if ((content.match(/site-header:start/g) || []).length !== 1) {
    throw new Error(`Expected one canonical header in ${file}`);
  }
  if ((content.match(/site-footer:start/g) || []).length !== 1) {
    throw new Error(`Expected one canonical footer in ${file}`);
  }
  if (!content.includes('href="/modern.css"')) {
    throw new Error(`Expected modern design system in ${file}`);
  }
  if (content.includes("__READTHEPLAN_VERSION__")) {
    throw new Error(`Unresolved version placeholder in ${file}`);
  }
  // Version strings must come from pyproject via the placeholder — never a
  // literal. Covers v-prefixed strings and pip pins (readtheplan==X.Y.Z).
  for (const match of content.matchAll(/\bv(\d+\.\d+\.\d+)\b|readtheplan==(\d+\.\d+\.\d+)/g)) {
    const found = match[1] || match[2];
    if (found !== version) {
      throw new Error(`Stale hardcoded version ${found} in ${file}`);
    }
  }
  // CSP compatibility: no inline script blocks or handlers may ship.
  if (/<script(?:\s[^>]*)?>(?!\s*<\/script>)[\s\S]*?<\/script>/.test(content.replace(/<script[^>]*\ssrc="[^"]*"[^>]*>\s*<\/script>/g, ""))) {
    throw new Error(`Inline <script> block shipped in ${file} (CSP forbids it)`);
  }
  // Any on*-attribute (onclick, onmouseover, onpointerdown, …), with or
  // without whitespace around '='.
  if (/\son[a-z]+\s*=/i.test(content)) {
    throw new Error(`Inline event handler shipped in ${file} (CSP forbids it)`);
  }
}

console.log(`Eleventy built ${htmlFiles.length} HTML routes with shared chrome (v${version}).`);
console.log(`Built site into ${path.relative(process.cwd(), dist)}`);
