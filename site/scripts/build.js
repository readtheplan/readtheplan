const fs = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const repoRoot = path.resolve(root, "..");

// Convert YAML compliance catalogs → JSON for Pages Functions
console.log("Converting compliance catalogs...");
try {
  execSync("python3 site/scripts/convert_data.py", { cwd: repoRoot, stdio: "inherit" });
} catch (e) {
  console.error("ERROR: data conversion failed; refusing to build with stale data");
  process.exit(1);
}

const dist = path.join(root, "dist");
const demoSource = path.join(
  repoRoot,
  "examples",
  "02-dangerous-replacement",
  "evidence.json",
);
const files = [
  "index.html",
  "styles.css",
  "matrix.css",
  "matrix.js",
  "app.js",
  "404.html",
  "favicon.svg",
  "og-image.png",
  "robots.txt",
  "sitemap.xml",
  "_redirects",
];
const assetDirs = ["fonts", "img", "tools", "resources", "mcp", "brief", "demo", "docs", "playground", "pricing", "terms", "privacy", "blog", "data", "chat"];

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

for (const file of files) {
  fs.copyFileSync(path.join(root, file), path.join(dist, file));
}

for (const dir of assetDirs) {
  const source = path.join(root, dir);
  if (fs.existsSync(source)) {
    fs.cpSync(source, path.join(dist, dir), { recursive: true });
  }
}

fs.copyFileSync(demoSource, path.join(dist, "demo-evidence.json"));

// Copy Cloudflare Pages Functions
const functionsDir = path.join(root, "functions");
if (fs.existsSync(functionsDir)) {
  fs.cpSync(functionsDir, path.join(dist, "functions"), { recursive: true });
  console.log("Copied functions/ to dist/");
}

// Generate _routes.json — only API/health routes go to Functions
fs.writeFileSync(
  path.join(dist, "_routes.json"),
  JSON.stringify({
    version: 1,
    include: ["/api/*", "/health", "/openapi.json"],
    exclude: []
  }, null, 2),
  "utf8"
);

fs.writeFileSync(
  path.join(dist, "_headers"),
  [
    "/*",
    "  Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; font-src 'self'; img-src 'self' data:; media-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests",
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

// Normalize absolute paths for root-domain hosting (Azure/GitHub/custom domain)
const htmlFiles = [];
function collectHtml(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectHtml(full);
    else if (entry.name.endsWith(".html")) htmlFiles.push(full);
  }
}
collectHtml(dist);

const basePath = "";  // custom domain (readtheplan.dev) — site at root
for (const file of htmlFiles) {
  let content = fs.readFileSync(file, "utf8");
  // Fix href and src that start with / but not // or http
  content = content.replace(/(href|src)="\/(?!\/)([^"]*)"/g, `$1="${basePath}/$2"`);
  fs.writeFileSync(file, content, "utf8");
}
console.log(`Fixed absolute paths in ${htmlFiles.length} HTML files`);

console.log(`Built site into ${path.relative(process.cwd(), dist)}`);
