const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const repoRoot = path.resolve(root, "..");
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
  "app.js",
  "404.html",
  "favicon.svg",
  "og-image.png",
  "robots.txt",
  "sitemap.xml",
  "_redirects",
];
const assetDirs = ["fonts", "img"];

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

for (const file of files) {
  fs.copyFileSync(path.join(root, file), path.join(dist, file));
}

for (const dir of assetDirs) {
  fs.cpSync(path.join(root, dir), path.join(dist, dir), { recursive: true });
}

fs.copyFileSync(demoSource, path.join(dist, "demo-evidence.json"));

fs.writeFileSync(
  path.join(dist, "_headers"),
  [
    "/*",
    "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests",
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

console.log(`Built site into ${path.relative(process.cwd(), dist)}`);
