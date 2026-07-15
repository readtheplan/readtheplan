import assert from "node:assert/strict";
import fs from "node:fs/promises";

const dist = new URL("../dist/", import.meta.url);
const routes = [
  "index.html",
  "404.html",
  "blog/index.html",
  "brief/index.html",
  "brief/sample-001/index.html",
  "chat/index.html",
  "demo/index.html",
  "docs/index.html",
  "docs/faq.html",
  "docs/adapters/index.html",
  "docs/cli/index.html",
  "docs/ci/index.html",
  "docs/github-action/index.html",
  "docs/quickstart/index.html",
  "mcp/index.html",
  "playground/index.html",
  "pricing/index.html",
  "privacy/index.html",
  "resources/terraform-cloudwatch-log-retention-risk/index.html",
  "resources/terraform-iam-policy-risk/index.html",
  "resources/terraform-s3-bucket-risk/index.html",
  "resources/terraform-security-group-0-0-0-0-risk/index.html",
  "terms/index.html",
  "tools/soc2-cloud-control-mapper/index.html",
  "tools/terraform-risk-calculator/index.html",
];

const pyproject = await fs.readFile(new URL("../../pyproject.toml", import.meta.url), "utf8");
const version = pyproject.match(/^version\s*=\s*"([^"]+)"/m)[1];

for (const route of routes) {
  const html = await fs.readFile(new URL(route, dist), "utf8");
  assert.equal((html.match(/site-header:start/g) || []).length, 1, `${route} header`);
  assert.equal((html.match(/site-footer:start/g) || []).length, 1, `${route} footer`);
  assert.match(html, /class="site-nav"/);
  assert.match(html, /class="site-footer"/);
  assert.ok(html.includes(`class="site-brand__version">v${version}<`), `${route} version badge`);
  assert.match(html, /href="\/modern\.css"/);
  assert.doesNotMatch(html, /__READTHEPLAN_VERSION__/);
}

// The effective CSP ships from dist/_headers. Exhaustive: assert the exact
// policy line so any drift — added sources, dropped directives, inline
// allowances — fails loudly rather than passing a substring check.
const headers = await fs.readFile(new URL("_headers", dist), "utf8");
const expectedCsp =
  "Content-Security-Policy: default-src 'self'; " +
  "script-src 'self' https://plausible.io; " +
  "style-src 'self' 'unsafe-inline'; " +
  "connect-src 'self' https://plausible.io; " +
  "font-src 'self'; img-src 'self' data:; media-src 'self'; " +
  "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; " +
  "form-action 'none'; upgrade-insecure-requests";
const cspLines = headers.split("\n").filter((line) => line.includes("Content-Security-Policy"));
assert.equal(cspLines.length, 1, "exactly one CSP definition");
assert.equal(cspLines[0].trim(), expectedCsp, "dist/_headers CSP must equal the canonical policy byte-for-byte");
for (const header of [
  "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options: nosniff",
  "X-Frame-Options: DENY",
  "Referrer-Policy: strict-origin-when-cross-origin",
  "Cross-Origin-Opener-Policy: same-origin",
  "Cross-Origin-Resource-Policy: same-origin",
]) {
  assert.ok(headers.includes(header), `dist/_headers must ship: ${header}`);
}

// Cloudflare Pages compiles Functions from the SOURCE tree (project root),
// never from dist — so dist must not contain an inert functions copy, and
// source functions must carry the real pyproject version.
const sourceFunctions = new URL("../functions/", import.meta.url);
await assert.rejects(fs.access(new URL("functions/", dist)), "dist/functions must not exist (inert copy)");
const chatFn = await fs.readFile(new URL("api/chat.js", sourceFunctions), "utf8");
const chatVersions = [...chatFn.matchAll(/readtheplan\/readtheplan@v(\d+\.\d+\.\d+)/g)].map((m) => m[1]);
assert.ok(chatVersions.length > 0, "chat prompt must pin the action version");
for (const found of chatVersions) assert.equal(found, version, "chat prompt version equals pyproject");
assert.doesNotMatch(chatFn, /__READTHEPLAN_VERSION__/);
const openapiFn = await fs.readFile(new URL("openapi.json.js", sourceFunctions), "utf8");
const openapiVersion = openapiFn.match(/version: "(\d+\.\d+\.\d+)"/);
assert.ok(openapiVersion, "openapi must declare an exact semver version");
assert.equal(openapiVersion[1], version, "openapi version equals pyproject");
assert.doesNotMatch(openapiFn, /__READTHEPLAN_VERSION__/);

for (const asset of [
  "llms.txt",
  "robots.txt",
  "sitemap.xml",
  "modern.css",
  "_headers",
  "_routes.json",
  "playground/compliance.json",
  "playground/risk-floors.js",
]) {
  await fs.access(new URL(asset, dist));
}

const sourceRiskFloors = await fs.readFile(
  new URL("../playground/risk-floors.js", import.meta.url),
  "utf8",
);
const builtRiskFloors = await fs.readFile(new URL("playground/risk-floors.js", dist), "utf8");
assert.equal(builtRiskFloors, sourceRiskFloors, "built classifier risk floors");
const playgroundHtml = await fs.readFile(new URL("playground/index.html", dist), "utf8");
assert.ok(
  playgroundHtml.indexOf('/playground/risk-floors.js') <
    playgroundHtml.indexOf('/playground/classifier.js'),
  "playground must load generated risk floors before the classifier",
);

const browserCompliance = JSON.parse(
  await fs.readFile(new URL("playground/compliance.json", dist), "utf8"),
);
const dataIndex = JSON.parse(await fs.readFile(new URL("data/index.json", dist), "utf8"));
const comparedFrameworks = new Set();
for (const { file } of Object.values(dataIndex.frameworks)) {
  const canonicalCatalog = JSON.parse(
    await fs.readFile(new URL(`data/${file}`, dist), "utf8"),
  );
  const framework = canonicalCatalog.framework;
  const browserCatalog = browserCompliance[framework];
  assert.ok(browserCatalog, `${framework} browser catalog`);
  comparedFrameworks.add(framework);
  assert.equal(browserCatalog.framework, canonicalCatalog.framework, `${framework} framework`);
  assert.equal(
    browserCatalog.version,
    canonicalCatalog.framework_version || "",
    `${framework} version`,
  );
  assert.deepEqual(
    browserCatalog.mappings,
    canonicalCatalog.mappings,
    `${framework} browser catalog must match canonical mappings`,
  );
}
assert.deepEqual(
  [...comparedFrameworks].sort(),
  Object.keys(browserCompliance).sort(),
  "browser and canonical framework sets",
);

const sitemap = await fs.readFile(new URL("sitemap.xml", dist), "utf8");
for (const route of [
  "/blog/",
  "/chat/",
  "/docs/adapters/",
  "/docs/ci/",
  "/docs/faq.html",
  "/pricing/",
  "/privacy/",
  "/terms/",
]) {
  assert.match(sitemap, new RegExp(`<loc>https://readtheplan\\.dev${route.replaceAll(".", "\\.")}</loc>`));
}

console.log(`Cloudflare Pages build contract: ${routes.length} HTML routes passed.`);
