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

for (const route of routes) {
  const html = await fs.readFile(new URL(route, dist), "utf8");
  assert.equal((html.match(/site-header:start/g) || []).length, 1, `${route} header`);
  assert.equal((html.match(/site-footer:start/g) || []).length, 1, `${route} footer`);
  assert.match(html, /class="site-nav"/);
  assert.match(html, /class="site-footer"/);
  assert.match(html, /class="site-brand__version">v0\.4\.0</);
  assert.match(html, /href="\/modern\.css"/);
  assert.doesNotMatch(html, /__READTHEPLAN_VERSION__/);
}

for (const asset of [
  "llms.txt",
  "robots.txt",
  "sitemap.xml",
  "matrix.css",
  "modern.css",
  "_headers",
  "_routes.json",
  "functions/api/chat.js",
]) {
  await fs.access(new URL(asset, dist));
}

const sitemap = await fs.readFile(new URL("sitemap.xml", dist), "utf8");
for (const route of [
  "/blog/",
  "/chat/",
  "/docs/adapters/",
  "/docs/faq.html",
  "/pricing/",
  "/privacy/",
  "/terms/",
]) {
  assert.match(sitemap, new RegExp(`<loc>https://readtheplan\\.dev${route.replaceAll(".", "\\.")}</loc>`));
}

console.log(`Cloudflare Pages build contract: ${routes.length} HTML routes passed.`);
