import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");

async function htmlFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await htmlFiles(target));
    else if (entry.name.endsWith(".html")) files.push(target);
  }
  return files;
}

const files = await htmlFiles(dist);
assert.equal(files.length, 25, "the production build must contain all 25 HTML routes");

const routeClassPattern = /class="[^"]*route-(?:home|docs|playground|pricing|chat|mcp|demo|tool|editorial|legal|not-found|standard)[^"]*"/;
for (const file of files) {
  const html = await readFile(file, "utf8");
  const route = path.relative(dist, file).replaceAll("\\", "/");
  assert.match(html, /<meta name="viewport"/i, `${route} needs responsive viewport metadata`);
  assert.match(html, /<title>[^<]+<\/title>/i, `${route} needs a document title`);
  assert.match(html, /<h1\b/i, `${route} needs one primary heading`);
  assert.match(html, /href="\/modern\.css"/, `${route} needs the shared visual system`);
  assert.match(html, /src="\/site-motion\.js"/, `${route} needs shared interaction behavior`);
  assert.match(html, /class="site-nav"/, `${route} needs shared navigation`);
  assert.match(html, /class="site-footer"/, `${route} needs the shared footer`);
  assert.match(html, routeClassPattern, `${route} needs a page-family class`);
  assert.doesNotMatch(html, /__READTHEPLAN_VERSION__/, `${route} contains an unresolved version token`);

  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, `${route} contains duplicate IDs`);
}

const critical = new Map([
  ["index.html", ["scan-tabs", "startInteractiveDemo"]],
  ["docs/index.html", ["card-grid", "Documentation"]],
  ["playground/index.html", ["playground-drop-zone", "riskMeter"]],
  ["pricing/index.html", ["pricing-card", "$0"]],
  ["chat/index.html", ["chat-container", "chat-input-area"]],
  ["demo/index.html", ["terminal-frame", "risk-meter"]],
  ["mcp/index.html", ["control-map", "code-output"]],
  ["tools/terraform-risk-calculator/index.html", ["riskCalculator", "result-card"]],
]);

for (const [route, markers] of critical) {
  const html = await readFile(path.join(dist, route), "utf8");
  for (const marker of markers) assert.ok(html.includes(marker), `${route} lost ${marker}`);
}

console.log("Rendered-route contract: 25 routes and critical components passed.");
