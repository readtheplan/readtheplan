import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const modern = await readFile(path.join(root, "modern.css"), "utf8");
const motion = await readFile(path.join(root, "site-motion.js"), "utf8");
const config = await readFile(path.join(root, "eleventy.config.cjs"), "utf8");

for (const routeClass of [
  "route-docs", "route-playground", "route-pricing", "route-chat", "route-mcp",
  "route-demo", "route-tool", "route-editorial", "route-legal", "route-not-found",
]) {
  assert.match(modern, new RegExp(`\\.${routeClass}\\b`), `${routeClass} must have a visual treatment`);
  assert.match(config, new RegExp(`"${routeClass}"`), `${routeClass} must be assigned during build`);
}

for (const component of [
  ".site-nav", ".site-footer", ".utility-hero", ".card-grid", ".control-map",
  ".playground-drop-zone", ".pricing-card", ".chat-container", ".prose", ".not-found",
]) {
  assert.ok(modern.includes(component), `${component} must be covered by the shared design system`);
}

assert.match(modern, /@media \(max-width: 720px\)/);
assert.match(modern, /@media \(prefers-reduced-motion: reduce\)/);
assert.match(modern, /:focus-visible/);

// Control-map rows carry three fields (label / purpose / detail) on the MCP,
// brief, and control-mapper routes. Pin the exact three-track grid and its
// single-column mobile collapse — and assert these are the ONLY
// grid-template-columns declarations that can ever apply to the row, so an
// overriding rule elsewhere cannot silently change the layout.
const controlMapDeclarations = [...modern.matchAll(/\.control-map-row[^{]*\{[^}]*?grid-template-columns:\s*([^;]+);/g)]
  .map((match) => match[1].trim());
assert.deepEqual(
  controlMapDeclarations,
  ["minmax(150px, 0.7fr) minmax(0, 1.1fr) minmax(0, 1.2fr)", "minmax(0, 1fr)"],
  "control-map rows must have exactly two grid declarations: the three-track desktop grid and the one-column mobile collapse",
);
assert.match(
  modern,
  /@media \(max-width: 720px\) \{\s*\n\s*\.control-map-row \{ grid-template-columns: minmax\(0, 1fr\); \}/,
  "the one-column declaration must live in the mobile media query",
);
// No other selector may set grid-template-columns on control-map rows.
const foreignOverrides = [...modern.matchAll(/^([^@{}]+)\{[^}]*grid-template-columns/gm)]
  .map((m) => m[1].trim())
  .filter((sel) => sel.includes("control-map") && !sel.startsWith(".control-map-row"));
assert.deepEqual(foreignOverrides, [], "no foreign selector may override control-map row columns");
assert.match(motion, /IntersectionObserver/);
assert.match(motion, /aria-current/);
assert.match(motion, /pointermove/);
assert.match(motion, /code-shell__copy/);
assert.match(config, /site-motion\.js/);

async function htmlCount(directory) {
  let count = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (["dist", "node_modules"].includes(entry.name)) continue;
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) count += await htmlCount(target);
    else if (entry.name.endsWith(".html")) count += 1;
  }
  return count;
}

assert.equal(await htmlCount(root), 25, "all 25 source routes remain present");
console.log("Design-system source contract: all page families and accessibility states covered.");
