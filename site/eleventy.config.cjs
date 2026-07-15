const fs = require("node:fs");
const path = require("node:path");

const siteRoot = __dirname;
const repoRoot = path.resolve(siteRoot, "..");

function projectVersion() {
  const pyproject = fs.readFileSync(path.join(repoRoot, "pyproject.toml"), "utf8");
  const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("Could not read project version from pyproject.toml");
  return match[1];
}

function routeClassForUrl(url = "/") {
  if (url === "/") return "route-home";
  if (url.startsWith("/docs/")) return "route-docs";
  if (url.startsWith("/playground/")) return "route-playground";
  if (url.startsWith("/pricing/")) return "route-pricing";
  if (url.startsWith("/chat/")) return "route-chat";
  if (url.startsWith("/mcp/")) return "route-mcp";
  if (url.startsWith("/demo/")) return "route-demo";
  if (url.startsWith("/tools/") || url.startsWith("/resources/")) return "route-tool";
  if (url.startsWith("/blog/") || url.startsWith("/brief/")) return "route-editorial";
  if (url.startsWith("/privacy/") || url.startsWith("/terms/")) return "route-legal";
  if (url.startsWith("/404")) return "route-not-found";
  return "route-standard";
}

module.exports = function (eleventyConfig) {
  const version = projectVersion();

  // Every template owns its chrome through layouts/base.njk. Shared data:
  eleventyConfig.addGlobalData("layout", "layouts/base.njk");
  eleventyConfig.addGlobalData("eleventyComputed", {
    routeClass: (data) => data.routeClass || routeClassForUrl(data.page.url),
  });

  // NOTE: functions/ is deliberately NOT copied into dist — Cloudflare Pages
  // compiles Functions from the project-root functions/ directory, so a dist
  // copy would be inert and could mask divergence from what actually deploys.
  for (const entry of [
    "modern.css", "site-motion.js",
    "js",
    "favicon.svg", "og-image.png", "og-image-modern.png", "robots.txt", "llms.txt", "sitemap.xml", "_redirects",
    "fonts", "img", "data", "tools/tools.js",
    "playground/classifier.js", "playground/playground.js", "playground/risk-floors.js",
    "playground/compliance.json", "playground/floci-spike-create-plan.json",
    "playground/floci-spike-destroy-plan.json", "playground/floci-samples.meta.json",
    "chat/chat.js",
  ]) {
    eleventyConfig.addPassthroughCopy(entry);
  }

  // Single-source the displayed version. Pages and layouts write
  // __READTHEPLAN_VERSION__; nothing else may hardcode a version string.
  eleventyConfig.addTransform("version-token", function (content) {
    if (!this.page.outputPath?.endsWith(".html")) return content;
    return content.replaceAll("__READTHEPLAN_VERSION__", version);
  });

  return {
    dir: { input: ".", output: "dist", includes: "_includes" },
    htmlTemplateEngine: false,
    markdownTemplateEngine: false,
    templateFormats: ["html"],
  };
};
