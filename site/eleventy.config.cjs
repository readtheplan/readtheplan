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

function partial(name) {
  return fs.readFileSync(path.join(siteRoot, "_includes", name), "utf8");
}

function routeClass(outputPath = "") {
  const fullPath = outputPath.replaceAll("\\", "/");
  const route = fullPath.includes("/dist/") ? fullPath.split("/dist/").at(-1) : fullPath;
  const inRoute = (name) => route.startsWith(`${name}/`) || route.includes(`/${name}/`);
  if (route === "index.html" || route === "/index.html") return "route-home";
  if (inRoute("docs")) return "route-docs";
  if (inRoute("playground")) return "route-playground";
  if (inRoute("pricing")) return "route-pricing";
  if (inRoute("chat")) return "route-chat";
  if (inRoute("mcp")) return "route-mcp";
  if (inRoute("demo")) return "route-demo";
  if (inRoute("tools") || inRoute("resources")) return "route-tool";
  if (inRoute("blog") || inRoute("brief")) return "route-editorial";
  if (inRoute("privacy") || inRoute("terms")) return "route-legal";
  if (inRoute("404")) return "route-not-found";
  return "route-standard";
}

module.exports = function (eleventyConfig) {
  const version = projectVersion();
  const canonicalHeader = partial("site-header.njk").replaceAll("__READTHEPLAN_VERSION__", version);
  const canonicalFooter = partial("site-footer.njk");

  for (const entry of [
    "styles.css", "matrix.css", "home.css", "modern.css", "site-motion.js", "matrix.js", "app.js",
    "favicon.svg", "og-image.png", "og-image-modern.png", "robots.txt", "llms.txt", "sitemap.xml", "_redirects",
    "fonts", "img", "data", "functions", "tools/tools.js", "playground/classifier.js",
    "playground/compliance.json", "playground/floci-spike-create-plan.json",
    "playground/floci-spike-destroy-plan.json", "playground/floci-samples.meta.json"
  ]) {
    eleventyConfig.addPassthroughCopy(entry);
  }

  eleventyConfig.addTransform("canonical-site-shell", function (content) {
    if (!this.page.outputPath?.endsWith(".html")) return content;
    const topbarPattern = /<header\b[^>]*class="[^"]*topbar[^"]*"[^>]*>[\s\S]*?<\/header>/i;
    const navbarPattern = /<nav\b[^>]*class="[^"]*navbar[^"]*"[^>]*>[\s\S]*?<\/nav>/i;
    const existingCanonical = /<!-- site-header:start -->[\s\S]*?<!-- site-header:end -->/i;
    const footerPattern = /<footer\b[^>]*>[\s\S]*?<\/footer>/i;

    let html = content;
    if (existingCanonical.test(html)) html = html.replace(existingCanonical, canonicalHeader);
    else if (topbarPattern.test(html)) html = html.replace(topbarPattern, canonicalHeader);
    else if (navbarPattern.test(html)) html = html.replace(navbarPattern, canonicalHeader);
    else html = html.replace(/<body([^>]*)>/i, `<body$1>\n${canonicalHeader}`);

    html = footerPattern.test(html)
      ? html.replace(footerPattern, canonicalFooter)
      : html.replace(/<\/body>/i, `${canonicalFooter}\n</body>`);
    if (!html.includes('href="/modern.css"')) {
      html = html.replace(/<\/head>/i, '  <link rel="stylesheet" href="/modern.css" />\n</head>');
    }
    const family = routeClass(this.page.outputPath);
    html = html.replace(/<body([^>]*)>/i, (match, attrs) => {
      if (/class="[^"]*"/i.test(attrs)) {
        return `<body${attrs.replace(/class="([^"]*)"/i, `class="$1 ${family}"`)}>`;
      }
      return `<body${attrs} class="${family}">`;
    });
    if (!html.includes('src="/site-motion.js"')) {
      html = html.replace(/<\/body>/i, '  <script defer src="/site-motion.js"></script>\n</body>');
    }
    return html.replaceAll("__READTHEPLAN_VERSION__", version);
  });

  return {
    dir: { input: ".", output: "dist", includes: "_includes" },
    htmlTemplateEngine: false,
    markdownTemplateEngine: false,
    templateFormats: ["html"],
  };
};
