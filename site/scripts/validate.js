const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");

function read(file) {
  return fs.readFileSync(path.join(root, file), "utf8");
}

function requireIncludes(source, token, label) {
  if (!source.includes(token)) {
    throw new Error(`Missing ${label}: ${token}`);
  }
}

function forbidIncludes(source, token, label) {
  if (source.toLowerCase().includes(token.toLowerCase())) {
    throw new Error(`${label} must not include: ${token}`);
  }
}

const html = read("index.html");
const homeJs = read("js/home.js");
const modernCss = read("modern.css");
const buildScript = read("scripts/build.js");
const eleventyConfig = read("eleventy.config.cjs");
const packageJson = read("package.json");
const baseLayout = read("_includes/layouts/base.njk");
const sharedChrome = `${read("_includes/site-header.njk")}\n${read("_includes/site-footer.njk")}\n${eleventyConfig}`;
const mcpHtml = read("mcp/index.html");
const briefHtml = read("brief/index.html");
const sampleBriefHtml = read("brief/sample-001/index.html");
const briefCombined = `${briefHtml}\n${sampleBriefHtml}`;
const sitemap = read("sitemap.xml");
const robots = read("robots.txt");
const llms = read("llms.txt");

// Index page contract: one AI-verification story, a truthful Terraform-first
// wedge, local-first setup, and a single primary activation path.
for (const token of [
  'id="top"',
  'class="hero-proof signal-console"',
  "static Terraform example · no uploaded data",
  'class="risk-orbit"',
  'class="resource-map"',
  'id="how-it-works"',
  'id="install-cmd"',
  'id="copy-install"',
  'id="setup"',
  'id="agent"',
  'id="community"',
  'id="resources"',
  'id="gen-output"',
  "No plan upload",
  "No uploads. Runs entirely in your CI.",
  "Verify AI-generated infrastructure changes before they run.",
  "Terraform/OpenTofu is the first gate",
  "Deterministic, not generative",
  'data-activation-event="verify_change_click"',
  "readtheplan agent-gate plan.json",
  "proceed / warn / block",
  "MCP integration",
  "rtp-evidence-soc2.json",
  "Good first issues tagged",
  "pip install readtheplan",
  "readtheplan-evidence.json",
  "readtheplan[sign]",
  "/mcp/",
  "/docs/",
  "/demo/",
  "/playground/",
]) {
  requireIncludes(html, token, "expected landing page token");
}

requireIncludes(html, 'data-activation-event="setup_help_click"', "homepage setup-help activation marker");
requireIncludes(mcpHtml, 'data-activation-event="setup_help_click"', "MCP setup-help activation marker");

const header = read("_includes/site-header.njk");
for (const demotedRoute of ["/pricing/", "/chat/"]) {
  if (header.includes(demotedRoute)) {
    throw new Error(`Primary navigation must not link demoted route: ${demotedRoute}`);
  }
}

// The setup generator lives in a CSP-safe external module.
for (const token of [
  "function workflowText()",
  "function cliCommand(",
  "installPackage(ev)",
  '"readtheplan[sign]"',
  "python -m pip install",
  "readtheplan-summary.json",
  "fail-on-threshold",
  "Generate evidence artifact",
  "if: always()",
  "cliCommand(true, false)",
  "--format",
  "readtheplan/readtheplan@v", // version resolved from the rendered nav badge
  "site-brand__version",
]) {
  requireIncludes(homeJs, token, "setup generator behavior token");
}

if (!homeJs.includes("plan.json")) {
  throw new Error("Generated setup must reference plan.json.");
}

for (const token of [
  "Upload a plan",
  "fail-on-risk-level",
  "\n    framework:",
  "\n    evidence:",
  "pilot-contact@example.com",
]) {
  if (html.includes(token) || homeJs.includes(token)) {
    throw new Error(`Landing page must not include stale or unsupported token: ${token}`);
  }
}

if (/<form[^>]+action=/i.test(html)) {
  throw new Error("Client intake form must not submit to a backend.");
}

// Layout owns document chrome: metadata, canonical, social cards, styles, scripts.
for (const token of [
  'rel="canonical"',
  "og:image",
  "twitter:card",
  'href="/modern.css"',
  'src="/site-motion.js"',
  'src="/js/analytics.js"',
  'name="viewport"',
]) {
  requireIncludes(baseLayout, token, "base layout chrome token");
}
if (baseLayout.includes("plausible.io/js/")) {
  throw new Error("General Plausible script must not add visited URL or referrer context.");
}

// Every source route is a layout-owned template: front matter, no chrome, no inline scripts.
const sourceRoutes = [];
(function collect(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["dist", "node_modules", "_includes"].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collect(full);
    else if (entry.name.endsWith(".html")) sourceRoutes.push(path.relative(root, full));
  }
})(root);

for (const route of sourceRoutes) {
  const source = read(route);
  if (!source.startsWith("---")) {
    throw new Error(`${route} must start with front matter (layout-owned chrome).`);
  }
  for (const forbidden of ["<head>", "</html>", "<!doctype", "topbar", 'class="navbar"', "<script>"]) {
    forbidIncludes(source, forbidden, `${route} (layout-owned template)`);
  }
  // Any on*-attribute is a CSP violation, whatever the event name or spacing.
  if (/\son[a-z]+\s*=/i.test(source)) {
    throw new Error(`${route} contains an inline event handler (CSP forbids it).`);
  }
}

// Shared visual contract: light-first editorial system, one accent, dark proof surfaces.
for (const token of [
  "--paper: #faf9f7;",
  "--ink: #191b20;",
  "--accent: #4438ca;",
  "--proof-bg: #12151b;",
  ".site-nav__inner",
  ".site-footer__inner",
  ".route-playground",
  ".chat-container",
  ".pricing-card",
  ".evidence-paper",
  ".skip-link",
  ".signal-console",
  ".risk-orbit",
  ".resource-map",
  ".scan-tabs",
  ":focus-visible",
  "@media print",
]) {
  requireIncludes(modernCss, token, "modern design system token");
}

if (!modernCss.includes("@media (max-width: 720px)")) {
  throw new Error("Responsive mobile styles are required.");
}
if (!modernCss.includes("prefers-reduced-motion")) {
  throw new Error("Reduced-motion support is required.");
}

// Build script contract: one CSP source, self-hosted scripts, Plausible API allowed.
for (const token of [
  "Content-Security-Policy",
  "script-src 'self'",
  "connect-src 'self' https://plausible.io",
  "font-src 'self'",
  "img-src 'self' data:",
  "Strict-Transport-Security",
  "Access-Control-Allow-Origin: https://readtheplan.dev",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "X-Frame-Options",
  "browsing-topics=()",
  "payment=()",
  "usb=()",
  "serial=()",
]) {
  requireIncludes(buildScript, token, "security header");
}
if (/script-src[^;]*'unsafe-inline'/.test(buildScript)) {
  throw new Error("script-src must not allow 'unsafe-inline'.");
}
if (buildScript.includes("cdnjs.cloudflare.com")) {
  throw new Error("No third-party CDN scripts are permitted.");
}

const chromePipeline = `${sharedChrome}\n${baseLayout}\n${buildScript}`;
for (const token of [
  "projectVersion",
  "site-header:start",
  "site-footer:start",
  "__READTHEPLAN_VERSION__",
  "pyproject.toml",
  "version-token",
  "site-header.njk",
  "site-footer.njk",
  "layouts/base.njk",
]) {
  requireIncludes(chromePipeline, token, "Eleventy canonical build chrome");
}

for (const token of ['"fonts"', '"img"', '"data"', '"modern.css"', '"js"', '"chat/chat.js"', '"playground/playground.js"']) {
  requireIncludes(eleventyConfig, token, "Eleventy passthrough token");
}
// functions/ must never be passthrough-copied: Pages compiles the source
// tree, and a dist copy would be an inert decoy.
forbidIncludes(eleventyConfig, 'addPassthroughCopy("functions")', "Eleventy config");
if (/"functions"/.test(eleventyConfig)) {
  throw new Error('Eleventy config must not passthrough-copy "functions".');
}

requireIncludes(packageJson, '"@11ty/eleventy": "3.1.6"', "pinned Eleventy dependency");
requireIncludes(buildScript, "npx eleventy --config=eleventy.config.cjs", "Eleventy build invocation");

for (const file of [
  "404.html",
  "_redirects",
  "favicon.svg",
  "og-image.png",
  "og-image-modern.png",
  "robots.txt",
  "llms.txt",
  "sitemap.xml",
  "js/home.js",
  "js/analytics.js",
  "js/demo.js",
  "chat/chat.js",
  "playground/playground.js",
  "site-motion.js",
  "modern.css",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing static site asset: ${file}`);
  }
}

// Retired assets must stay retired. site/_headers is retired because the
// deployed policy is generated into dist/_headers by build.js — a second
// source file would silently diverge again.
for (const file of ["app.js", "matrix.css", "home.css", "styles.css", "matrix.js", "_headers"]) {
  if (fs.existsSync(path.join(root, file))) {
    throw new Error(`Legacy asset must not return: ${file}`);
  }
}

// Shared interaction module owns copy affordances for ALL code blocks,
// including bare <pre> in docs.
const siteMotion = read("site-motion.js");
requireIncludes(siteMotion, 'document.querySelectorAll("pre, .code-output")', "bare-pre copy enhancement");
requireIncludes(siteMotion, "data-copy-block", "delegated block copy handler");

// Pages Functions deploy from the source tree verbatim: no placeholders,
// and version literals must match pyproject.
const pyprojectSource = fs.readFileSync(path.join(root, "..", "pyproject.toml"), "utf8");
const pyprojectVersion = pyprojectSource.match(/^version\s*=\s*"([^"]+)"/m)[1];
for (const fn of ["functions/api/chat.js", "functions/openapi.json.js"]) {
  const fnSource = read(fn);
  forbidIncludes(fnSource, "__READTHEPLAN_VERSION__", fn);
  if (!fnSource.includes(pyprojectVersion)) {
    throw new Error(`${fn} version literal is stale (expected ${pyprojectVersion}).`);
  }
}

// Exhaustive version sweep: NO source file may carry a product-version
// literal other than pyproject's. Templates use the placeholder; only
// functions/ may hold the (matching) literal.
const versionSweep = [];
(function sweep(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["dist", "node_modules", ".git"].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sweep(full);
    else if (/\.(html|js|njk|mjs|json|xml|txt)$/.test(entry.name)) versionSweep.push(full);
  }
})(root);
for (const file of versionSweep) {
  const rel = path.relative(root, file).replaceAll("\\", "/");
  const source = fs.readFileSync(file, "utf8");
  for (const match of source.matchAll(/\bv(\d+\.\d+\.\d+)\b|readtheplan@v?(\d+\.\d+\.\d+)|readtheplan==(\d+\.\d+\.\d+)/g)) {
    const found = match[1] || match[2] || match[3];
    if (found !== pyprojectVersion) {
      throw new Error(`${rel}: stale version literal v${found} (pyproject is ${pyprojectVersion}).`);
    }
    if (!rel.startsWith("functions/") && !rel.startsWith("analysis/") && !rel.startsWith("scripts/")) {
      throw new Error(`${rel}: version literal v${found} outside functions/ — use __READTHEPLAN_VERSION__.`);
    }
  }
}

for (const token of [
  "Content-Signal: search=yes, ai-input=yes, ai-train=no",
  "Sitemap: https://readtheplan.dev/sitemap.xml",
]) {
  requireIncludes(robots, token, "AI crawler policy");
}

for (const token of [
  "Every product feature is free",
  "https://readtheplan.dev/docs/",
  "https://github.com/readtheplan/readtheplan",
  "model training is not granted",
]) {
  requireIncludes(llms, token, "agent-readable site guidance");
}

for (const file of [
  "fonts/JetBrainsMono-Regular.woff2",
  "fonts/LICENSE-JetBrainsMono.txt",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing font asset: ${file}`);
  }
}

// Public routes and sitemap coverage.
const seoRoutes = [
  "tools/terraform-risk-calculator/index.html",
  "tools/soc2-cloud-control-mapper/index.html",
  "resources/terraform-s3-bucket-risk/index.html",
  "resources/terraform-iam-policy-risk/index.html",
  "resources/terraform-security-group-0-0-0-0-risk/index.html",
  "resources/terraform-cloudwatch-log-retention-risk/index.html",
];
const docsRoutes = [
  "docs/index.html",
  "docs/faq.html",
  "docs/adapters/index.html",
  "docs/quickstart/index.html",
  "docs/cli/index.html",
  "docs/ci/index.html",
  "docs/github-action/index.html",
];
const experientialRoutes = ["demo/index.html", "playground/index.html", "chat/index.html"];
const briefRoutes = ["brief/index.html", "brief/sample-001/index.html"];
const projectRoutes = [
  "blog/index.html",
  "pricing/index.html",
  "privacy/index.html",
  "terms/index.html",
];

for (const route of [...seoRoutes, ...docsRoutes, ...experientialRoutes, ...briefRoutes, ...projectRoutes, "mcp/index.html"]) {
  if (!fs.existsSync(path.join(root, route))) {
    throw new Error(`Missing public route: ${route}`);
  }
}

for (const token of [
  "/mcp/",
  "/docs/",
  "/demo/",
  "/playground/",
]) {
  if (!html.includes(token) && !sharedChrome.includes(token)) {
    throw new Error(`Missing linked primary route: ${token}`);
  }
  if (!sitemap.includes(token)) {
    throw new Error(`Missing sitemap-listed primary route: ${token}`);
  }
}

// Secondary utilities stay public and discoverable without competing in the
// homepage or primary navigation journey.
for (const token of [
  "/tools/terraform-risk-calculator/",
  "/tools/soc2-cloud-control-mapper/",
  "/brief/",
  "/chat/",
  "/pricing/",
]) {
  if (!sitemap.includes(token)) {
    throw new Error(`Missing sitemap-listed secondary route: ${token}`);
  }
}

for (const token of [
  "/docs/quickstart/",
  "/docs/cli/",
  "/docs/github-action/",
  "/docs/adapters/",
  "/docs/faq.html",
  "/blog/",
  "/pricing/",
  "/privacy/",
  "/terms/",
  "/brief/sample-001/",
  "/resources/terraform-s3-bucket-risk/",
  "/resources/terraform-iam-policy-risk/",
  "/resources/terraform-security-group-0-0-0-0-risk/",
  "/resources/terraform-cloudwatch-log-retention-risk/",
]) {
  requireIncludes(sitemap, token, "sitemap-listed route");
}

if (!briefHtml.includes("/brief/sample-001/")) {
  throw new Error("Brief index must link to sample brief route.");
}

const docsHtml = docsRoutes.map((route) => read(route)).join("\n");

for (const token of [
  "Documentation",
  "Quickstart",
  "CLI Reference",
  "GitHub Action",
  "__READTHEPLAN_VERSION__",
  "utility-panel-wide",
  "readtheplan agent-gate",
  'pip install "readtheplan[sign]"',
]) {
  requireIncludes(docsHtml, token, "docs route token");
}

const seoHtml = seoRoutes.map((route) => read(route)).join("\n");

for (const token of [
  "Terraform Risk Calculator",
  "raw Terraform plans stay local",
  'id="riskCalculator"',
  "Calculate risk",
  'type="number"',
  "SOC 2 Cloud Control Mapper",
  "SOC 2 control family map",
  "Terraform S3 Bucket Risk",
  "Terraform IAM Policy Risk",
  "Terraform Security Group 0.0.0.0/0 Risk",
  "Terraform CloudWatch Log Retention Risk",
  'itemscope itemtype="https://schema.org/FAQPage"',
  "info@readtheplan.dev",
]) {
  requireIncludes(seoHtml, token, "SEO/tool copy token");
}

if (!read("tools/tools.js").includes("new FormData(calculator)")) {
  throw new Error("Terraform risk calculator must compute from local form values.");
}

for (const token of ["Upload a plan", "hosted analyzer", "hosted plan analysis", "API endpoint", "store uploaded", "stored plan"]) {
  forbidIncludes(seoHtml, token, "SEO tools");
}

if (/<input[^>]+type=["']file["']/i.test(seoHtml)) {
  throw new Error("SEO tools must not include file inputs.");
}

if (/<form[^>]+action=/i.test(seoHtml)) {
  throw new Error("SEO tools must not submit forms to a backend.");
}

// Brief page: free community signal, no upload/backend/billing/automation claims.
for (const token of [
  "Weekly Terraform/SOC 2 change intelligence for platform teams",
  "free community loop",
  "monitor, filter, analyze, package, publish",
  "Platform and SRE teams",
  "DevOps consultancies",
  "SOC 2 consultants",
  "Infra and devtool projects",
  "Top 5 infra/compliance changes",
  "Why they matter",
  "Terraform/SOC2 risk angle",
  "Action checklist",
  "readtheplan CTA",
  "Public sample",
  "Free weekly brief",
  "Community requests",
  "Local integrations",
  "Suggest a brief item",
  "Terraform/OpenTofu",
  "AWS logging",
  "AWS IAM",
  "Security group ingress",
  "GitHub Actions permission expansion",
  "SOC 2 evidence",
  "readtheplan progress",
  "Demo issue",
]) {
  requireIncludes(briefCombined, token, "weekly brief token");
}

for (const token of [
  'type="file"',
  "Upload a plan",
  "submit your plan",
  "Start hosted analyzer",
  "hosted plan analyzer is available",
  "Create account",
  "Sign up",
  "Stripe",
  "Checkout",
  "Subscribe now",
  "storage bucket",
  "store uploaded",
  "stored plan",
  "cron job is enabled",
  "scheduled delivery is enabled",
  "automatic scheduled delivery is enabled",
  "repeated paid output loop",
  "Private weekly brief",
  "private pilot",
  "MCP/custom integration upsell",
]) {
  forbidIncludes(briefCombined, token, "Brief pages");
}

if (/<form/i.test(briefCombined)) {
  throw new Error("Brief pages must not include forms.");
}

// MCP page: local preview only, no hosted/upload implications.
for (const token of [
  "Local MCP infrastructure reviewer",
  "Give your AI coding agent a deterministic Terraform/OpenTofu second check",
  "Local-first",
  "No raw plan upload",
  "No hosted MCP service",
  "No hosted plan analysis",
  'pip install "readtheplan[mcp]"',
  "readtheplan mcp",
  "agent_gate_project",
  "MCP_ROOT",
  "isolated temporary snapshot",
  "analyze_plan",
  "agent_gate",
  "agent_gate_pulumi",
  "agent_gate_pulumi_project",
  "agent_gate_azure",
  "agent_gate_bicep",
  "agent_gate_cdk",
  "agent_gate_nix",
  "agent_gate_dsc",
  "agent_gate_cfengine",
  "agent_gate_opa",
  "agent_gate_sentinel",
  "agent_gate_sops",
  "agent_gate_docker_bake",
  "agent_gate_skaffold",
  "agent_gate_devspace",
  "agent_gate_tilt",
  "agent_gate_cue",
  "agent_gate_jsonnet",
  "agent_gate_helmfile",
  "agent_gate_terramate",
  "agent_gate_spacelift",
  "agent_gate_carvel",
  "agent_gate_terraform_lock",
  "agent_gate_terraform_state",
  "jenkins-jcasc",
  "jenkins-project",
  "TeamCity Kotlin DSL",
  "Concourse",
  "Bamboo Specs",
  "AWS CodeBuild",
  "Google Cloud Build",
  "AWS CodePipeline",
  "SOPS",
  "Docker Buildx Bake definitions",
  "ansible-project",
  "chef-project",
  "Chef recipes/projects/Berkshelf dependencies/client, Workstation, Solo, and Server runtime configuration",
  "puppet-project",
  "salt-project",
  "NixOS",
  "PowerShell DSC",
  "CFEngine",
  "provider locks",
  "proceed/warn/block",
  "PR reviewer",
  "SOC 2 evidence prep",
  "Dangerous change triage",
  "Auditor-friendly summary",
  "CloudFormation",
  "Kubernetes",
  "Pulumi",
  "info@readtheplan.dev",
  "auth design",
  "least privilege",
  "audit logs",
  "Free setup help",
  "Community guidance",
]) {
  requireIncludes(mcpHtml, token, "MCP landing page token");
}

for (const token of [
  "Upload a plan",
  "hosted MCP endpoint",
  "hosted MCP platform",
  "hosted plan analyzer",
  "API endpoint",
  "submit your plan",
  "store uploaded",
  "stored plan",
]) {
  forbidIncludes(mcpHtml, token, "MCP page");
}

if (/<input[^>]+type=["']file["']/i.test(mcpHtml)) {
  throw new Error("MCP page must not include file inputs.");
}

if (/<form[^>]+action=/i.test(mcpHtml)) {
  throw new Error("MCP page must not submit forms to a backend.");
}

console.log("Site source validated.");
