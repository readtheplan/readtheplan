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
const css = read("matrix.css");
const buildScript = read("scripts/build.js");
const mcpHtml = read("mcp/index.html");
const briefHtml = read("brief/index.html");
const sampleBriefHtml = read("brief/sample-001/index.html");
const briefCombined = `${briefHtml}\n${sampleBriefHtml}`;
const sitemap = read("sitemap.xml");

// Index page contract: single linear landing page, local-first setup, community-driven.
for (const token of [
  'id="top"',
  'id="matrix-rain"',
  'id="webgl-canvas"',
  'id="how-it-works"',
  'id="install-cmd"',
  'id="copy-install"',
  'id="setup"',
  'id="agent"',
  'id="community"',
  'id="resources"',
  'id="gen-output"',
  'rel="canonical"',
  "og:image",
  "twitter:card",
  "No plan upload",
  "No uploads. Runs entirely in your CI.",
  "Terraform + OpenTofu",
  "readtheplan agent-gate plan.json",
  "proceed / warn / block",
  "MCP integration",
  "rtp-evidence-soc2.json",
  "Good first issues tagged",
  "pip install readtheplan",
  "fail-on-threshold",
  "readtheplan-evidence.json",
  "readtheplan[sign]",
  "/tools/terraform-risk-calculator/",
  "/tools/soc2-cloud-control-mapper/",
  "/mcp/",
  "/docs/",
  "/demo/",
  "/brief/",
  "/playground/",
  "v0.3.0",
]) {
  requireIncludes(html, token, "expected landing page token");
}

for (const token of [
  "function workflowText()",
  "function cliCommand(",
  "installPackage(ev)",
  '"readtheplan[sign]"',
  "python -m pip install",
  "readtheplan-summary.json",
  "readtheplan analyze --framework",
  "Generate evidence artifact",
  "if: always()",
  "cliCommand(true)",
  "--format",
]) {
  requireIncludes(html, token, "setup generator behavior token");
}

if (!html.includes("plan.json")) {
  throw new Error("Generated setup must reference plan.json.");
}

for (const token of [
  "Upload a plan",
  "fail-on-risk-level",
  "\n    framework:",
  "\n    evidence:",
  "pilot-contact@example.com",
]) {
  if (html.includes(token)) {
    throw new Error(`Landing page must not include stale or unsupported token: ${token}`);
  }
}

if (/<form[^>]+action=/i.test(html)) {
  throw new Error("Client intake form must not submit to a backend.");
}

// Shared visual contract: routed pages should match the Matrix theme.
for (const token of [
  "JetBrains Mono",
  "url('/fonts/JetBrainsMono-Regular.woff2')",
  "--matrix-bg: #000000;",
  "--matrix-green: #00FF41;",
  "--matrix-fg: #00CC33;",
  "--matrix-glow:",
  "--matrix-text-glow:",
  "font-family: var(--font-mono);",
  ".gradient-text {",
  ".navbar {",
  ".cta-btn",
  ".terminal-box {",
  "Matrix Theme for readtheplan",
  "Scanline overlay",
  "Digital rain",
  "phosp",
  "background: var(--matrix-bg);",
  "border: 1px solid rgba(0, 255, 65,",
]) {
  requireIncludes(css, token, "Matrix CSS token");
}

if (!css.includes("@media (max-width: 768px)") && !css.includes("@media (max-width: 720px)")) {
  throw new Error("Responsive mobile styles are required.");
}

// Build script contract.
for (const token of [
  "Content-Security-Policy",
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

for (const token of ["assetDirs", '"fonts"', '"img"', '"tools"', '"resources"', '"mcp"', '"brief"']) {
  requireIncludes(buildScript, token, "build script asset/route copy token");
}

for (const file of [
  "404.html",
  "_redirects",
  "favicon.svg",
  "og-image.png",
  "robots.txt",
  "sitemap.xml",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing static site asset: ${file}`);
  }
  requireIncludes(buildScript, file, "static site asset copy token");
}

for (const file of [
  "fonts/DepartureMono-Regular.woff2",
  "fonts/JetBrainsMono-Regular.woff2",
  "fonts/LICENSE-DepartureMono.txt",
  "fonts/LICENSE-JetBrainsMono.txt",
  "img/noise.svg",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing redesign asset: ${file}`);
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
  "docs/quickstart/index.html",
  "docs/cli/index.html",
  "docs/github-action/index.html",
];
const experientialRoutes = ["demo/index.html", "playground/index.html"];
const briefRoutes = ["brief/index.html", "brief/sample-001/index.html"];

for (const route of [...seoRoutes, ...docsRoutes, ...experientialRoutes, ...briefRoutes, "mcp/index.html"]) {
  if (!fs.existsSync(path.join(root, route))) {
    throw new Error(`Missing public route: ${route}`);
  }
}

for (const token of [
  "/tools/terraform-risk-calculator/",
  "/tools/soc2-cloud-control-mapper/",
  "/mcp/",
  "/brief/",
  "/docs/",
  "/demo/",
  "/playground/",
]) {
  if (!html.includes(token) || !sitemap.includes(token)) {
    throw new Error(`Missing linked and sitemap-listed primary route: ${token}`);
  }
}

for (const token of [
  "/docs/quickstart/",
  "/docs/cli/",
  "/docs/github-action/",
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
  "v0.3.0",
  "topbar g",
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

// Brief page: paid output loop, no upload/backend/billing/automation claims.
for (const token of [
  "Weekly Terraform/SOC 2 change intelligence for platform teams",
  "repeated paid output loop",
  "monitor, filter, analyze, package, deliver",
  "platform/SRE teams",
  "DevOps consultancies",
  "SOC 2 consultants",
  "seed-stage infra/devtool startups",
  "Top 5 infra/compliance changes",
  "Why they matter",
  "Terraform/SOC2 risk angle",
  "Action checklist",
  "readtheplan CTA",
  "First sample/free",
  "Private weekly brief",
  "Custom company-specific monitoring",
  "MCP/custom integration upsell",
  "Request first brief / private pilot",
  "info@readtheplan.dev",
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
]) {
  forbidIncludes(briefCombined, token, "Brief pages");
}

if (/<form/i.test(briefCombined)) {
  throw new Error("Brief pages must not include forms.");
}

// MCP page: local preview only, no hosted/upload implications.
for (const token of [
  "Local MCP Terraform reviewer",
  "Give your AI coding agent a Terraform/SOC 2 reviewer that runs locally",
  "Local-first",
  "No raw plan upload",
  "No hosted MCP service",
  "No hosted plan analysis",
  'pip install "readtheplan[mcp]"',
  "readtheplan mcp",
  "analyze_plan",
  "agent_gate",
  "proceed/warn/block",
  "PR reviewer",
  "SOC 2 evidence prep",
  "Dangerous change triage",
  "Auditor-friendly summary",
  "CloudFormation",
  "Kubernetes",
  "Terraform-first today",
  "info@readtheplan.dev",
  "auth design",
  "least privilege",
  "audit logs",
  "Custom engagement",
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
