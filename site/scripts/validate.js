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
const modernCss = read("modern.css");
const homeCss = read("home.css");
const buildScript = read("scripts/build.js");
const eleventyConfig = read("eleventy.config.cjs");
const packageJson = read("package.json");
const sharedChrome = `${read("_includes/site-header.njk")}\n${read("_includes/site-footer.njk")}\n${eleventyConfig}`;
const mcpHtml = read("mcp/index.html");
const briefHtml = read("brief/index.html");
const sampleBriefHtml = read("brief/sample-001/index.html");
const briefCombined = `${briefHtml}\n${sampleBriefHtml}`;
const sitemap = read("sitemap.xml");
const robots = read("robots.txt");
const llms = read("llms.txt");

// Index page contract: single linear landing page, local-first setup, community-driven.
for (const token of [
  'id="top"',
  'class="hero-proof signal-console"',
  "static product preview · no uploaded data",
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
  'rel="canonical"',
  "og:image",
  "twitter:card",
  "No plan upload",
  "No uploads. Runs entirely in your CI.",
  "Terraform + the broader infra stack",
  "Six built-in catalogs cover SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST",
  "readtheplan agent-gate plan.json",
  "proceed / warn / block",
  "MCP integration",
  "rtp-evidence-soc2.json",
  "Good first issues tagged",
  "pip install readtheplan",
  "readtheplan scan .",
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
  "v0.4.0",
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
  "cliCommand(true, false)",
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

// Shared visual contract: routes use the graphite signal workspace system.
for (const token of [
  "--signal-bg: #07090d;",
  "--signal-panel: rgba(16, 20, 27, 0.88);",
  "--signal-green: #72e6b1;",
  "--signal-cyan: #75a7ff;",
  ".site-nav__inner",
  ".site-footer__inner",
  ".route-playground",
  ".chat-container",
  ".pricing-card",
  ".evidence-paper",
  "@media print",
]) {
  requireIncludes(modernCss, token, "modern design system token");
}

for (const token of [".signal-console", ".risk-orbit", ".resource-map", ".scan-tabs"]) {
  requireIncludes(homeCss, token, "homepage product-demo token");
}

if (!modernCss.includes("@media (max-width: 720px)")) {
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

for (const token of [
  "projectVersion",
  "site-header:start",
  "site-footer:start",
  "__READTHEPLAN_VERSION__",
  "pyproject.toml",
  "canonical-site-shell",
  "site-header.njk",
  "site-footer.njk",
]) {
  requireIncludes(sharedChrome, token, "Eleventy canonical build chrome");
}

for (const token of ['"fonts"', '"img"', '"data"', '"functions"', '"modern.css"']) {
  requireIncludes(eleventyConfig, token, "Eleventy passthrough token");
}

requireIncludes(packageJson, '"@11ty/eleventy": "3.1.6"', "pinned Eleventy dependency");
requireIncludes(buildScript, "npx eleventy --config=eleventy.config.cjs", "Eleventy build invocation");

for (const file of [
  "404.html",
  "_redirects",
  "favicon.svg",
  "og-image.png",
  "robots.txt",
  "llms.txt",
  "sitemap.xml",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    throw new Error(`Missing static site asset: ${file}`);
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
  "docs/faq.html",
  "docs/adapters/index.html",
  "docs/quickstart/index.html",
  "docs/cli/index.html",
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
  "/tools/terraform-risk-calculator/",
  "/tools/soc2-cloud-control-mapper/",
  "/mcp/",
  "/brief/",
  "/docs/",
  "/demo/",
  "/playground/",
  "/chat/",
]) {
  if (!html.includes(token) || !sitemap.includes(token)) {
    throw new Error(`Missing linked and sitemap-listed primary route: ${token}`);
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
  "v0.4.0",
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
  "Give your AI coding agent deterministic Terraform, CloudFormation, Azure, Kubernetes",
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
