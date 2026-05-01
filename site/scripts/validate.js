const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");

function read(file) {
  return fs.readFileSync(path.join(root, file), "utf8");
}

const html = read("index.html");
const css = read("styles.css");
const js = read("app.js");

const requiredHtml = [
  "id=\"onboardingForm\"",
  "id=\"actionOutput\"",
  "id=\"cliOutput\"",
  "id=\"pilotLink\"",
  "id=\"recommendation\"",
  "id=\"planRows\"",
  "rel=\"canonical\"",
  "rel=\"icon\"",
  "og:image",
  "twitter:card",
  "No plan upload",
];

for (const token of requiredHtml) {
  if (!html.includes(token)) {
    throw new Error(`Missing expected HTML token: ${token}`);
  }
}

if (!js.includes("terraform show -json tfplan > plan.json")) {
  throw new Error("Generated setup must show Terraform JSON export.");
}

if (!js.includes("readtheplan/readtheplan@v1")) {
  throw new Error("Generated setup must include the readtheplan GitHub Action.");
}

if (!js.includes("teamProfiles")) {
  throw new Error("Team type selections must drive visible setup profiles.");
}

if (!js.includes("renderRiskCounts(rows)")) {
  throw new Error("Risk summary counts must respond to form state.");
}

if (!js.includes("No raw Terraform plan is attached.")) {
  throw new Error("Pilot handoff must avoid raw plan collection.");
}

if (!js.includes("permissions:")) {
  throw new Error("Generated GitHub Actions workflow must include least-privilege permissions.");
}

for (const token of [
  "workflow_run:",
  "actions: read",
  "actions/download-artifact@v4",
  "Do not expose cloud credentials to forked pull_request jobs.",
]) {
  if (!js.includes(token)) {
    throw new Error(`Generated GitHub Actions workflow missing trusted-plan guardrail: ${token}`);
  }
}

if (js.includes("terraform init -input=false")) {
  throw new Error("Generated GitHub Actions workflow must not run Terraform directly on PR events.");
}

if (!css.includes(".recommendation")) {
  throw new Error("Preview recommendation styles are required.");
}

const buildScript = read("scripts/build.js");

for (const token of [
  "Content-Security-Policy",
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
  if (!buildScript.includes(token)) {
    throw new Error(`Missing expected security header: ${token}`);
  }
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
  if (!buildScript.includes(file)) {
    throw new Error(`Build script must copy static site asset: ${file}`);
  }
}

if (!css.includes("@media (max-width: 720px)")) {
  throw new Error("Responsive mobile styles are required.");
}

console.log("Site source validated.");
