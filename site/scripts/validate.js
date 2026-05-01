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

if (!js.includes("No raw Terraform plan is attached.")) {
  throw new Error("Pilot handoff must avoid raw plan collection.");
}

if (!css.includes("@media (max-width: 720px)")) {
  throw new Error("Responsive mobile styles are required.");
}

console.log("Site source validated.");
