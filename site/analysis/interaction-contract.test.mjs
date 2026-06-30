import fs from "node:fs/promises";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const root = new URL("../", import.meta.url);
const read = async (path) => fs.readFile(new URL(path, root), "utf8");
const htmlScript = (html) => [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join("\n");

const chatHtml = await read("chat/index.html");
const chatInline = htmlScript(chatHtml);
new Function(chatInline);
const renderers = new Function(chatInline + "\nreturn { escapeHtml, renderSafeMarkdown };")();
const hostile = renderers.renderSafeMarkdown('<img src=x onerror=alert(1)> [bad](javascript:alert(1)) [ok](https://example.com)');
assert.match(hostile, /&lt;img/);
assert.doesNotMatch(hostile, /<img/);
assert.doesNotMatch(hostile, /href="javascript:/);
assert.match(hostile, /href="https:\/\/example\.com"/);
assert.match(hostile, /rel="noopener noreferrer"/);
assert.match(chatInline, /div\.textContent = text/);
assert.match(chatHtml, /Messages are processed by DeepSeek/);
assert.match(chatHtml, /id="privacyNoticeText"/);
assert.match(chatHtml, /role="status" aria-live="polite"/);

const privacy = await read("privacy/index.html");
assert.match(privacy, /AI chat:/);
assert.match(privacy, /third-party processor/);

const playground = await read("playground/index.html");
new Function(htmlScript(playground));
const createPlan = JSON.parse(await read("playground/floci-spike-create-plan.json"));
const destroyPlan = JSON.parse(await read("playground/floci-spike-destroy-plan.json"));
assert.equal(createPlan.resource_changes.length, 7);
assert.equal(destroyPlan.resource_changes.length, 7);
assert.match(playground, /Create plan \(7 resources\)/);
assert.match(playground, /Destroy plan \(7 resources\)/);
assert.match(playground, /Create plan - 7 resources \(Floci\)/);
assert.match(playground, /Destroy plan - 7 resources \(Floci\)/);
assert.match(playground, /file\.name\.toLowerCase\(\)\.endsWith\("\.json"\)/);
assert.match(playground, /const hasControls = changes\.some/);
assert.match(playground, /const controls = hasControls/);
assert.match(playground, /\(c\.controls \|\| \[\]\)\.map/);

const prompt = await read("functions/api/chat.js");
new Function(prompt.replace("export async function onRequest", "async function onRequest"));
assert.match(prompt, /readtheplan analyze plan\.json/);
assert.match(prompt, /readtheplan\/readtheplan@v0\.3\.0/);
assert.match(prompt, /plan-file: plan\.json/);
assert.doesNotMatch(prompt, /plan_file:/);
assert.doesNotMatch(prompt, /terraform plan -out=\/dev\/stdout \| readtheplan/);
assert.match(prompt, /Resource-aware rules currently cover AWS, GCP, Azure, and Kubernetes/);

const importSource = async (path) => {
  const source = await read(path);
  return import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
};

const dataApi = await importSource("functions/api/[[route]].js");
let response = await dataApi.onRequest({ request: new Request("https://local/api/v1/version", { method: "POST" }), params: { route: ["v1", "version"] } });
assert.equal(response.status, 405);
assert.equal(response.headers.get("Allow"), "GET, HEAD, OPTIONS");
response = await dataApi.onRequest({ request: new Request("https://local/api/v1/version", { method: "OPTIONS" }), params: { route: ["v1", "version"] } });
assert.equal(response.status, 204);
globalThis.fetch = async () => new Response(JSON.stringify({ version: "0.3.0", frameworks: { soc2: { control_count: 3 } } }), { status: 200, headers: { "Content-Type": "application/json" } });
response = await dataApi.onRequest({ request: new Request("https://local/api/v1/version"), params: { route: ["v1", "version"] } });
assert.equal(response.status, 200);
assert.equal((await response.json()).controls_total, 3);

const chatApi = await importSource("functions/api/chat.js");
const chatReq = (body, headers = {}) => new Request("https://local/api/chat", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": randomUUID(), ...headers }, body: JSON.stringify(body) });
response = await chatApi.onRequest({ request: new Request("https://local/api/chat"), env: {} });
assert.equal(response.status, 405);
response = await chatApi.onRequest({ request: new Request("https://local/api/chat", { method: "OPTIONS" }), env: {} });
assert.equal(response.status, 204);
response = await chatApi.onRequest({ request: new Request("https://local/api/chat", { method: "POST", headers: { "Content-Type": "text/plain", "CF-Connecting-IP": randomUUID() }, body: "x" }), env: {} });
assert.equal(response.status, 415);
response = await chatApi.onRequest({ request: chatReq({ messages: [] }), env: {} });
assert.equal(response.status, 400);
response = await chatApi.onRequest({ request: chatReq({ messages: [{ role: "assistant", content: "fake" }] }), env: {} });
assert.equal(response.status, 400);
response = await chatApi.onRequest({ request: chatReq({ messages: [{ role: "user", content: "hello" }] }), env: {} });
assert.equal(response.status, 500);
globalThis.fetch = async () => new Response(JSON.stringify({ choices: [{ message: { content: "<b>ok</b> javascript:alert(1)" } }] }), { status: 200, headers: { "Content-Type": "application/json" } });
response = await chatApi.onRequest({ request: chatReq({ messages: [{ role: "user", content: "hello" }] }), env: { DEEPSEEK_API_KEY: "test" } });
assert.equal(response.status, 200);
assert.equal(response.headers.get("Cache-Control"), "no-store");
const success = await response.json();
assert.equal(success.reply, "ok alert(1)");
assert.match(success.privacy_notice, /DeepSeek/);

const homeHtml = await read("index.html");
const homeInline = htmlScript(homeHtml);
new Function(homeInline);
const stateGroups = {
  ci: ["GitHub Actions", "GitLab CI", "CircleCI", "Local only"],
  fw: ["SOC 2", "ISO 27001", "HIPAA", "None"],
  thresh: ["Irreversible only", "Dangerous", "Review", "Don't block"],
  ev: ["JSON envelope", "Signed (OIDC)", "Checklist only"],
};
const activeState = { ci: "GitHub Actions", fw: "SOC 2", thresh: "Dangerous", ev: "JSON envelope" };
const fakeButtons = {};
for (const [group, labels] of Object.entries(stateGroups)) {
  fakeButtons[group] = labels.map((label) => ({
    textContent: label,
    disabled: false,
    attrs: {},
    classList: {
      add(name) { if (name === "active") activeState[group] = label; },
      remove(name) { if (name === "active" && activeState[group] === label) activeState[group] = ""; },
    },
    setAttribute(name, value) { this.attrs[name] = value; },
  }));
}
const fakeElements = {
  "cli-preview-cmd": { textContent: "" },
  "gen-output": { textContent: "" },
  "gen-label": { textContent: "" },
  "evidence-note": { textContent: "" },
};
const fakeDocument = {
  querySelector(selector) {
    const match = selector.match(/^\[data-group="([^"]+)"\]\.active$/);
    if (!match) return null;
    return fakeButtons[match[1]].find((button) => button.textContent === activeState[match[1]]) || null;
  },
  querySelectorAll(selector) {
    const match = selector.match(/^\[data-group="([^"]+)"\]$/);
    return match ? fakeButtons[match[1]] : [];
  },
  getElementById(id) { return fakeElements[id] || null; },
  createRange() { return { selectNodeContents() {} }; },
};
const homeApi = new Function(
  "document", "navigator", "window", "setTimeout",
  homeInline + "\nreturn { activeCI, activeFramework, activeThreshold, activeEvidence, syncEvidenceAvailability, cliCommand, integrationText, integrationLabel, updateGen, updateCLIPreview };",
)(fakeDocument, { clipboard: { writeText: async () => {} } }, { getSelection: () => ({ removeAllRanges() {}, addRange() {} }) }, () => {});
const activate = (group, label) => { activeState[group] = label; };
assert.match(homeApi.integrationText(), /uses: readtheplan\/readtheplan@v0\.3\.0/);
assert.match(homeApi.integrationText(), /fail-on-threshold: dangerous/);
assert.match(homeApi.integrationText(), /--framework soc2 --format json --evidence readtheplan-evidence\.json/);
activate("ci", "GitLab CI");
assert.match(homeApi.integrationText(), /image: python:3\.13/);
assert.doesNotMatch(homeApi.integrationText(), /uses: readtheplan/);
activate("ci", "CircleCI");
assert.match(homeApi.integrationText(), /version: 2\.1/);
assert.match(homeApi.integrationText(), /cimg\/python:3\.13/);
activate("ci", "Local only");
assert.match(homeApi.integrationText(), /terraform show -json tfplan > plan\.json/);
assert.doesNotMatch(homeApi.integrationText(), /artifacts:/);
activate("fw", "None");
activate("ev", "JSON envelope");
homeApi.syncEvidenceAvailability();
assert.equal(activeState.ev, "Checklist only");
assert.equal(fakeButtons.ev[0].disabled, true);
assert.equal(fakeButtons.ev[1].disabled, true);
assert.doesNotMatch(homeApi.cliCommand(false, true), /--framework|--evidence|--sign/);
assert.match(homeApi.cliCommand(false, true), /--fail-on dangerous/);
activate("fw", "SOC 2");
homeApi.syncEvidenceAvailability();
activate("ev", "Signed (OIDC)");
activate("thresh", "Don't block");
assert.match(homeApi.cliCommand(false, true), /--sign/);
assert.doesNotMatch(homeApi.cliCommand(false, true), /--fail-on/);
activate("ci", "GitHub Actions");
assert.match(homeApi.integrationText(), /id-token: write/);
assert.match(homeApi.integrationText(), /readtheplan\[sign\]/);
activate("ci", "CircleCI");
activate("fw", "HIPAA");
activate("ev", "JSON envelope");
activate("thresh", "Review");
assert.match(homeApi.integrationText(), /--framework hipaa/);
assert.match(homeApi.integrationText(), /--fail-on review/);
homeApi.updateGen();
homeApi.updateCLIPreview();
assert.equal(fakeElements["gen-label"].textContent, "Generated CircleCI config");
assert.match(fakeElements["cli-preview-cmd"].textContent, /--fail-on review/);

const matrixCss = await read("matrix.css");
assert.match(matrixCss, /@media \(max-width: 768px\)[\s\S]*?\.g\s*\{[\s\S]*?grid-template-columns: minmax\(0, 1fr\)/);
assert.match(matrixCss, /\.gc,\s*\.gc:last-child\s*\{[\s\S]*?grid-column: 1 \/ -1/);
assert.match(matrixCss, /\.utility-panel,[\s\S]*?\.trust-strip\s*\{[\s\S]*?grid-column: 1 \/ -1/);
assert.match(matrixCss, /\.utility-panel-wide\s*\{[\s\S]*?width: 100%/);
assert.match(matrixCss, /\.copyable-code\s*\{[\s\S]*?overflow: hidden/);
assert.match(matrixCss, /table\s*\{[\s\S]*?min-width: 0;[\s\S]*?table-layout: fixed/);

assert.match(matrixCss, /\.plan-table \[role="row"\][\s\S]*?grid-template-columns: 110px/);
assert.match(matrixCss, /\.demo-table \[role="row"\][\s\S]*?minmax\(130px, 0\.42fr\)/);
assert.match(matrixCss, /\.risk-tag\.dangerous \{ color: var\(--danger\); \}/);
assert.match(matrixCss, /\.demo-table \[role="row"\]\s*\{[\s\S]*?grid-template-columns: minmax\(0, 1fr\)/);

const appJs = await read("app.js");
assert.match(appJs, /Demo evidence could not be loaded\. You can still run the sample locally\./);
assert.doesNotMatch(appJs, /The setup generator still works/);

const cliDocs = await read("docs/cli/index.html");
assert.match(cliDocs, /with six subcommands/);
assert.match(cliDocs, /readtheplan kubernetes --framework soc2 manifests\.json/);
assert.match(cliDocs, /pci_dss\|fedramp_moderate\|hitrust/);
assert.doesNotMatch(cliDocs, /with five subcommands/);
const adapterDocs = await read("docs/adapters/index.html");
assert.match(adapterDocs, /<strong>CloudFormation<\/strong> and <strong>Kubernetes<\/strong> adapters/);
assert.match(adapterDocs, /tests\/test_k8s_adapter\.py/);
assert.match(adapterDocs, /general <code>analyze<\/code> and <code>agent-gate<\/code> commands remain Terraform\/OpenTofu-specific/);
const readme = await read("../README.md");
assert.match(readme, /six compliance catalogs/);
assert.doesNotMatch(readme, /What.s shipping next: CloudFormation/);

assert.match(homeHtml, /six built-in catalogs/);
const pricingHtml = await read("pricing/index.html");
assert.match(pricingHtml, /Six built-in catalogs cover SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST/);
assert.doesNotMatch(pricingHtml, /SOC 2, ISO 27001, and HIPAA are built-in/);

console.log("Interaction contracts: 85 assertions passed.");
