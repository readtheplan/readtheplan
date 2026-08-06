import fs from "node:fs/promises";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const root = new URL("../", import.meta.url);
const read = async (path) => fs.readFile(new URL(path, root), "utf8");
const htmlScript = (html) => [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join("\n");

const chatHtml = await read("chat/index.html");
assert.equal(htmlScript(chatHtml), "", "chat page must not ship inline scripts (CSP)");
const chatModule = await read("chat/chat.js");
new Function(chatModule);
const renderers = new Function(chatModule + "\nreturn { escapeHtml, renderSafeMarkdown };")();
const hostile = renderers.renderSafeMarkdown('<img src=x onerror=alert(1)> [bad](javascript:alert(1)) [ok](https://example.com)');
assert.match(hostile, /&lt;img/);
assert.doesNotMatch(hostile, /<img/);
assert.doesNotMatch(hostile, /href="javascript:/);
assert.match(hostile, /href="https:\/\/example\.com\/"/);
assert.match(hostile, /rel="noopener noreferrer"/);
assert.match(chatModule, /div\.textContent = text/);
assert.match(chatHtml, /Messages are processed by DeepSeek/);
assert.match(chatHtml, /id="privacyNoticeText"/);
assert.match(chatHtml, /role="status" aria-live="polite"/);
assert.match(chatHtml, /<button[^>]+class="suggestion"/, "suggestion chips must be keyboard-accessible buttons");
assert.match(chatHtml, /<label[^>]+for="userInput"/, "chat input must be labeled");

const privacy = await read("privacy/index.html");
assert.match(privacy, /AI chat:/);
assert.match(privacy, /third-party processor/);
const activationEvents = [
  "verify_change_click",
  "copy_install",
  "playground_run",
  "generate_ci",
  "setup_help_click",
];
for (const eventName of activationEvents) {
  assert.match(privacy, new RegExp(eventName), `privacy policy names ${eventName}`);
}
assert.match(privacy, /never include raw plans, repository contents, file names, credentials, or command output/);
assert.match(privacy, /standard network request metadata/, "privacy policy discloses unavoidable HTTPS metadata processing");
assert.match(privacy, /Count allowlisted activation events/, "privacy policy states the activation-measurement purpose");
assert.match(privacy, /service processors described above/, "privacy policy discloses processor sharing");

const analytics = await read("js/analytics.js");
new Function("window", "document", analytics);
const analyticsRequests = [];
const analyticsListeners = {};
const analyticsWindow = {
  fetch(url, options) {
    analyticsRequests.push({ url, options });
    return Promise.resolve({ ok: true });
  },
};
const analyticsDocument = {
  addEventListener(name, handler) { analyticsListeners[name] = handler; },
};
new Function("window", "document", analytics)(analyticsWindow, analyticsDocument);
assert.equal(typeof analyticsWindow.readtheplanTrack, "function");
assert.deepEqual(analyticsWindow.readtheplanTrack.allowedEvents, activationEvents,
  "the sender allowlist exactly matches the disclosed activation contract");
assert.equal(analyticsWindow.readtheplanTrack("copy_install"), true);
assert.equal(analyticsRequests.length, 1);
assert.equal(analyticsWindow.readtheplanTrack("copy_install"), false,
  "an activation event is counted at most once per page view");
assert.equal(analyticsRequests.length, 1, "duplicate activation is not sent");
assert.equal(analyticsRequests[0].url, "https://plausible.io/api/event");
assert.equal(analyticsRequests[0].options.method, "POST");
assert.equal(analyticsRequests[0].options.credentials, "omit");
assert.equal(analyticsRequests[0].options.referrerPolicy, "no-referrer");
assert.equal(analyticsRequests[0].options.keepalive, true);
assert.deepEqual(JSON.parse(analyticsRequests[0].options.body), {
  name: "copy_install",
  url: "https://readtheplan.dev/activation",
  domain: "readtheplan.dev",
}, "events carry only an allowlisted name and fixed synthetic site fields");
assert.equal(analyticsWindow.readtheplanTrack("unknown_event"), false);
assert.equal(analyticsRequests.length, 1, "unknown events fail closed");
analyticsListeners.click({
  target: {
    closest(selector) {
      assert.equal(selector, "[data-activation-event]");
      return { getAttribute: () => "verify_change_click" };
    },
  },
});
assert.equal(JSON.parse(analyticsRequests[1].options.body).name, "verify_change_click");
analyticsListeners.click({
  target: { closest: () => ({ getAttribute: () => "verify_change_click" }) },
});
assert.equal(analyticsRequests.length, 2, "duplicate CTA clicks are deduplicated in memory");
const baseLayout = await read("_includes/layouts/base.njk");
assert.match(baseLayout, /src="\/js\/analytics\.js"/);
assert.doesNotMatch(baseLayout, /plausible\.io\/js\//,
  "the general Plausible script would add full URL and referrer context");
assert.equal((analytics.match(/\bfetch\s*\(/g) || []).length, 1,
  "analytics has one audited network boundary");
for (const forbidden of [
  "location.search",
  "location.hash",
  "location.href",
  "location.pathname",
  "document.referrer",
  "document.cookie",
  "localStorage",
  "sessionStorage",
  "XMLHttpRequest",
  "planData",
  "event.detail",
  "props",
  "meta",
]) {
  assert.ok(!analytics.includes(forbidden), `analytics module omits ${forbidden}`);
}

const playgroundHtml = await read("playground/index.html");
assert.equal(htmlScript(playgroundHtml), "", "playground page must not ship inline scripts (CSP)");
const playground = await read("playground/playground.js");
new Function(playground);
assert.match(playground, /readtheplanTrack\("playground_run"\)/);
const createPlan = JSON.parse(await read("playground/floci-spike-create-plan.json"));
const destroyPlan = JSON.parse(await read("playground/floci-spike-destroy-plan.json"));
assert.equal(createPlan.resource_changes.length, 7);
assert.equal(destroyPlan.resource_changes.length, 7);
assert.match(playgroundHtml, /Create plan \(7 resources\)/);
assert.match(playgroundHtml, /Destroy plan \(7 resources\)/);
assert.match(playground, /Create plan - 7 resources \(Floci\)/);
assert.match(playground, /Destroy plan - 7 resources \(Floci\)/);
assert.match(playground, /file\.name\.toLowerCase\(\)\.endsWith\("\.json"\)/);
assert.match(playground, /const hasControls = changes\.some/);
assert.match(playground, /const controls = hasControls/);
assert.match(playground, /\(c\.controls \|\| \[\]\)\.map/);
// All six compliance catalogs are selectable in the playground.
for (const framework of ["soc2", "iso27001", "hipaa", "pci-dss", "fedramp-moderate", "hitrust"]) {
  assert.match(playgroundHtml, new RegExp(`<option value="${framework}"`), `playground offers ${framework}`);
}

const prompt = await read("functions/api/chat.js");
new Function(prompt.replace("export async function onRequest", "async function onRequest"));
assert.match(prompt, /readtheplan analyze plan\.json/);
assert.ok(prompt.includes(`readtheplan/readtheplan@v${(await read("../pyproject.toml")).match(/^version\s*=\s*"([^"]+)"/m)[1]}`),
  "chat prompt version must match pyproject");
assert.doesNotMatch(prompt, /__READTHEPLAN_VERSION__/);
assert.match(prompt, /input-file: plan\.json/);
assert.doesNotMatch(prompt, /plan_file:/);
assert.doesNotMatch(prompt, /terraform plan -out=\/dev\/stdout \| readtheplan/);
assert.match(prompt, /broad built-in adapter catalog/);
assert.match(prompt, /There is no paid or enterprise tier/);

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
const catalogIndex = {
  version: "0.4.0",
  frameworks: {
    soc2: {
      control_mapping_count: 3,
      unique_control_count: 2,
      control_count: 3,
    },
  },
};
globalThis.fetch = async () => new Response(JSON.stringify(catalogIndex), { status: 200, headers: { "Content-Type": "application/json" } });
response = await dataApi.onRequest({ request: new Request("https://local/api/v1/version"), params: { route: ["v1", "version"] } });
assert.equal(response.status, 200);
const versionPayload = await response.json();
assert.equal(versionPayload.unique_controls_total, 2);
assert.equal(versionPayload.control_mappings_total, 3);
assert.equal(versionPayload.controls_total, 3, "legacy alias remains mapping-row count");
response = await dataApi.onRequest({ request: new Request("https://local/api/v1/controls"), params: { route: ["v1", "controls"] } });
const frameworkPayload = await response.json();
assert.deepEqual(frameworkPayload.frameworks[0], {
  id: "soc2",
  control_mapping_count: 3,
  unique_control_count: 2,
  control_count: 3,
  url: "/api/v1/controls/soc2",
});

const healthApi = await importSource("functions/health.js");
response = await healthApi.onRequest({ request: new Request("https://local/health") });
const healthPayload = await response.json();
assert.equal(healthPayload.unique_controls_total, 2);
assert.equal(healthPayload.control_mappings_total, 3);
assert.equal(healthPayload.controls_total, 3, "health legacy alias remains mapping-row count");

const openapiApi = await importSource("functions/openapi.json.js");
response = await openapiApi.onRequest({});
const openapi = await response.json();
assert.ok(openapi.paths["/health"]);
assert.equal(openapi.components.schemas.FrameworkSummary.properties.control_count.deprecated, true);
assert.equal(openapi.components.schemas.ServiceStats.properties.controls_total.deprecated, true);
assert.match(
  openapi.components.schemas.ServiceStats.properties.control_mappings_total.description,
  /inventory, not certified coverage/,
);

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
const chatRateLimiter = {
  idFromName: (name) => name,
  get: () => ({
    fetch: async () => Response.json({ allowed: true, retryAfterSeconds: 0 }),
  }),
};
response = await chatApi.onRequest({
  request: chatReq({ messages: [{ role: "user", content: "hello" }] }),
  env: { DEEPSEEK_API_KEY: "test", CHAT_RATE_LIMITER: chatRateLimiter },
});
assert.equal(response.status, 200);
assert.equal(response.headers.get("Cache-Control"), "no-store");
const success = await response.json();
assert.equal(success.reply, "ok alert(1)");
assert.match(success.privacy_notice, /DeepSeek/);

const homeHtml = await read("index.html");
assert.equal(htmlScript(homeHtml), "", "homepage must not ship inline scripts (CSP)");
assert.doesNotMatch(homeHtml, /\son(?:click|keydown|submit|change)=/i, "homepage must not ship inline handlers");
assert.equal((homeHtml.match(/data-activation-event="verify_change_click"/g) || []).length, 1,
  "homepage has one canonical verification CTA event");
assert.equal((homeHtml.match(/data-activation-event="setup_help_click"/g) || []).length, 1,
  "homepage has one explicit founder-assisted setup event");
assert.match(homeHtml, /<label>Optional review catalog<\/label>[\s\S]*?<button class="seg-btn active" data-group="fw" aria-pressed="true">None<\/button>/,
  "optional catalog defaults to None");
assert.match(homeHtml, /<label>Optional evidence output<\/label>[\s\S]*?<button class="seg-btn active" data-group="ev" aria-pressed="true">No evidence file<\/button>/,
  "optional evidence defaults to no extra artifact");
assert.doesNotMatch(homeHtml, /Checklist only|readtheplan-checklist\.json/,
  "the setup wizard must not promise a checklist file that the command does not emit");
assert.match(homeHtml, /SOC 2[\s\S]*?--framework soc2/,
  "sample control IDs disclose the framework flag needed to reproduce them");
assert.doesNotMatch(homeHtml, /id="demo-pause"/, "the single-scenario demo has no meaningless pause control");
const mcpHtml = await read("mcp/index.html");
assert.equal((mcpHtml.match(/data-activation-event="setup_help_click"/g) || []).length, 2,
  "the two explicit MCP setup-help links carry the setup event");
const pricingActivationHtml = await read("pricing/index.html");
assert.equal((pricingActivationHtml.match(/data-activation-event="setup_help_click"/g) || []).length, 1,
  "pricing has one explicit setup-help event");
for (const [page, html] of Object.entries({ home: homeHtml, mcp: mcpHtml, pricing: pricingActivationHtml })) {
  for (const match of html.matchAll(/data-activation-event="([^"]+)"/g)) {
    assert.ok(activationEvents.includes(match[1]), `${page} uses only disclosed activation event ${match[1]}`);
  }
}
const homeInline = await read("js/home.js");
new Function(homeInline);
assert.match(homeInline, /readtheplanTrack\("copy_install"\)/);
assert.match(homeInline, /readtheplanTrack\("generate_ci"\)/);
assert.doesNotMatch(`${analytics}\n${homeInline}\n${playground}`, /gate_enabled/,
  "browser activity must not be mislabeled as a repository-enabled gate");
assert.match(homeInline, /if \(order\.length < 2\) return;/,
  "a single demo scenario must not restart an identical animation timer");
assert.doesNotMatch(homeInline, /demo-pause/,
  "the removed demo pause control must not leave a dead event-handler path");
for (const deadScenario of ["repository:", "kubernetes:", "pipeline:"]) {
  assert.ok(!homeInline.includes(deadScenario), `homepage demo omits unreachable ${deadScenario}`);
}
const pyprojectToml = await read("../pyproject.toml");
const projectVersion = pyprojectToml.match(/^version\s*=\s*"([^"]+)"/m)[1];
const stateGroups = {
  ci: [
    "GitHub Actions",
    "GitLab CI",
    "CircleCI",
    "Jenkins",
    "Azure DevOps",
    "Buildkite",
    "Bitbucket",
    "Local only",
  ],
  fw: ["SOC 2", "ISO 27001", "HIPAA", "None"],
  thresh: ["Irreversible only", "Dangerous", "Review", "Don't block"],
  ev: ["JSON envelope", "Signed (OIDC)", "No evidence file"],
};
const activeState = { ci: "GitHub Actions", fw: "None", thresh: "Dangerous", ev: "No evidence file" };
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
    if (selector === ".site-brand__version") return { textContent: `v${projectVersion}` };
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
  homeInline + "\nreturn { activeVal, activeFramework, activeThreshold, activeEvidence, cliCommand, workflowText, updateGen, updateCLIPreview };",
)(fakeDocument, { clipboard: { writeText: async () => {} } }, { getSelection: () => ({ removeAllRanges() {}, addRange() {} }) }, () => {});
const activate = (group, label) => { activeState[group] = label; };
assert.ok(homeApi.workflowText().includes(`uses: readtheplan/readtheplan@v${projectVersion}`), "workflow pins the pyproject version");
assert.match(homeApi.workflowText(), /uses: actions\/checkout@v4/);
assert.match(homeApi.workflowText(), /Prerequisite: authenticate Terraform\/OpenTofu and generate plan\.json/);
assert.match(homeApi.workflowText(), /https:\/\/readtheplan\.dev\/docs\/github-action\//);
assert.match(homeApi.workflowText(), /input-file: plan\.json/);
assert.match(homeApi.workflowText(), /fail-on-threshold: dangerous/);
assert.doesNotMatch(homeApi.workflowText(), /Generate evidence artifact|--framework|--evidence/,
  "default workflow stays focused on the gate");
activate("fw", "SOC 2");
assert.match(homeApi.workflowText(), /- name: Generate analysis summary/,
  "catalog-only mode names the summary artifact honestly");
assert.doesNotMatch(homeApi.workflowText(), /Generate evidence artifact/);
activate("ev", "JSON envelope");
assert.match(homeApi.workflowText(), /- name: Generate evidence and analysis summary/,
  "evidence mode names both emitted outputs");
assert.match(homeApi.workflowText(), /--framework soc2 --format json --evidence readtheplan-evidence\.json/);
activate("ci", "GitLab CI");
assert.match(homeApi.workflowText(), /image: python:3\.13/);
assert.match(homeApi.workflowText(), /artifacts:/);
assert.doesNotMatch(homeApi.workflowText(), /uses: readtheplan/);
activate("ci", "CircleCI");
assert.match(homeApi.workflowText(), /version: 2\.1/);
assert.match(homeApi.workflowText(), /cimg\/python:3\.13/);
activate("ci", "Jenkins");
assert.match(homeApi.workflowText(), /stage\('Infrastructure risk gate'\)/);
assert.match(homeApi.workflowText(), /--fail-on dangerous/);
activate("ci", "Azure DevOps");
assert.match(homeApi.workflowText(), /azure-pipelines\.yml/);
assert.match(homeApi.workflowText(), /displayName: Gate infrastructure risk/);
activate("ci", "Buildkite");
assert.match(homeApi.workflowText(), /\.buildkite\/pipeline\.yml/);
assert.match(homeApi.workflowText(), /commands:/);
activate("ci", "Bitbucket");
assert.match(homeApi.workflowText(), /bitbucket-pipelines\.yml/);
assert.match(homeApi.workflowText(), /image: python:3\.13-slim/);
activate("ci", "Local only");
assert.match(homeApi.workflowText(), /terraform show -json tfplan > plan\.json/);
assert.match(homeApi.workflowText(), /--fail-on dangerous/);
assert.doesNotMatch(homeApi.workflowText(), /artifacts:/);
activate("fw", "None");
activate("ev", "JSON envelope");
assert.doesNotMatch(homeApi.cliCommand(false, true), /--framework/);
assert.match(homeApi.cliCommand(false, true), /--evidence readtheplan-evidence\.json/);
assert.match(homeApi.cliCommand(false, true), /--fail-on dangerous/);
activate("fw", "SOC 2");
activate("ev", "Signed (OIDC)");
activate("thresh", "Don't block");
assert.match(homeApi.cliCommand(false, true), /--sign/);
assert.doesNotMatch(homeApi.cliCommand(false, true), /--fail-on/);
activate("ci", "GitHub Actions");
assert.match(homeApi.workflowText(), /readtheplan\[sign\]/);
activate("ci", "CircleCI");
activate("fw", "HIPAA");
activate("ev", "JSON envelope");
activate("thresh", "Review");
assert.match(homeApi.workflowText(), /--framework hipaa/);
assert.match(homeApi.workflowText(), /--fail-on review/);
homeApi.updateGen();
homeApi.updateCLIPreview();
assert.match(fakeElements["gen-output"].textContent, /version: 2\.1/);
assert.equal(fakeElements["gen-label"].textContent, "Generated CircleCI config");
assert.match(fakeElements["cli-preview-cmd"].textContent, /--fail-on review/);

const systemCss = await read("modern.css");
assert.match(systemCss, /@media \(max-width: 720px\)/);
assert.match(systemCss, /\.console-meta\s*\{[^}]*flex-wrap:\s*wrap;/,
  "console metadata wraps instead of overflowing narrow proof surfaces");
assert.match(systemCss, /\.console-meta code\s*\{[^}]*white-space:\s*nowrap;/,
  "copyable framework flags stay visually intact");
assert.match(systemCss, /\.table-wrap \{ overflow-x: auto/);
assert.match(systemCss, /\.plan-table-body \[role="row"\], \.demo-table \[role="row"\][\s\S]*?grid-template-columns: 110px minmax\(130px, 0\.42fr\)/);
assert.match(systemCss, /\.risk-tag\.dangerous[\s\S]*?color: var\(--danger\)/);
assert.match(systemCss, /\.plan-table-body \[role="row"\], \.demo-table \[role="row"\] \{\s*\n\s*grid-template-columns: minmax\(0, 1fr\)/);
assert.match(systemCss, /prefers-reduced-motion/);

const demoJs = await read("js/demo.js");
assert.match(demoJs, /Demo evidence could not be loaded\. You can still run the sample locally\./);
assert.doesNotMatch(demoJs, /The setup generator still works/);

const cliDocs = await read("docs/cli/index.html");
assert.match(cliDocs, /one local CLI/);
assert.match(cliDocs, /readtheplan kubernetes --framework soc2 manifests\.json/);
assert.match(cliDocs, /pci_dss\|fedramp_moderate\|hitrust/);
const adapterDocs = await read("docs/adapters/index.html");
assert.match(adapterDocs, /<h1 id="title">Secondary adapters beyond the Terraform\/OpenTofu gate\.<\/h1>/);
assert.match(adapterDocs, /<strong>CloudFormation and AWS CDK<\/strong>/);
assert.match(adapterDocs, /<strong>Kubernetes<\/strong>/);
assert.match(adapterDocs, /<strong>Ansible playbooks and project configuration<\/strong>/);
assert.match(adapterDocs, /<strong>Jenkins pipelines\/JCasC<\/strong>/);
assert.match(adapterDocs, /<strong>Chef recipes, projects, and runtime configuration<\/strong>/);
assert.match(adapterDocs, /<strong>Puppet manifests and projects<\/strong>/);
assert.match(adapterDocs, /<strong>Docker Compose and Buildx Bake<\/strong>/);
assert.match(adapterDocs, /BaseAdapter/);
const readme = await read("../README.md");
assert.match(readme, /SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST/);
assert.doesNotMatch(readme, /What.s shipping next: CloudFormation/);
const readmeQuickstart = readme.match(/## Quickstart([\s\S]*?)## Usage/)[1];
assert.match(readmeQuickstart, /terraform show -json tfplan > plan\.json[\s\S]*?readtheplan agent-gate plan\.json/,
  "README primary quickstart follows the Terraform plan-to-gate journey");
assert.doesNotMatch(readmeQuickstart, /readtheplan scan \./,
  "repository scanning remains secondary rather than competing in the primary quickstart");
assert.match(homeHtml, /Signatures protect artifact integrity; mappings do not certify control satisfaction\./,
  "homepage evidence copy preserves the compliance boundary");

assert.doesNotMatch(homeHtml, /Six built-in catalogs/,
  "compliance inventory must not compete with the primary Terraform activation path");
const pricingHtml = await read("pricing/index.html");
assert.match(pricingHtml, /Six built-in catalogs cover SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST/);
assert.doesNotMatch(pricingHtml, /SOC 2, ISO 27001, and HIPAA are built-in/);
assert.match(pricingHtml, /Everything is free/);
assert.doesNotMatch(pricingHtml, /\$499|Managed platform|Enterprise adds/);

console.log("Interaction contracts: CI-neutral setup assertions passed.");
