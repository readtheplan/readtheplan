import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";

const root = new URL("../", import.meta.url);
const read = (path) => fs.readFile(new URL(path, root), "utf8");
const htmlScript = (html) => [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1]).join("\n");

const html = await read("chat/index.html");
const inline = htmlScript(html);
new Function(inline);
const { renderSafeMarkdown } = new Function(`${inline}\nreturn { renderSafeMarkdown };`)();
const hostile = renderSafeMarkdown('<img src=x onerror=alert(1)> [bad](javascript:alert(1)) [ok](https://example.com)');
assert.match(hostile, /&lt;img/);
assert.doesNotMatch(hostile, /<img/);
assert.doesNotMatch(hostile, /href="javascript:/);
assert.match(hostile, /href="https:\/\/example\.com"/);
assert.match(hostile, /rel="noopener noreferrer"/);
assert.match(inline, /div\.textContent = text/);
assert.match(inline, /Retry-After/);
assert.match(inline, /retry\.textContent = 'Retry'/);
assert.match(html, /Messages are processed by DeepSeek/);
assert.match(html, /id="privacyNoticeText"/);
assert.match(html, /role="status" aria-live="polite"/);

const source = await read("functions/api/chat.js");
assert.match(source, /readtheplan analyze plan\.json/);
assert.match(source, /readtheplan\/readtheplan@v0\.3\.0/);
assert.match(source, /plan-file: plan\.json/);
assert.doesNotMatch(source, /plan_file:/);
assert.doesNotMatch(source, /terraform plan -out=\/dev\/stdout \| readtheplan/);
assert.match(source, /Resource-aware rules currently cover AWS, GCP, Azure, and Kubernetes/);

const module = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const request = (body) => new Request("https://local/api/chat", {
  method: "POST",
  headers: { "Content-Type": "application/json", "CF-Connecting-IP": randomUUID() },
  body: JSON.stringify(body),
});

const originalFetch = globalThis.fetch;
try {
  globalThis.fetch = async () => new Response(JSON.stringify({ choices: [{ message: { content: "<b>ok</b>" } }] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
  const response = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal((await response.json()).reply, "ok");
} finally {
  globalThis.fetch = originalFetch;
}

console.log("Chat contracts passed.");
