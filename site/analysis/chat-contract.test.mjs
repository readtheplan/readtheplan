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
const hostile = renderSafeMarkdown(
  '<img src=x onerror=alert(1)> [bad](javascript:alert(1)) [ok](https://example.com)',
);
assert.match(hostile, /&lt;img/);
assert.doesNotMatch(hostile, /<img/);
assert.doesNotMatch(hostile, /href="javascript:/);
assert.match(hostile, /href="https:\/\/example\.com\//);
assert.match(hostile, /rel="noopener noreferrer"/);
assert.match(inline, /div\.textContent = text/);
assert.match(inline, /Retry-After/);
assert.match(inline, /retry\.textContent = 'Retry'/);
assert.match(inline, /userMessage\.remove\(\)/);
assert.match(html, /Messages are processed by DeepSeek/);
assert.match(html, /role="status" aria-live="polite"/);

const source = await read("functions/api/chat.js");
assert.match(source, /readtheplan analyze plan\.json/);
assert.match(source, /readtheplan\/readtheplan@v0\.4\.0/);
assert.match(source, /input-file: plan\.json/);
assert.match(source, /more than 300 control mappings/);
assert.doesNotMatch(source, /Access-Control-Allow-Origin': '\*'/);
assert.doesNotMatch(source, /console\.error\('DeepSeek API error:', resp\.status, /);

const module = await import(
  "data:text/javascript;base64," + Buffer.from(source).toString("base64")
);
const request = (body, origin = "https://readtheplan.dev") => new Request(
  "https://readtheplan.dev/api/chat",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": randomUUID(),
      Origin: origin,
    },
    body: JSON.stringify(body),
  },
);

const originalFetch = globalThis.fetch;
try {
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    return new Response(JSON.stringify({
      choices: [{ message: { content: "<b>ok</b>" } }],
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const response = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://readtheplan.dev");
  assert.equal(response.headers.get("Vary"), "Origin");
  assert.equal((await response.json()).reply, "ok");
  assert.equal(upstreamCalls, 1);

  const forbidden = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }, "https://example.com"),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(upstreamCalls, 1);

  const serverToServer = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }, ""),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(serverToServer.status, 200);
  assert.equal(serverToServer.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(upstreamCalls, 2);

  const invalid = await module.onRequest({
    request: request({ messages: "not-an-array" }),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(invalid.status, 400);
  assert.equal(upstreamCalls, 2);
} finally {
  globalThis.fetch = originalFetch;
}

const health = await read("functions/health.js");
const dataIndex = JSON.parse(await read("data/index.json"));
const conversion = await read("scripts/convert_data.py");
assert.match(health, /version = idx\.version \|\| null/);
assert.equal(dataIndex.version, "0.4.0");
assert.match(conversion, /"version": project_version\(\)/);

console.log("Chat and site runtime contracts passed.");
