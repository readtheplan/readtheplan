import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";

const root = new URL("../", import.meta.url);
const read = (path) => fs.readFile(new URL(path, root), "utf8");
const htmlScript = (html) => [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
  .map((match) => match[1]).join("\n");

const html = await read("chat/index.html");
assert.equal(htmlScript(html), "", "chat page must not ship inline scripts (CSP)");
const inline = await read("chat/chat.js");
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
const chatPyproject = await read("../pyproject.toml");
const chatProjectVersion = chatPyproject.match(/^version\s*=\s*"([^"]+)"/m)[1];
assert.ok(source.includes(`readtheplan/readtheplan@v${chatProjectVersion}`),
  "chat prompt version literal must match pyproject (Pages deploys source functions verbatim)");
assert.doesNotMatch(source, /__READTHEPLAN_VERSION__/, "functions must not contain unresolved placeholders");
assert.match(source, /input-file: plan\.json/);
assert.match(source, /more than 300 resource\/action mapping entries/);
assert.match(source, /not distinct controls or certified coverage/);
assert.doesNotMatch(source, /Access-Control-Allow-Origin': '\*'/);
assert.doesNotMatch(source, /console\.error\('DeepSeek API error:', resp\.status, /);

const moduleUrl = "data:text/javascript;base64," + Buffer.from(source).toString("base64");
const module = await import(moduleUrl);
const importFreshChat = () => import(`${moduleUrl}#${randomUUID()}`);

const createSharedLimiter = ({ limit = 15, fail = false } = {}) => {
  const counts = new Map();
  return {
    idFromName(name) {
      assert.match(name, /^[0-9a-f]{64}$/);
      return name;
    },
    get(id) {
      return {
        async fetch() {
          if (fail) throw new Error("limiter unavailable");
          const count = (counts.get(id) || 0) + 1;
          counts.set(id, count);
          return Response.json({
            allowed: count <= limit,
            retryAfterSeconds: count <= limit ? 0 : 60,
          });
        },
      };
    },
  };
};

const chatEnv = (overrides = {}) => ({
  DEEPSEEK_API_KEY: "test",
  CHAT_RATE_LIMITER: createSharedLimiter(),
  ...overrides,
});

const request = (body, origin = "https://readtheplan.dev", options = {}) => new Request(
  "https://readtheplan.dev/api/chat",
  {
    method: "POST",
    signal: options.signal,
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": options.clientIP || randomUUID(),
      ...(origin ? { Origin: origin } : {}),
      ...options.headers,
    },
    body: JSON.stringify(body),
  },
);

const streamedRequest = (text, chunkSizes, options = {}) => {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  let chunkIndex = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (offset >= bytes.byteLength) {
        controller.close();
        return;
      }
      const size = chunkSizes[chunkIndex++] || bytes.byteLength - offset;
      const end = Math.min(offset + size, bytes.byteLength);
      controller.enqueue(bytes.slice(offset, end));
      offset = end;
    },
  });
  return new Request("https://readtheplan.dev/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": options.clientIP || randomUUID(),
      ...options.headers,
    },
    body,
    duplex: "half",
  });
};

const paddedPayload = (byteLength) => {
  const prefix = '{"messages":[{"role":"user","content":"hello"}],"padding":"';
  const suffix = '"}';
  const paddingLength = byteLength - Buffer.byteLength(prefix + suffix);
  assert.ok(paddingLength >= 0);
  return prefix + "x".repeat(paddingLength) + suffix;
};

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
    env: chatEnv(),
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://readtheplan.dev");
  assert.equal(response.headers.get("Vary"), "Origin");
  assert.equal((await response.json()).reply, "ok");
  assert.equal(upstreamCalls, 1);

  const forbidden = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }, "https://example.com"),
    env: chatEnv(),
  });
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(upstreamCalls, 1);

  const serverToServer = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }, ""),
    env: chatEnv(),
  });
  assert.equal(serverToServer.status, 200);
  assert.equal(serverToServer.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(upstreamCalls, 2);

  const invalid = await module.onRequest({
    request: request({ messages: "not-an-array" }),
    env: chatEnv(),
  });
  assert.equal(invalid.status, 400);
  assert.equal(upstreamCalls, 2);
} finally {
  globalThis.fetch = originalFetch;
}

// The actual number of bytes read is authoritative even without Content-Length.
try {
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    return Response.json({ choices: [{ message: { content: "ok" } }] });
  };

  const oversizedPayload = paddedPayload(65_537);
  const oversizedRequest = streamedRequest(oversizedPayload, [32_768, 32_769]);
  assert.equal(oversizedRequest.headers.get("Content-Length"), null);
  let response = await module.onRequest({ request: oversizedRequest, env: chatEnv() });
  assert.equal(response.status, 413);
  assert.equal(upstreamCalls, 0);

  const exactPayload = paddedPayload(65_536);
  const exactRequest = streamedRequest(exactPayload, [16_384, 16_384, 16_384, 16_384]);
  assert.equal(exactRequest.headers.get("Content-Length"), null);
  response = await module.onRequest({ request: exactRequest, env: chatEnv() });
  assert.equal(response.status, 200);
  assert.equal(upstreamCalls, 1);

  const multibytePayload = '{"messages":[{"role":"user","content":"hello"}],"padding":"'
    + "💥".repeat(17_000) + '"}';
  assert.ok(multibytePayload.length < 65_536);
  assert.ok(Buffer.byteLength(multibytePayload) > 65_536);
  response = await module.onRequest({
    request: streamedRequest(multibytePayload, [60_000, 8_000]),
    env: chatEnv(),
  });
  assert.equal(response.status, 413);
  assert.equal(upstreamCalls, 1);
} finally {
  globalThis.fetch = originalFetch;
}

// Two independently imported handler instances must share one allowance.
try {
  const instanceA = await importFreshChat();
  const instanceB = await importFreshChat();
  const sharedLimiter = createSharedLimiter();
  const env = chatEnv({ CHAT_RATE_LIMITER: sharedLimiter });
  const clientIP = "198.51.100.42";
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    return Response.json({ choices: [{ message: { content: "ok" } }] });
  };

  for (let index = 0; index < 15; index += 1) {
    const handler = index % 2 === 0 ? instanceA : instanceB;
    const response = await handler.onRequest({
      request: request({ messages: [{ role: "user", content: "hello" }] }, "", { clientIP }),
      env,
    });
    assert.equal(response.status, 200);
  }
  const rejected = await instanceB.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }, "", { clientIP }),
    env,
  });
  assert.equal(rejected.status, 429);
  assert.equal(rejected.headers.get("Retry-After"), "60");
  assert.equal(upstreamCalls, 15);
} finally {
  globalThis.fetch = originalFetch;
}

// Missing and unhealthy durable protection fail closed before provider work.
try {
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    throw new Error("provider must not be called");
  };
  let response = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: { DEEPSEEK_API_KEY: "test" },
  });
  assert.equal(response.status, 503);

  response = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: chatEnv({ CHAT_RATE_LIMITER: createSharedLimiter({ fail: true }) }),
  });
  assert.equal(response.status, 503);

  let limiterSignal;
  const stalledLimiter = {
    idFromName: (name) => name,
    get: () => ({
      fetch: async (_url, init) => {
        limiterSignal = init.signal;
        return new Promise((_, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        });
      },
    }),
  };
  response = await module.onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: chatEnv({
      CHAT_RATE_LIMITER: stalledLimiter,
      CHAT_RATE_LIMITER_TIMEOUT_MS: 20,
    }),
  });
  assert.equal(response.status, 503);
  assert.equal(limiterSignal.aborted, true);
  assert.equal(upstreamCalls, 0);
} finally {
  globalThis.fetch = originalFetch;
}

// One deadline covers both the provider fetch and complete response-body read.
try {
  let providerSignal;
  globalThis.fetch = async (_url, init) => {
    providerSignal = init.signal;
    return new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    });
  };
  let response = await (await importFreshChat()).onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: chatEnv({ CHAT_PROVIDER_TIMEOUT_MS: 20 }),
  });
  assert.equal(response.status, 504);
  assert.equal(providerSignal.aborted, true);

  globalThis.fetch = async (_url, init) => {
    providerSignal = init.signal;
    return {
      ok: true,
      status: 200,
      json: () => new Promise(() => {}),
    };
  };
  response = await (await importFreshChat()).onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: chatEnv({ CHAT_PROVIDER_TIMEOUT_MS: 20 }),
  });
  assert.equal(response.status, 504);
  assert.equal(providerSignal.aborted, true);

  let successSignal;
  globalThis.fetch = async (_url, init) => {
    successSignal = init.signal;
    return Response.json({ choices: [{ message: { content: "ok" } }] });
  };
  response = await (await importFreshChat()).onRequest({
    request: request({ messages: [{ role: "user", content: "hello" }] }),
    env: chatEnv({ CHAT_PROVIDER_TIMEOUT_MS: 20 }),
  });
  assert.equal(response.status, 200);
  await new Promise((resolve) => setTimeout(resolve, 35));
  assert.equal(successSignal.aborted, false);
} finally {
  globalThis.fetch = originalFetch;
}

// Incoming cancellation reaches the in-flight provider request when supported.
try {
  const inbound = new AbortController();
  let providerStarted;
  const started = new Promise((resolve) => { providerStarted = resolve; });
  let providerSignal;
  globalThis.fetch = async (_url, init) => {
    providerSignal = init.signal;
    providerStarted();
    return new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    });
  };
  const pending = (await importFreshChat()).onRequest({
    request: request(
      { messages: [{ role: "user", content: "hello" }] },
      "https://readtheplan.dev",
      { signal: inbound.signal },
    ),
    env: chatEnv({ CHAT_PROVIDER_TIMEOUT_MS: 500 }),
  });
  await started;
  inbound.abort();
  const response = await pending;
  assert.equal(response.status, 499);
  assert.equal(providerSignal.aborted, true);
} finally {
  globalThis.fetch = originalFetch;
}

// Exercise the repository's Durable Object implementation and atomic window.
const limiterSource = await read("workers/chat-rate-limiter/src/index.js");
const limiterModule = await import(
  "data:text/javascript;base64," + Buffer.from(limiterSource).toString("base64")
);
assert.equal((await limiterModule.default.fetch()).status, 404);
class FakeDurableStorage {
  constructor() {
    this.data = new Map();
    this.tail = Promise.resolve();
    this.alarmAt = null;
  }

  async transaction(callback) {
    const previous = this.tail;
    let release;
    this.tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await callback();
    } finally {
      release();
    }
  }

  async get(key) {
    return this.data.get(key);
  }

  async put(key, value) {
    this.data.set(key, value);
  }

  async delete(key) {
    this.data.delete(key);
  }

  async setAlarm(timestamp) {
    this.alarmAt = timestamp;
  }
}

const realDateNow = Date.now;
try {
  let now = 1_700_000_000_000;
  Date.now = () => now;
  const storage = new FakeDurableStorage();
  const limiter = new limiterModule.ChatRateLimiter({ storage });
  const checks = await Promise.all(Array.from({ length: 16 }, async () => {
    const response = await limiter.fetch(new Request("https://internal/check", { method: "POST" }));
    return response.json();
  }));
  assert.equal(checks.filter((decision) => decision.allowed).length, 15);
  assert.equal(checks.filter((decision) => !decision.allowed).length, 1);
  assert.equal(storage.alarmAt, now + 60_000);

  now += 60_000;
  const reset = await limiter.fetch(new Request("https://internal/check", { method: "POST" }));
  assert.equal((await reset.json()).allowed, true);
} finally {
  Date.now = realDateNow;
}

const limiterConfig = await read("workers/chat-rate-limiter/wrangler.toml");
assert.match(limiterConfig, /name = "readtheplan-chat-rate-limiter"/);
assert.match(limiterConfig, /workers_dev = false/);
assert.match(limiterConfig, /class_name = "ChatRateLimiter"/);
assert.match(limiterConfig, /new_sqlite_classes = \["ChatRateLimiter"\]/);

const health = await read("functions/health.js");
const dataIndex = JSON.parse(await read("data/index.json"));
const conversion = await read("scripts/convert_data.py");
assert.match(health, /version = idx\.version \|\| null/);
assert.equal(dataIndex.version, "0.4.0");
assert.match(conversion, /"version": project_version\(\)/);
let mappingTotal = 0;
let uniqueControlTotal = 0;
for (const framework of Object.values(dataIndex.frameworks)) {
  const catalog = JSON.parse(await read(`data/${framework.file}`));
  const mappingCount = catalog.mappings.length;
  const uniqueControlCount = new Set(
    catalog.mappings.flatMap((mapping) => mapping.controls.map((control) => control.id)),
  ).size;
  assert.equal(framework.control_mapping_count, mappingCount);
  assert.equal(framework.unique_control_count, uniqueControlCount);
  assert.equal(framework.control_count, mappingCount, "legacy alias is mapping-row count");
  mappingTotal += mappingCount;
  uniqueControlTotal += uniqueControlCount;
}
assert.equal(mappingTotal, 314);
assert.equal(uniqueControlTotal, 99);
assert.match(health, /control_mappings_total: controlMappingsTotal/);
assert.match(health, /unique_controls_total: uniqueControlsTotal/);
assert.match(conversion, /def catalog_counts/);

console.log("Chat and site runtime contracts passed.");
