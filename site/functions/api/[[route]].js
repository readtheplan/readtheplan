// api/[[route]].js — readtheplan static data API
// Fetches bundled JSON data from /data/ (served as static assets by Cloudflare Pages)

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://readtheplan.dev",
  "Cache-Control": "public, max-age=3600",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS, ...extraHeaders },
  });
}

async function fetchData(request, path) {
  const url = new URL(path, request.url);
  const resp = await fetch(url);
  if (!resp.ok) return null;
  return resp.json();
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: { ...CORS_HEADERS, Allow: "GET, HEAD, OPTIONS" },
    });
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return json({ error: "method not allowed" }, 405, {
      Allow: "GET, HEAD, OPTIONS",
    });
  }
  let route = context.params.route || [];
  if (!Array.isArray(route)) route = [route];

  // /api/v1/controls — list all frameworks
  if (route[0] === "v1" && route[1] === "controls" && !route[2]) {
    const idx = await fetchData(request, "/data/index.json");
    if (!idx) return json({ error: "data not available" }, 503);
    const list = Object.keys(idx.frameworks).map(name => ({
      id: name,
      control_count: idx.frameworks[name].control_count,
      url: `/api/v1/controls/${name}`,
    }));
    return json({ frameworks: list, total: list.length });
  }

  // /api/v1/controls/:framework
  if (route[0] === "v1" && route[1] === "controls" && route[2]) {
    const fw = route[2].toLowerCase().replace(/[^a-z0-9_]/g, "");
    const idx = await fetchData(request, "/data/index.json");
    if (!idx) return json({ error: "data not available" }, 503);
    if (!idx.frameworks[fw]) {
      return json({ error: "not found", available: Object.keys(idx.frameworks) }, 404);
    }
    const data = await fetchData(request, `/data/${fw}.json`);
    if (!data) return json({ error: "framework data not available" }, 503);
    return json(data);
  }

  // /api/v1/version
  if (route[0] === "v1" && route[1] === "version") {
    const idx = await fetchData(request, "/data/index.json");
    if (!idx) {
      return json({ version: null, service: "readtheplan", data_available: false });
    }
    return json({
      version: idx.version || null,
      frameworks: Object.keys(idx.frameworks || {}).length,
      controls_total: Object.values(idx.frameworks || {})
        .reduce((sum, f) => sum + (f.control_count || 0), 0),
      service: "readtheplan",
    });
  }

  // /api/v1/demo — list demo plans
  if (route[0] === "v1" && route[1] === "demo" && !route[2]) {
    const demos = await fetchData(request, "/data/demos/index.json");
    if (!demos) return json({ error: "demo data not available" }, 503);
    return json({
      demos: (demos.demos || []).map(d => ({
        id: d.replace(/\.json$/i, ""),
        url: `/api/v1/demo/${d.replace(/\.json$/i, "")}`,
      })),
    });
  }

  // /api/v1/demo/:plan
  if (route[0] === "v1" && route[1] === "demo" && route[2]) {
    const plan = route[2].replace(/[^a-zA-Z0-9_.-]/g, "");
    const data = await fetchData(request, `/data/demos/${plan}.json`);
    if (data) return json(data);
    // Try .meta.json variant
    const metaPlan = plan.replace(/\.meta$/, "");
    const meta = await fetchData(request, `/data/demos/${metaPlan}.meta.json`);
    if (meta) return json(meta);
    const demos = await fetchData(request, "/data/demos/index.json");
    return json({
      error: "demo plan not found",
      available: (demos?.demos || []).map(d => d.replace(/\.json$/i, "")),
    }, 404);
  }

  // Catch-all
  const idx = await fetchData(request, "/data/index.json");
  return json({
    error: "not found",
    available_endpoints: idx?.endpoints || {
      controls: "/api/v1/controls",
      demo: "/api/v1/demo",
      version: "/api/v1/version",
    },
    documentation: "https://readtheplan.dev/docs",
  }, 404);
}
