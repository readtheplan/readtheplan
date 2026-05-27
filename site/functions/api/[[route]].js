// api/[[route]].js — readtheplan static data API
// Serves compliance catalogs, demo plans, and version info from bundled JSON.

import indexData from "../data/index.json";

// Preload framework data (imports resolve at deploy time)
const frameworks = {};
const frameworkNames = Object.keys(indexData.frameworks);
for (const name of frameworkNames) {
  frameworks[name] = await import(`../data/${name}.json`).then(m => m.default);
}

// Preload demo list
let demoList = { demos: [] };
try {
  demoList = await import("../data/demos/index.json").then(m => m.default);
} catch (_) { /* no demos */ }

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev",
      "Cache-Control": "public, max-age=3600",
      ...extraHeaders,
    },
  });
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  let route = context.params.route || [];
  if (!Array.isArray(route)) route = [route];

  // /api/v1/controls — list all frameworks
  if (route[0] === "v1" && route[1] === "controls" && !route[2]) {
    const list = frameworkNames.map(name => ({
      id: name,
      control_count: indexData.frameworks[name].control_count,
      url: `/api/v1/controls/${name}`,
    }));
    return json({ frameworks: list, total: list.length });
  }

  // /api/v1/controls/:framework
  if (route[0] === "v1" && route[1] === "controls" && route[2]) {
    const fw = route[2].toLowerCase();
    const data = frameworks[fw];
    if (!data) {
      return json({ error: "not found", available: frameworkNames }, 404);
    }
    return json(data);
  }

  // /api/v1/version
  if (route[0] === "v1" && route[1] === "version") {
    return json({
      version: indexData.version,
      frameworks: frameworkNames.length,
      controls_total: Object.values(indexData.frameworks)
        .reduce((sum, f) => sum + f.control_count, 0),
      demos: demoList.demos?.length || 0,
      service: "readtheplan",
    });
  }

  // /api/v1/demo/:plan
  if (route[0] === "v1" && route[1] === "demo" && route[2]) {
    const plan = route[2].replace(/\.json$/i, "");
    try {
      const data = await import(`../data/demos/${plan}.json`).then(m => m.default);
      return json(data);
    } catch (_) {
      try {
        const data = await import(`../data/demos/${plan}.meta.json`).then(m => m.default);
        return json(data);
      } catch (_2) {
        return json({
          error: "demo plan not found",
          available: demoList.demos || [],
        }, 404);
      }
    }
  }

  // /api/v1/demo — list demo plans
  if (route[0] === "v1" && route[1] === "demo" && !route[2]) {
    return json({
      demos: (demoList.demos || []).map(d => ({
        id: d.replace(/\.json$/i, ""),
        url: `/api/v1/demo/${d.replace(/\.json$/i, "")}`,
      })),
    });
  }

  // Catch-all: route not implemented
  return json({
    error: "not found",
    available_endpoints: indexData.endpoints,
    documentation: "https://readtheplan.dev/docs",
  }, 404);
}
