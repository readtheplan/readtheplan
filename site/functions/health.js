export async function onRequest(context) {
  let frameworks = 0;
  let controlsTotal = 0;
  try {
    const url = new URL("/data/index.json", context.request.url);
    const resp = await fetch(url);
    if (resp.ok) {
      const idx = await resp.json();
      frameworks = Object.keys(idx.frameworks || {}).length;
      controlsTotal = Object.values(idx.frameworks || {})
        .reduce((sum, f) => sum + (f.control_count || 0), 0);
    }
  } catch (_) { /* data not yet deployed */ }

  return new Response(JSON.stringify({
    status: "ok",
    service: "readtheplan",
    version: "0.3.0",
    frameworks,
    controls_total: controlsTotal,
    timestamp: new Date().toISOString()
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev",
      "Cache-Control": "no-cache"
    }
  });
}
