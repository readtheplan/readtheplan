export async function onRequest(context) {
  // Try to load index for stats (may not be bundled yet in first deploy)
  let frameworks = 0;
  let controlsTotal = 0;
  try {
    const idx = await import("../data/index.json").then(m => m.default);
    frameworks = Object.keys(idx.frameworks || {}).length;
    controlsTotal = Object.values(idx.frameworks || {})
      .reduce((sum, f) => sum + (f.control_count || 0), 0);
  } catch (_) { /* pre-data-bundle */ }

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
