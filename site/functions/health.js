export async function onRequest(context) {
  let version = null;
  let frameworks = 0;
  let controlsTotal = 0;
  try {
    const url = new URL("/data/index.json", context.request.url);
    const resp = await fetch(url);
    if (resp.ok) {
      const idx = await resp.json();
      version = idx.version || null;
      frameworks = Object.keys(idx.frameworks || {}).length;
      controlsTotal = Object.values(idx.frameworks || {})
        .reduce((sum, f) => sum + (f.control_count || 0), 0);
    }
  } catch (_) { /* data not yet deployed */ }

  return new Response(JSON.stringify({
    status: "ok",
    service: "readtheplan",
    version,
    frameworks,
    controls_total: controlsTotal,
    timestamp: new Date().toISOString()
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev",
      "Cache-Control": "no-cache",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"
    }
  });
}
