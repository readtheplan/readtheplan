export async function onRequest(context) {
  let version = "unavailable";
  try {
    const response = await fetch(new URL("/data/index.json", context.request.url));
    if (response.ok) version = (await response.json()).version || version;
  } catch (_) { /* data not yet deployed */ }
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "https://readtheplan.dev",
    "Cache-Control": "public, max-age=86400",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"
  };

  return new Response(JSON.stringify({
    openapi: "3.0.3",
    info: {
      title: "readtheplan API",
      version,
      description: "Static data API serving compliance catalogs, demo plans, and version info."
    },
    servers: [{ url: "https://readtheplan.dev" }],
    paths: {
      "/api/v1/controls": {
        get: { summary: "List all compliance frameworks", responses: { "200": { description: "Array of framework summaries" } } }
      },
      "/api/v1/controls/{framework}": {
        get: { summary: "Get a specific compliance catalog", parameters: [{ name: "framework", in: "path", schema: { type: "string", enum: ["soc2","iso27001","hipaa","pci_dss","fedramp_moderate","hitrust"] } }], responses: { "200": { description: "Full control catalog" } } }
      },
      "/api/v1/version": {
        get: { summary: "Get API version and stats", responses: { "200": { description: "Version object" } } }
      },
      "/api/v1/demo": {
        get: { summary: "List demo plans", responses: { "200": { description: "Array of demo plan summaries" } } }
      },
      "/api/v1/demo/{plan}": {
        get: { summary: "Get a demo Terraform plan", responses: { "200": { description: "Terraform plan JSON" } } }
      }
    }
  }, null, 2), {
    status: 200,
    headers
  });
}
