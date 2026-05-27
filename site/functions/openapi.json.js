export async function onRequest(context) {
  return new Response(JSON.stringify({
    openapi: "3.0.3",
    info: {
      title: "readtheplan API",
      version: "0.3.0",
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
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev",
      "Cache-Control": "public, max-age=86400"
    }
  });
}
