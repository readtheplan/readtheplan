export async function onRequest(context) {
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
      version: "0.5.0",
      description: "Static data API serving compliance catalogs, demo plans, and version info."
    },
    servers: [{ url: "https://readtheplan.dev" }],
    paths: {
      "/health": {
        get: {
          summary: "Get service health and catalog inventory",
          responses: {
            "200": {
              description: "Health and catalog inventory",
              content: {
                "application/json": {
                  schema: { "$ref": "#/components/schemas/ServiceStats" }
                }
              }
            }
          }
        }
      },
      "/api/v1/controls": {
        get: {
          summary: "List all compliance frameworks",
          responses: {
            "200": {
              description: "Array of framework summaries",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      frameworks: {
                        type: "array",
                        items: { "$ref": "#/components/schemas/FrameworkSummary" }
                      },
                      total: { type: "integer" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/v1/controls/{framework}": {
        get: { summary: "Get a specific compliance catalog", parameters: [{ name: "framework", in: "path", schema: { type: "string", enum: ["soc2","iso27001","hipaa","pci_dss","fedramp_moderate","hitrust"] } }], responses: { "200": { description: "Full control catalog" } } }
      },
      "/api/v1/version": {
        get: {
          summary: "Get API version and catalog inventory",
          responses: {
            "200": {
              description: "Version and catalog inventory",
              content: {
                "application/json": {
                  schema: { "$ref": "#/components/schemas/ServiceStats" }
                }
              }
            }
          }
        }
      },
      "/api/v1/demo": {
        get: { summary: "List demo plans", responses: { "200": { description: "Array of demo plan summaries" } } }
      },
      "/api/v1/demo/{plan}": {
        get: { summary: "Get a demo Terraform plan", responses: { "200": { description: "Terraform plan JSON" } } }
      }
    },
    components: {
      schemas: {
        FrameworkSummary: {
          type: "object",
          required: ["id", "unique_control_count", "control_mapping_count", "url"],
          properties: {
            id: { type: "string" },
            unique_control_count: {
              type: "integer",
              description: "Distinct framework-scoped control IDs referenced by this catalog."
            },
            control_mapping_count: {
              type: "integer",
              description: "Resource/action mapping rows, including generic baseline mappings. This is catalog inventory, not certified coverage."
            },
            control_count: {
              type: "integer",
              deprecated: true,
              description: "Deprecated alias of control_mapping_count retained for compatibility."
            },
            url: { type: "string" }
          }
        },
        ServiceStats: {
          type: "object",
          properties: {
            status: { type: "string" },
            service: { type: "string" },
            version: { type: "string", nullable: true },
            frameworks: { type: "integer" },
            unique_controls_total: {
              type: "integer",
              description: "Sum of distinct control IDs within each framework. IDs are framework-scoped; this is inventory, not certified coverage."
            },
            control_mappings_total: {
              type: "integer",
              description: "Total resource/action mapping rows, including generic baseline mappings. This is inventory, not certified coverage."
            },
            controls_total: {
              type: "integer",
              deprecated: true,
              description: "Deprecated alias of control_mappings_total retained for compatibility."
            },
            timestamp: { type: "string", format: "date-time" }
          }
        }
      }
    }
  }, null, 2), {
    status: 200,
    headers
  });
}
