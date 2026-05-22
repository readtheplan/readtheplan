export async function onRequest(context) {
  return new Response(JSON.stringify({
    status: "unavailable",
    message: "API is currently offline. The readtheplan SaaS backend is not active."
  }), {
    status: 503,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev",
      "Cache-Control": "public, max-age=3600"
    }
  });
}
