export async function onRequest(context) {
  return new Response(JSON.stringify({
    openapi: "3.0.3",
    info: {
      title: "readtheplan API",
      version: "0.0.0",
      description: "API is currently offline."
    },
    paths: {}
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://readtheplan.dev"
    }
  });
}
