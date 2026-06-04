export async function onRequest(context) {
  const env = context.env || {};
  const allKeys = Object.keys(env);
  const filtered = allKeys.filter(function(k) { return !k.startsWith("__"); });
  return new Response(JSON.stringify({
    totalKeys: allKeys.length,
    filteredKeys: filtered,
    hasDeepseek: "DEEPSEEK_API_KEY" in env,
    deepseekType: typeof env.DEEPSEEK_API_KEY,
    deepseekLen: typeof env.DEEPSEEK_API_KEY === "string" ? env.DEEPSEEK_API_KEY.length : null,
    cfPages: env.CF_PAGES || "not-set",
    cfPagesUrl: env.CF_PAGES_URL || "not-set",
    cfPagesBranch: env.CF_PAGES_BRANCH || "not-set",
    cfPagesCommitSha: env.CF_PAGES_COMMIT_SHA || "not-set",
  }), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}
