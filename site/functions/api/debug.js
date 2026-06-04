export async function onRequest(context) {
  const { env } = context;
  const allKeys = Object.keys(env);
  const filtered = allKeys.filter(k => !k.startsWith('__'));
  return new Response(JSON.stringify({
    totalKeys: allKeys.length,
    filteredKeys: filtered,
    hasDeepseek: 'DEEPSEEK_API_KEY' in env,
    deepseekLen: typeof env.DEEPSEEK_API_KEY === 'string' ? env.DEEPSEEK_API_KEY.length : 'not-a-string',
    cfPages: env.CF_PAGES || 'not-set',
  }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}
