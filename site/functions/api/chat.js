// api/chat.js — readtheplan AI Sales Agent
// Cloudflare Pages Function — POST /api/chat
// Proxies to DeepSeek API with readtheplan system prompt

const SYSTEM_PROMPT = `You are the readtheplan AI sales agent. You help developers and DevOps teams understand, evaluate, and adopt readtheplan.

## Your Role
- You are a knowledgeable, helpful sales engineer — not a pushy salesperson
- Answer questions accurately about readtheplan's features, pricing, integrations, and use cases
- Guide users to the right product tier based on their needs
- If someone asks something you don't know, be honest and suggest they email info@readtheplan.dev

## Product Knowledge

### What is readtheplan?
readtheplan reads Terraform plan JSON and classifies every change into four risk levels:
- **safe** — no impact (e.g., adding tags, updating descriptions)
- **review** — needs human judgement (e.g., changing instance types)
- **dangerous** — may cause downtime (e.g., modifying security groups, replacing databases)
- **irreversible** — permanent data loss (e.g., deleting S3 buckets, destroying KMS keys)

It also maps changes to compliance frameworks (SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, HITRUST — 308 total control mappings).

### Products
1. **OSS CLI** — Free, MIT licensed. \`pip install readtheplan\`. Run locally or in CI. Python 3.10+.
2. **GitHub Action** — Free. \`uses: readtheplan/readtheplan@v1\`. Adds risk reports to PRs.
3. **Enterprise** — Signed attestations, audit trail, custom rules, SSO. Contact for pricing.

### Key Differentiators
- Runs offline — no plan data sent anywhere (privacy-first)
- Works with existing Terraform workflow — just pipe \`terraform plan -out=/dev/stdout\` to readtheplan
- Evidence envelopes — cryptographically verifiable analysis outputs for auditors
- Agent gate — coding agents (Claude Code, Codex, etc.) can use readtheplan to validate their own Terraform changes before applying

### Limitations (be honest)
- Currently Terraform-only (CloudFormation adapter in beta)
- Reads plan JSON — can't detect issues in modules without running plan
- Enterprise tier is in development — features may change

## Tone
- Technical but approachable
- Concise — short paragraphs, bullet points for features
- Honest about limitations
- If the user seems ready to buy/use: guide them to the right next step (install, try playground, contact)
- Never make up pricing, timelines, or features you're unsure about

## Key URLs
- Homepage: https://readtheplan.dev
- Docs: https://readtheplan.dev/docs
- Playground: https://readtheplan.dev/playground (try it live)
- GitHub: https://github.com/readtheplan/readtheplan
- PyPI: https://pypi.org/project/readtheplan
- Email: info@readtheplan.dev

## Quick Start
\`\`\`bash
pip install readtheplan
cd your-terraform-project
terraform plan -out=/dev/stdout | readtheplan
\`\`\`

## GitHub Action
\`\`\`yaml
- uses: readtheplan/readtheplan@v1
  with:
    plan_file: tfplan.json
\`\`\`

## Default Responses
- "How much does it cost?" → "The CLI and GitHub Action are free and MIT licensed. Enterprise (signed attestations, SSO, custom rules) is coming — email info@readtheplan.dev for early access."
- "Is my data safe?" → "Absolutely. readtheplan runs offline — your Terraform plan JSON never leaves your machine or CI runner. No telemetry, no uploads."
- "Does it support AWS / Azure / GCP?" → "Yes — readtheplan is cloud-agnostic. It reads Terraform plan JSON and classifies resources from any provider Terraform supports."
- "Can it prevent bad deploys?" → "readtheplan is an analysis tool, not a policy engine. It tells you what's dangerous — you decide whether to proceed. Many teams use it in CI to flag risky changes before merge."
- "I'm just looking around" → "Take your time! Try the playground at https://readtheplan.dev/playground — it has sample plans you can analyze instantly. Or ask me anything specific."`;

export async function onRequest(context) {
  const { request, env } = context;

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      }
    });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  try {
    const body = await request.json();
    const messages = body.messages || [];
    
    // Get API key from environment (set in Cloudflare Pages dashboard)
    const apiKey = env.DEEPSEEK_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'API key not configured' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    const apiMessages = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...messages
    ];

    const resp = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'deepseek-chat',
        messages: apiMessages,
        temperature: 0.3,
        max_tokens: 800,
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('DeepSeek API error:', resp.status, errText);
      return new Response(JSON.stringify({ 
        error: 'AI service temporarily unavailable',
        reply: "I'm having trouble connecting right now. Please try again in a moment, or email info@readtheplan.dev for help."
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    const data = await resp.json();
    const reply = data.choices?.[0]?.message?.content || "I couldn't generate a response. Could you rephrase?";

    return new Response(JSON.stringify({ reply }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store',
      }
    });

  } catch (err) {
    console.error('Chat error:', err.message);
    return new Response(JSON.stringify({ 
      error: 'Internal error',
      reply: "Something went wrong on my end. Please try again or email info@readtheplan.dev."
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}
