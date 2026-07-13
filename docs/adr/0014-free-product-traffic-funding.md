# ADR 0014: Keep the product free and separate funding from feature access

- Status: Superseded by ADR 0015
- Date: 2026-07-12

## Context

readtheplan is an MIT-licensed, local-first infrastructure analysis project. The
public site previously described hypothetical Managed and Enterprise tiers that
did not match the shipped product. Those promises weakened the simple trust
boundary: users can run the complete toolchain locally without creating an
account or uploading raw infrastructure artifacts.

Cloudflare AI Crawl Control is available on the Free plan for visibility and
allow/block controls.

References:

- https://developers.cloudflare.com/ai-crawl-control/
- https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/

## Decision

1. Every readtheplan feature remains free and MIT licensed. There is no paid,
   Managed, or Enterprise product tier.
2. The website will not use behavioral advertising scripts or gate human access.
3. Funding experiments must be separable from product access. The current
   sustainability decision is recorded in ADR 0015.
4. The site publishes explicit content-use signals: search indexing and live AI
   retrieval are allowed, while model-training permission is not granted.
5. AI crawler blocking must not be enabled blindly. Crawler policy must preserve
   normal search and referral traffic while addressing demonstrated abuse.
6. Optional chat remains clearly disclosed as a DeepSeek-backed exception to the
   otherwise local data boundary.

## Consequences

- Pricing, legal, chat, brief, and setup-help surfaces describe one free product.
- `robots.txt` and `llms.txt` make the content boundary machine-readable.
- Bot-policy and Cloudflare account changes remain account operations, not code
  prerequisites.
- If a future funding mechanism requires tracking users or withholding features,
  it requires a new ADR and explicit privacy review.
