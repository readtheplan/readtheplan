# ADR 0014: Keep the product free and separate funding from feature access

- Status: Accepted
- Date: 2026-07-12

## Context

readtheplan is an MIT-licensed, local-first infrastructure analysis project. The
public site previously described hypothetical Managed and Enterprise tiers that
did not match the shipped product. Those promises weakened the simple trust
boundary: users can run the complete toolchain locally without creating an
account or uploading raw infrastructure artifacts.

Cloudflare AI Crawl Control is available on the Free plan for visibility and
allow/block controls. Cloudflare Pay Per Crawl can monetize commercial AI crawler
access, but it remains a closed beta and must not be presented as active until the
zone is enrolled and payment settlement is configured.

References:

- https://developers.cloudflare.com/ai-crawl-control/
- https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/what-is-pay-per-crawl/
- https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/

## Decision

1. Every readtheplan feature remains free and MIT licensed. There is no paid,
   Managed, or Enterprise product tier.
2. The website will not use behavioral advertising scripts or gate human access.
3. Funding experiments must be traffic-side and separable from product access.
   Cloudflare Pay Per Crawl is the preferred experiment after the zone is accepted
   into the beta; no public claim may imply it is already enabled.
4. The site publishes explicit content-use signals: search indexing and live AI
   retrieval are allowed, while model-training permission is not granted.
5. AI crawler blocking must not be enabled blindly. Cloudflare documents that bot
   blocking takes precedence over Pay Per Crawl, so crawler policy must be reviewed
   again during enrollment.
6. Optional chat remains clearly disclosed as a DeepSeek-backed exception to the
   otherwise local data boundary.

## Consequences

- Pricing, legal, chat, brief, and setup-help surfaces describe one free product.
- `robots.txt` and `llms.txt` make the content boundary machine-readable.
- Pay Per Crawl enrollment, Stripe settlement, and bot-policy changes remain an
  account operation, not a code prerequisite.
- If a future funding mechanism requires tracking users or withholding features,
  it requires a new ADR and explicit privacy review.
