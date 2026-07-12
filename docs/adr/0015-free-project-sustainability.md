# ADR 0015: Free Project Sustainability

## Status

Proposed

## Context

readtheplan's strongest product boundary is local, account-free infrastructure
analysis. Paid feature tiers, hosted-plan upsells, and private pilot funnels
conflict with that boundary and make the public site promise harder to trust.

The website still has operating costs and attracts both human readers and
automated crawlers. Cloudflare AI Crawl Control already reports crawler traffic
for `readtheplan.dev`, but Pay Per Crawl remains a closed beta and the current
account exposes allow/block controls rather than a charge control.

## Decision

All shipped readtheplan software features remain free and MIT licensed. There
will be no paid CLI, adapter, rule pack, compliance catalog, evidence format,
GitHub Action, or local MCP tier.

Project sustainability may use these channels, in order:

1. Clearly labeled project sponsorships and donations.
2. Clearly labeled, context-relevant sponsorship placements on editorial pages.
3. Cloudflare Pay Per Crawl for machine traffic after beta access is granted.
4. Cloudflare's machine-payment tooling for future public APIs or hosted MCP
   resources only if those resources are additive and the local equivalent
   remains free.

## Guardrails

- Normal human access remains free and requires no account.
- Risk classifications, documentation rankings, and compliance guidance cannot
  be bought or influenced by a sponsor.
- No behavioral advertising, cross-site tracking, dark patterns, or paid search
  placement is introduced.
- No monetization claim is published before the corresponding channel is active.
- Any new analytics, advertising, or payment processor requires an updated
  privacy disclosure before deployment.
- Raw infrastructure inputs are never uploaded merely to create a monetizable
  hosted path.

## Cloudflare Rollout

1. Keep AI Crawl Control analytics enabled and preserve search/referral crawlers.
2. Apply to the Pay Per Crawl closed beta as a publisher.
3. After acceptance, connect the required payout account and start with the
   minimum supported price on training crawlers only.
4. Leave search crawlers and user-initiated assistants allowed unless traffic
   data shows abuse.
5. Review crawl revenue, referral loss, and false positives before expanding.

The beta application requires contact details, country, and consent to receive
Cloudflare product communications. It must be submitted by an authorized project
owner rather than silently automated.

## Consequences

The business model is aligned with broad adoption rather than feature scarcity.
Revenue will be modest until readership or machine traffic is substantial, but
the project avoids undermining the local-first trust boundary to create a sales
funnel.
