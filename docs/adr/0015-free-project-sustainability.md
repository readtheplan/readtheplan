# ADR 0015: Free Project Sustainability

## Status

Accepted

## Context

readtheplan's strongest product boundary is local, account-free infrastructure
analysis. Paid feature tiers, hosted-plan upsells, and private pilot funnels
conflict with that boundary and make the public site's privacy promise harder to
trust.

The website still has operating costs and attracts both human readers and
automated crawlers. Cloudflare AI Crawl Control provides crawler visibility and
allow/block controls. Cloudflare announced the Monetization Gateway in July 2026
for usage-based payments on web
pages, APIs, datasets, and MCP tools, with access initially offered through a
waitlist.

## Decision

All shipped readtheplan software features remain free and MIT licensed. There
will be no paid CLI, adapter, rule pack, compliance catalog, evidence format,
GitHub Action, or local MCP tier.

Project sustainability may use these channels, in order:

1. Clearly labeled project sponsorships and donations.
2. Clearly labeled, context-relevant sponsorship placements on editorial pages.
3. Cloudflare Monetization Gateway for unauthenticated machine calls to future
   public APIs or hosted MCP resources after access is granted, only when those
   resources are additive and the local equivalent remains free.

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
2. Apply for Monetization Gateway access for additive public API or hosted MCP
   resources only.
3. Require owner approval before connecting a wallet or payout account,
   accepting stablecoin settlement, or publishing a price.
4. Leave human traffic, search crawlers, authenticated community integrations,
   and user-initiated assistants free unless traffic data shows abuse.
5. Review revenue, referral loss, failed payments, geographic/tax obligations,
   and false positives before expanding.

The application requires project-owner contact and business details, and
activation may require wallet, payout, tax, and pricing decisions. Those steps
must be completed or explicitly approved by an authorized project owner rather
than silently automated.

## Consequences

The sustainability model is aligned with broad adoption rather than feature
scarcity. Revenue will be modest until readership or machine traffic is
substantial, but the project avoids undermining the local-first trust boundary
to create a sales funnel.

## References

- [Cloudflare AI Crawl Control](https://developers.cloudflare.com/ai-crawl-control/)
- [Cloudflare Monetization Gateway announcement](https://blog.cloudflare.com/monetization-gateway/)
