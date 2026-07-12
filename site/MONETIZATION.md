# Free-product monetization policy

readtheplan is free forever. The CLI, CI integrations, MCP tools, compliance
catalogs, custom rules, and signed evidence remain available under the MIT
License without accounts, subscriptions, usage charges, or feature gates.

## Allowed funding

- GitHub Sponsors and voluntary contributions.
- Aggregate, cookie-less traffic measurement.
- Charging authenticated automated crawlers for access to public website
  content while keeping the website free for people.
- Future hosted conveniences only when they are optional and do not remove
  features from the local toolchain.

## Prohibited funding

- Behavioral advertising, cross-site tracking, or sale of visitor data.
- Uploading or monetizing infrastructure plans, analysis output, chat messages,
  credentials, or personal data.
- Changing risk classifications, compliance mappings, or search results for a
  sponsor or payer.
- Paywalling documentation for human visitors.

## Cloudflare rollout

As of July 12, 2026, Cloudflare does not provide a conventional display-ad
network for monetizing human page views. That is a good fit for this policy:
people remain the audience, not the product. The preferred revenue path is to
charge selected commercial automation while leaving human access and the open
source toolchain free.

Cloudflare AI Crawl Control is available on all plans for crawler visibility
and allow/block policy, while Pay Per Crawl remains a private beta. The
production rollout is:

1. Confirm `readtheplan.dev` is proxied through Cloudflare and inspect AI Crawl
   Control metrics before changing policy.
2. Keep search engines and useful citation/referral crawlers allowed.
3. Apply for Pay Per Crawl and use its native `Allow`, `Charge`, and `Block`
   controls if the zone is accepted into the beta.
4. Keep `/robots.txt`, `/sitemap.xml`, `/security.txt`, and
   `/.well-known/security.txt` free, along with the homepage and installation
   path used for discovery.
5. Connect the dedicated Cloudflare Stripe account only after payout ownership,
   tax details, pricing, and crawler selection are explicitly approved.
6. Review revenue, crawler failures, search visibility, referrals, and support
   reports after launch. Disable charging if it harms human access or project
   discovery.

Cloudflare's Monetization Gateway is a separate, waitlist-only path for charging
agents for specific APIs, datasets, or MCP calls over x402. Join the waitlist,
but do not put the CLI, documentation, public website, or existing MCP tools
behind it. Reconsider it for new, compute-intensive hosted endpoints only after
the product is available and wallet ownership, pricing, tax treatment, abuse
controls, and a permanently free equivalent have been explicitly approved.

Do not deploy a custom x402 proxy merely to imitate either managed product. It
adds a wallet, payment verification, and production security surface before the
project has evidence that automated demand will cover those costs.

Official references:

- [AI Crawl Control overview](https://developers.cloudflare.com/ai-crawl-control/)
- [Manage AI crawlers](https://developers.cloudflare.com/ai-crawl-control/features/manage-ai-crawlers/)
- [Pay Per Crawl payouts](https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/use-pay-per-crawl-as-site-owner/manage-payouts/)
- [Monetization Gateway announcement and waitlist](https://blog.cloudflare.com/monetization-gateway/)
- [x402 payment-gated proxy](https://developers.cloudflare.com/ai-crawl-control/reference/worker-templates/)
