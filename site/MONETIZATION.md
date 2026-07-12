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

As of July 12, 2026, the preferred path is Cloudflare AI Crawl Control. It is
available on all plans for crawler visibility and allow/block policy, while Pay
Per Crawl remains a closed beta. The production rollout is:

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

Do not deploy the x402 proxy merely to imitate Pay Per Crawl. It requires a
wallet and production payment configuration, and reliable bot-only gating can
depend on paid Bot Management. Reconsider it only if native Pay Per Crawl is
unavailable and there is enough crawler volume to justify the added payment and
security surface.

Official references:

- [AI Crawl Control overview](https://developers.cloudflare.com/ai-crawl-control/)
- [Manage AI crawlers](https://developers.cloudflare.com/ai-crawl-control/features/manage-ai-crawlers/)
- [Pay Per Crawl payouts](https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/use-pay-per-crawl-as-site-owner/manage-payouts/)
- [x402 payment-gated proxy](https://developers.cloudflare.com/agents/tools/payments/x402/charge-for-http-content/)
