# ADR 0011: Site framework rebuild — Next.js or stay vanilla

## Status

Accepted (stay vanilla; reject Next.js rebuild) — 2026-05-04

## Context

The marketing + onboarding surface at `readtheplan.dev` is currently
vanilla HTML / CSS / JS, served as static files from Cloudflare Pages.
After PR #15 (inspired-refresh redesign) and PR #16 (five visual fixes),
the site is in a stable place: terminal-frame aesthetic, dark palette,
self-hosted SIL OFL fonts, strict CSP, ~700 lines of CSS, ~330 lines of
HTML, ~280 lines of vanilla JS.

The user asked, after the inspired-refresh shipped, whether we should
rebuild the site on Next.js. This ADR exists to answer that question
honestly before any code is touched.

The relevant constraints, none negotiable:

- Hosting must stay on Cloudflare Pages (no platform migration).
- The strict CSP must survive: `default-src 'self'; script-src 'self';
  style-src 'self'; font-src 'self'; img-src 'self' data:; object-src
  'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`.
  No `unsafe-inline`, no `unsafe-eval`, no remote sources.
- The product is the **signed-evidence pipeline** (CLI + GitHub Action
  + sigstore + framework catalogs). The site is marketing and
  onboarding. A rebuild that becomes a rewrite of the product is out of
  scope.
- No SaaS dashboard, no plan upload — both are out-of-scope per
  CLAUDE.md.
- No multi-cloud beyond AWS — also out per CLAUDE.md.

The four candidate paths:

1. **Stay vanilla.** Keep editing static HTML / CSS / JS.
2. **Rebuild on Next.js (App Router, static export).** What the user
   asked about; matches the visual reference (`hermes-agent.nousresearch.com`
   is itself a Next.js + Tailwind site).
3. **Rebuild on Astro.** Static-site generator with islands; better CSP
   story than Next.js.
4. **Rebuild on Eleventy.** Pure static; minimal JS; closest in spirit
   to the current vanilla setup with templating ergonomics added.

## Decision

**Reject Next.js rebuild. Stay vanilla. Optionally add a templating
layer (Eleventy) only if duplication becomes painful.**

The rebuild fails three of its own justification tests:

### 1. Need test — what does a framework give us that vanilla can't?

After PR #15 + PR #16, the actual gaps in the current site are not
framework gaps. They are content gaps and feature gaps that any stack
would need to deliver:

- More example plans on the demo (data, not framework).
- Better copy in the pilot section (writing, not framework).
- A blog or changelog page (could be vanilla; doesn't need React).
- Maybe an interactive plan-uploader someday — but plan upload is
  explicitly out-of-scope per CLAUDE.md.

The honest answer to "what does Next.js unlock?" right now is:
*nothing concrete the product needs in the next six months*. It would
unlock developer ergonomics for a frontend dev who's used to JSX —
but the current owner is a one-person team writing Python, and the
site rarely changes.

### 2. CSP test — does Next.js survive `default-src 'self'`?

Partially. Next.js App Router static export emits inline `<script>`
hydration payloads by default. To preserve `script-src 'self'` without
`unsafe-inline`, every inline script needs a per-build nonce or hash,
which means:

- Cloudflare Pages must inject the CSP at the edge (`_headers` file)
  with a nonce that matches the inline scripts. Pages does not
  natively support per-request nonces; you'd need a Pages Function or
  Worker in front of the static export to inject them.
- Or: configure Next.js to externalize all inline scripts (not the
  default; possible with custom Webpack config but fragile across
  Next.js minor versions).
- Or: weaken CSP to `script-src 'self' 'unsafe-inline'`, which is a
  regression we shouldn't accept.

Astro is materially better here — its islands architecture keeps
component boundaries explicit and makes `script-src 'self'` easier to
maintain. Eleventy is best — it emits static HTML with no client-side
hydration runtime at all.

If we must rebuild, Astro > Eleventy > Next.js on the CSP axis. The
visual reference (Hermes Agent) uses Next.js because Nous Research is
not constrained by `default-src 'self'`. We are.

### 3. Velocity test — does the rebuild slow down product work?

Yes, materially.

- Phase 1 of any rebuild: scaffold + content parity (~2 weeks of
  Codex's time at the brief-driven pace we've been running).
- Phase 2: feature parity — copy buttons, demo toggles, framework
  picker, signed-evidence preview, all the JS interactions in
  `app.js`.
- Phase 3: visual polish to match what we have today.

That's 4–6 weeks of Codex's time on something that does not move the
core product. As of the post-MVP reconciliation on 2026-05-05, customer
rule overlays, examples, benchmarks, live demo work, site polish, ADR 0011,
and the PR #18 rule additions have shipped. The remaining higher-leverage
work is catalog breadth, rule quality, auditor outreach, and adoption docs.
Every week spent on a site rebuild is a week not spent hardening the actual
product.

### Counter-argument the rebuild has

The strongest argument *for* a rebuild is **consistency with the
ecosystem signal**. A Next.js + Tailwind site reads as "modern OSS
project with serious frontend posture" to the kind of buyer or
contributor we want. A vanilla HTML/CSS/JS site reads as "indie." Both
are accurate; the question is which signal helps adoption.

Counter-counter: the people who care about this distinction are
frontend devs evaluating which project to contribute to. The buyers
(SRE leads, compliance officers, security engineers) read the README
and the CLI output, not the HTML source. Optimizing the marketing site
for frontend dev sentiment is a misallocation when the real audience
reads `readtheplan analyze --framework soc2 plan.json` output.

## Alternatives considered

| Stack | CSP fit | Velocity cost | Visual ceiling | Verdict |
|---|---|---|---|---|
| Vanilla (current) | Excellent | Zero | Good (already shipped) | **Keep** |
| Eleventy + Nunjucks | Excellent | 1 week | Identical to current | Defer; revisit only if duplication becomes painful (e.g., 5+ pages) |
| Astro + Tailwind | Good (with care) | 3–4 weeks | High | Defer; consider if we add a blog or changelog |
| Next.js static export + Tailwind | Poor (CSP nonces required) | 4–6 weeks | High | Reject; CSP cost not justified |
| SvelteKit static | Good | 4–5 weeks | High | Not considered seriously; no advantage over Astro |

## Triggers that should reopen this decision

This ADR sets the stance "no rebuild," but the stance is conditional.
Re-open and accept a rebuild if any of these hits:

1. The site grows past ~5 distinct pages (changelog, blog, docs,
   landing, pricing-or-pilot). At that point templating saves real
   editing time. Pick **Eleventy first** — it has the best CSP fit and
   smallest learning surface.
2. The site needs interactive features that exceed vanilla JS
   ergonomics (e.g., a real plan analyzer running in-browser via
   wasm-built Python). At that point pick **Astro** — its island
   architecture handles "mostly static, occasional interactivity"
   better than vanilla and keeps CSP manageable.
3. A frontend-experienced contributor joins the project full-time and
   would land more value if they could work in JSX. At that point the
   velocity calculus inverts and Next.js or SvelteKit becomes
   reasonable.

None of those triggers is met today. None looks plausible in the next
two quarters.

## Consequences

- We keep `site/` as vanilla HTML / CSS / JS.
- Future visual iteration goes through CSS-only patches following the
  PR #15 + PR #16 pattern (single-file diffs, layering contract,
  visual screenshot review).
- We do not invest in Tailwind, JSX components, or a build system
  beyond the existing `site/scripts/build.js`.
- We re-read this ADR every six months or whenever a "let's rebuild
  the site" idea reappears, whichever is sooner.
- If a rebuild does become necessary later, the order of preference is
  Eleventy → Astro → Next.js, driven by the CSP fit and the velocity
  cost.

## References

- ADR 0005 — compliance control mapping (catalog format)
- ADR 0006 — ISO 27001:2022 catalog
- PR #15 — inspired-refresh redesign
- PR #16 — five-bug visual patch
- `site/scripts/build.js` — current static build emitting strict CSP
- Hermes Agent (visual reference, Next.js + Tailwind):
  https://hermes-agent.nousresearch.com/
- Cloudflare Pages CSP injection patterns:
  https://developers.cloudflare.com/pages/configuration/headers/
