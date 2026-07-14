# ADR 0016: Static site modernization with Eleventy

## Status

Accepted — 2026-07-13

## Context

ADR 0011 kept the site vanilla and named growth beyond roughly five distinct
pages as the trigger for reconsidering a templating layer. The public site now
contains 24 HTML documents. Shared navigation and footer markup had consequently
moved into a custom post-build string-replacement step.

The product boundary has not changed: readtheplan is a local-first CLI and
GitHub Action. The site must not imply accounts, hosted plan analysis, persisted
run history, or raw plan upload. ADR 0013 continues to govern any future hosted
analyzer proposal.

The existing terminal aesthetic also no longer communicates the product as
clearly as a structured risk-and-evidence interface can. A visual modernization
is warranted, but it must represent sample/local analysis honestly rather than
invent a SaaS dashboard.

## Decision

Adopt Eleventy as a build-time-only templating layer and modernize the visual
system around a restrained graphite "signal workspace" direction.

- Eleventy compiles the existing routes into static HTML for Cloudflare Pages.
- Shared navigation and footer live in versioned partials.
- The homepage may visualize a clearly labeled sample analysis.
- The playground may analyze user-selected Terraform JSON entirely in-browser.
- No run history, accounts, backend storage, or hosted analyzer is added.
- Light editorial styling is reserved for printable evidence/report surfaces.
- The CLI, GitHub Action, MCP server, and signed evidence pipeline remain the
  product; the site remains marketing, documentation, and local tooling.

## Relationship to previous decisions

This ADR supersedes ADR 0011 only where ADR 0011 chose hand-maintained vanilla
HTML after its own page-count trigger had not yet been met. It preserves ADR
0011's rejection of a client-side application framework and SaaS dashboard.
ADR 0013 remains unchanged.

## Consequences

- Contributors edit reusable static partials instead of duplicating site chrome.
- Cloudflare continues to receive static assets with no frontend runtime.
- The build gains one Node development dependency and an explicit static-site
  compilation step.
- Visual regression and route-contract checks are required for all 24 outputs.
