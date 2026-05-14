# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in readtheplan, please report it privately to the maintainer.

**Do not open a public issue.**

Email: security@readtheplan.dev (or contact [@texasich](https://github.com/texasich) directly)

Please include:
- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you've identified

You should receive a response within 48 hours. We will work with you to understand the scope and coordinate a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Active |
| < 0.3   | ❌ No longer supported |

## Security Model

readtheplan is designed to run locally. Terraform plan JSON is never uploaded, transmitted, or stored by the tool. The security model relies on:

- **Local execution only** — no network calls, no telemetry, no backend
- **No plan data exfiltration** — plan JSON stays on your machine
- **Evidence envelopes** — optional signed attestations use sigstore (local or CI OIDC)
- **CI isolation** — GitHub Action workflow uses `workflow_run` to avoid credential exposure to forked PRs

If you discover a way for readtheplan to exfiltrate plan data, make network calls without user intent, or bypass the local-only constraint, please report it immediately.

Hosted analyzer work is currently blocked by ADR 0013 (`docs/adr/0013-hosted-analyzer-data-handling-boundary.md`) until release-gate controls are implemented and verifiably passing.

## Supply Chain Policy

- GitHub workflows declare least-privilege `permissions:` blocks and job timeouts.
- GitHub Actions dependencies are monitored weekly with Dependabot.
- Release publishing uses PyPI Trusted Publishing via GitHub OIDC (`id-token: write`), not a stored PyPI API token.
- Third-party action SHA pinning is the target hardening posture. Until every workflow is SHA-pinned, action version bumps must come through reviewed Dependabot PRs or maintainer-authored PRs.

## Responsible Disclosure

We follow a 90-day disclosure timeline. After the fix is released, we will publish a security advisory crediting the reporter (unless you request anonymity).
