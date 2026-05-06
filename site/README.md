# readtheplan.dev

Static setup generator for readtheplan.

The first release is intentionally client-side only: it helps visitors choose CI,
framework, plan artifact/path, blocking threshold, and evidence settings, then
captures optional client intake context and generates GitHub Actions YAML, CLI
commands, privacy guidance, an onboarding checklist, and a transparent mailto
handoff without uploading Terraform plan data.

The pilot handoff destination is configured in `site/app.js` as
`PILOT_HANDOFF_EMAIL`. It currently uses `pilot-contact@example.com` as a
placeholder; replace it before production use. The intake form has no backend
action, and client context stays in the browser until the visitor chooses to open
the generated email draft.

The `tools/` and `resources/` routes are static SEO lead-gen pages. They use
manual counts and high-level Terraform/AWS control examples only; they do not
accept raw plan files or send form submissions.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
