# readtheplan.dev

Static setup generator for readtheplan.

The first release is intentionally client-side only: it helps visitors choose CI,
framework, plan artifact/path, blocking threshold, and evidence settings, then
generates GitHub Actions YAML, CLI commands, privacy guidance, and an evidence
checklist without uploading Terraform plan data.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
