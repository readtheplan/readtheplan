# readtheplan.dev

Static onboarding app for readtheplan.

The first release is intentionally client-side only: it helps visitors choose a
setup path, generate GitHub Action / CLI snippets, and request a pilot without
uploading Terraform plan data.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
