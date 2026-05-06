# Corpus feedback loop

`tools/scan_corpus.py` creates local scan bundles from real Terraform plan JSON
so reviewers can compare readtheplan output against human judgment. It is a
collection harness only: it does not upload plans, send telemetry, or change the
rule library.

## Security boundary

Raw real Terraform plan JSON is local/private by default. Plans often contain
account IDs, ARNs, resource names, tags, endpoints, IAM details, and other
environment-specific metadata.

Only commit or publish corpus material that is synthetic, public-redacted, or
minimized enough for public review. Do not commit generated `plan.json` bundles
from private infrastructure. Prefer `--redact` when you need a shareable
starting point, and still review the result before publishing it.

## Generate bundles from existing plans

```bash
python tools/scan_corpus.py \
  --output-dir .local/readtheplan-scans \
  --framework soc2 \
  --redact \
  ./terraform-plans/
```

For each discovered `plan.json`, the harness writes:

- `readtheplan.json`: structured analyzer output.
- `readtheplan.md`: markdown reviewer summary.
- `metadata.json`: scan metadata, hashes, risk counts, and raw-plan flags.
- `feedback.yaml`: reviewer template matching
  [feedback.schema.yaml](feedback.schema.yaml).
- `plan.redacted.json`: only when `--redact` is used.
- `plan.json`: only when `--include-raw-plan` is used.

Generated bundle directories are also ignored by default (`corpus-scans/` and
`.local/readtheplan-scans/`), and root `plan.json` files are already ignored in
`.gitignore`. Treat that as a backstop, not approval to store private plans in
the repo tree.

## Generate a plan from a Terraform module

Terraform execution is guarded because provider downloads and plan evaluation
can touch local credentials and remote APIs. Use it only in a trusted local
workspace:

```bash
python tools/scan_corpus.py \
  --run-terraform \
  --refresh=false \
  --output-dir .local/readtheplan-scans \
  ./modules/network
```

Extra plan arguments can be repeated with `--terraform-arg`, for example:

```bash
python tools/scan_corpus.py --run-terraform \
  --terraform-arg=-var-file=dev.tfvars \
  ./modules/network
```

## Review workflow

1. Generate bundles into a private local directory.
2. Read `readtheplan.md` and fill in `feedback.yaml`.
3. Mark each resource as `correct`, `underclassified`, `overclassified`,
   `missed_resource`, `bad_explanation`, `missing_compliance_mapping`,
   `false_positive`, `parser_bug`, or `output_usability`.
4. Add `expected_reason` and `suggested_rule` when the tool missed important
   context.
5. For public examples, minimize/redact the plan first and manually inspect the
   result before committing anything.

Keep rule improvements in separate PRs. Corpus feedback should preserve what
readtheplan said at scan time so later rule changes can be evaluated against it.
